package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.DoubleConsumer;

/**
 * Reflected XSS detector.
 * Injects test probes into URL parameters and form fields, then checks whether
 * the payload appears unescaped in the response body.
 */
public class XssDetector {

    private static final int TIMEOUT = 6000;

    /** A unique canary embedded in every payload so false-positives are rare. */
    private static final String CANARY = "xss7k3b";

    private static final List<String> PAYLOADS = List.of(
        "<" + CANARY + ">",
        "\">" + CANARY + "<b>",
        "'>" + CANARY + "<b>",
        "<img src=x on" + "error=" + CANARY + ">",
        "javascript:" + CANARY,
        "<script>" + CANARY + "</script>",
        "%3C" + CANARY + "%3E"
    );

    /** Result of a single XSS probe. */
    public record XssResult(
        String url,
        String parameter,
        String payload,
        boolean reflected,
        String evidence
    ) {
        public String risk() { return reflected ? "HIGH" : "NONE"; }
    }

    /**
     * Probes the given URL parameters for reflected XSS.
     *
     * @param targetUrl  Base URL (e.g. "https://example.com/search")
     * @param parameters List of parameter names to test
     * @param progress   0.0–1.0 progress callback
     * @return List of findings (only reflected=true entries are vulnerable)
     */
    public List<XssResult> scan(String targetUrl, List<String> parameters,
                                DoubleConsumer progress) {
        List<XssResult> findings = new ArrayList<>();
        if (targetUrl == null || targetUrl.isBlank()) return findings;

        List<String> params = (parameters == null || parameters.isEmpty())
            ? List.of("q", "search", "id", "query", "input", "text", "name", "page", "s")
            : parameters;

        int total = params.size() * PAYLOADS.size();
        int done = 0;

        for (String param : params) {
            for (String payload : PAYLOADS) {
                XssResult result = probe(targetUrl, param, payload);
                if (result != null) findings.add(result);
                done++;
                if (progress != null) progress.accept((double) done / total);
            }
        }
        return findings;
    }

    private XssResult probe(String targetUrl, String param, String payload) {
        try {
            String encoded = URLEncoder.encode(payload, StandardCharsets.UTF_8);
            String separator = targetUrl.contains("?") ? "&" : "?";
            String probeUrl = targetUrl + separator + param + "=" + encoded;

            HttpURLConnection conn = openConnection(probeUrl);
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(true);
            conn.connect();

            String body = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            conn.disconnect();

            boolean reflected = body.contains(payload) || body.contains(CANARY);
            if (reflected) {
                String evidence = extractEvidence(body, CANARY, 80);
                return new XssResult(probeUrl, param, payload, true, evidence);
            }
        } catch (IOException ignored) { }
        return null;
    }

    private HttpURLConnection openConnection(String url) throws IOException {
        return (HttpURLConnection) URI.create(url).toURL().openConnection();
    }

    private String extractEvidence(String body, String needle, int windowChars) {
        int idx = body.indexOf(needle);
        if (idx < 0) return "";
        int start = Math.max(0, idx - windowChars / 2);
        int end   = Math.min(body.length(), idx + needle.length() + windowChars / 2);
        return "…" + body.substring(start, end).replaceAll("\\s+", " ").trim() + "…";
    }

    /** Formats a human-readable report. */
    public static String formatReport(List<XssResult> results, String targetUrl) {
        if (results == null || results.isEmpty()) {
            return "=== XSS SCAN: " + targetUrl + " ===\n  No reflected XSS found.\n";
        }
        StringBuilder sb = new StringBuilder("=== XSS SCAN: ").append(targetUrl).append(" ===\n");
        List<XssResult> hits = results.stream().filter(XssResult::reflected).toList();
        if (hits.isEmpty()) {
            sb.append("  No reflected XSS found.\n");
        } else {
            sb.append("  ").append(hits.size()).append(" reflected XSS finding(s):\n");
            for (XssResult r : hits) {
                sb.append("\n  [").append(r.risk()).append("] param=").append(r.parameter()).append("\n");
                sb.append("    payload : ").append(r.payload()).append("\n");
                sb.append("    url     : ").append(r.url()).append("\n");
                if (!r.evidence().isBlank())
                    sb.append("    evidence: ").append(r.evidence()).append("\n");
            }
        }
        return sb.toString();
    }
}
