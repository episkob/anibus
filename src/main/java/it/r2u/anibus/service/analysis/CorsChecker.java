package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * CORS misconfiguration checker.
 * Sends a crafted Origin header and inspects the ACAO/ACAC response headers.
 */
public class CorsChecker {

    private static final int TIMEOUT = 7000;
    private static final String EVIL_ORIGIN = "https://evil.attacker.com";
    private static final String NULL_ORIGIN  = "null";
    private static final String PREFLIGHT_METHOD = "POST";
    private static final String PREFLIGHT_HEADERS = "Authorization, Content-Type";

    public enum CorsRisk { CRITICAL, HIGH, MEDIUM, SAFE }

    /** Result of a single CORS probe. */
    public record CorsResult(
        String url,
        String allowOrigin,
        String allowCredentials,
        CorsRisk risk,
        String finding
    ) {}

    /**
     * Runs CORS probes against the target URL and common API sub-paths.
     *
     * @param targetUrl Base URL to test
     * @return List of CorsResult (one per probe)
     */
    public List<CorsResult> check(String targetUrl) {
        List<CorsResult> findings = new ArrayList<>();
        if (targetUrl == null || targetUrl.isBlank()) return findings;

        // Probe with attacker origin
        CorsResult r1 = probe(targetUrl, EVIL_ORIGIN);
        if (r1 != null) findings.add(r1);

        // Probe with null origin (iframe sandbox bypass)
        CorsResult r2 = probe(targetUrl, NULL_ORIGIN);
        if (r2 != null) findings.add(r2);

        // Try common API paths
        for (String suffix : List.of("/api", "/api/v1", "/graphql", "/rest")) {
            String apiUrl = targetUrl.replaceAll("/$", "") + suffix;
            CorsResult r = probe(apiUrl, EVIL_ORIGIN);
            if (r != null && r.risk() != CorsRisk.SAFE) findings.add(r);
        }

        return findings;
    }

    private CorsResult probe(String url, String origin) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Origin", origin);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(true);
            conn.connect();

            String acao = conn.getHeaderField("Access-Control-Allow-Origin");
            String acac = conn.getHeaderField("Access-Control-Allow-Credentials");
            conn.disconnect();

            PreflightOutcome preflight = probePreflight(url, origin);

            if (acao == null) return new CorsResult(url, null, acac, CorsRisk.SAFE, "CORS not configured");

            CorsRisk risk;
            String finding;

            if ("*".equals(acao) && "true".equalsIgnoreCase(acac)) {
                risk    = CorsRisk.CRITICAL;
                finding = "Wildcard ACAO with credentials — any origin can make credentialed requests";
            } else if (origin.equals(acao) && "true".equalsIgnoreCase(acac)) {
                risk    = CorsRisk.CRITICAL;
                finding = "Arbitrary origin reflected with Allow-Credentials: true — credential theft possible";
            } else if (NULL_ORIGIN.equals(acao)) {
                risk    = CorsRisk.HIGH;
                finding = "null origin accepted — iframe sandbox bypass possible";
            } else if (origin.equals(acao)) {
                risk    = CorsRisk.HIGH;
                finding = "Arbitrary origin reflected in ACAO without credentials";
            } else if ("*".equals(acao)) {
                risk    = CorsRisk.MEDIUM;
                finding = "Wildcard ACAO — public read access from any origin";
            } else {
                risk    = CorsRisk.SAFE;
                finding = "ACAO fixed to: " + acao;
            }

            if (preflight.allowingCrossOriginAuthHeaders()) {
                risk = maxRisk(risk, CorsRisk.HIGH);
                finding = finding + " | Preflight allows cross-origin auth headers";
            } else if (preflight.permissive()) {
                risk = maxRisk(risk, CorsRisk.MEDIUM);
                finding = finding + " | Preflight is permissive";
            }

            return new CorsResult(url, acao, acac, risk, finding);
        } catch (IOException ignored) {
            return null;
        }
    }

    private PreflightOutcome probePreflight(String url, String origin) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("OPTIONS");
            conn.setRequestProperty("Origin", origin);
            conn.setRequestProperty("Access-Control-Request-Method", PREFLIGHT_METHOD);
            conn.setRequestProperty("Access-Control-Request-Headers", PREFLIGHT_HEADERS);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(true);
            conn.connect();

            int status = conn.getResponseCode();
            String acao = conn.getHeaderField("Access-Control-Allow-Origin");
            String acam = conn.getHeaderField("Access-Control-Allow-Methods");
            String acah = conn.getHeaderField("Access-Control-Allow-Headers");
            conn.disconnect();

            boolean methodAllowed = containsTokenIgnoreCase(acam, PREFLIGHT_METHOD);
            boolean originAllowed = "*".equals(acao) || origin.equals(acao);
            boolean headersAllowed = containsTokenIgnoreCase(acah, "Authorization") || "*".equals(acah);

            boolean permissive = status >= 200 && status < 300 && originAllowed && methodAllowed;
            boolean allowingAuthHeaders = permissive && headersAllowed;
            return new PreflightOutcome(permissive, allowingAuthHeaders);
        } catch (IOException ignored) {
            return new PreflightOutcome(false, false);
        }
    }

    private boolean containsTokenIgnoreCase(String csv, String token) {
        if (csv == null || csv.isBlank()) {
            return false;
        }
        for (String part : csv.split(",")) {
            if (token.equalsIgnoreCase(part.trim())) {
                return true;
            }
        }
        return false;
    }

    private CorsRisk maxRisk(CorsRisk a, CorsRisk b) {
        return severity(a) >= severity(b) ? a : b;
    }

    private int severity(CorsRisk risk) {
        return switch (risk) {
            case CRITICAL -> 4;
            case HIGH -> 3;
            case MEDIUM -> 2;
            case SAFE -> 1;
        };
    }

    private record PreflightOutcome(boolean permissive, boolean allowingCrossOriginAuthHeaders) {}

    /** Formats a human-readable CORS report. */
    public static String formatReport(List<CorsResult> results, String targetUrl) {
        StringBuilder sb = new StringBuilder("=== CORS CHECK: ").append(targetUrl).append(" ===\n");
        if (results == null || results.isEmpty()) {
            sb.append("  Could not reach target or no CORS headers present.\n");
            return sb.toString();
        }
        List<CorsResult> issues = results.stream()
            .filter(r -> r.risk() != CorsRisk.SAFE).toList();
        if (issues.isEmpty()) {
            sb.append("  CORS appears correctly configured.\n");
            return sb.toString();
        }
        sb.append("  ").append(issues.size()).append(" CORS misconfiguration(s):\n");
        for (CorsResult r : issues) {
            sb.append("\n  [").append(r.risk()).append("] ").append(r.url()).append("\n");
            sb.append("    ACAO: ").append(r.allowOrigin()).append("\n");
            if (r.allowCredentials() != null)
                sb.append("    ACAC: ").append(r.allowCredentials()).append("\n");
            sb.append("    ").append(r.finding()).append("\n");
        }
        return sb.toString();
    }
}
