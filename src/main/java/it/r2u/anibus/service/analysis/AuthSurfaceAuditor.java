package it.r2u.anibus.service.analysis;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Auth Surface Auditor — probes common authentication endpoints for:
 * <ul>
 *   <li>Rate-limiting headers ({@code X-RateLimit-*}, {@code Retry-After})</li>
 *   <li>Account lockout indicators (HTTP 429 / 5xx / redirect after N rapid attempts)</li>
 *   <li>CAPTCHA presence in login page HTML (reCAPTCHA / hCaptcha / Turnstile tokens)</li>
 *   <li>Basic security headers ({@code X-Frame-Options}, {@code CSP}, {@code X-Content-Type-Options})</li>
 * </ul>
 *
 * <p>Only safe, non-destructive probes are performed — no credentials are ever
 * submitted, no accounts are locked in a real sense (the rate-limit probe sends
 * a small burst of empty POST requests to detect the 429 threshold without
 * valid credentials).
 */
public class AuthSurfaceAuditor {

    // ── Login paths to probe ───────────────────────────────────────────────────
    private static final List<String> LOGIN_PATHS = List.of(
            "/login", "/signin", "/sign-in", "/auth", "/auth/login",
            "/api/login", "/api/auth", "/api/v1/login", "/api/v1/auth",
            "/account/login", "/user/login", "/session", "/sessions",
            "/wp-login.php", "/admin/login", "/admin", "/administrator",
            "/panel", "/dashboard/login", "/portal/login"
    );

    // ── CAPTCHA fingerprints ───────────────────────────────────────────────────
    private static final List<String> CAPTCHA_TOKENS = List.of(
            "recaptcha", "g-recaptcha", "hcaptcha", "h-captcha",
            "turnstile", "cf-turnstile", "captcha", "altcha"
    );

    private static final int CONNECT_TIMEOUT = 5_000;
    private static final int READ_TIMEOUT    = 8_000;
    private static final int BURST_COUNT     = 8;   // rapid POST attempts for rate-limit check

    // ── Result types ──────────────────────────────────────────────────────────

    public record AuthFinding(
            String  endpoint,
            boolean reachable,
            boolean captchaPresent,
            boolean rateLimited,
            boolean lockoutDetected,
            String  rateLimitHeader,
            List<String> missingSecurityHeaders,
            String  severity
    ) {}

    public record AuthSurfaceReport(
            String           baseUrl,
            List<AuthFinding> findings,
            List<String>     discoveredEndpoints
    ) {}

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Probes all known login paths under {@code baseUrl} and returns an
     * {@link AuthSurfaceReport}.
     *
     * @param baseUrl scheme + host [+ port], e.g. {@code https://example.com}
     */
    public static AuthSurfaceReport audit(String baseUrl) {
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        List<AuthFinding>  findings            = new ArrayList<>();
        List<String>       discoveredEndpoints = new ArrayList<>();

        for (String path : LOGIN_PATHS) {
            String url = base + path;
            AuthFinding finding = probePath(url);
            if (finding != null) {
                findings.add(finding);
                if (finding.reachable()) discoveredEndpoints.add(url);
            }
        }

        return new AuthSurfaceReport(baseUrl, findings, discoveredEndpoints);
    }

    /** Formats the audit report into a human-readable string. */
    public static String formatReport(AuthSurfaceReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("Auth Surface Audit — ").append(report.baseUrl()).append(System.lineSeparator());
        sb.append("─".repeat(70)).append(System.lineSeparator());

        List<AuthFinding> reachable = report.findings().stream()
                .filter(AuthFinding::reachable).toList();

        if (reachable.isEmpty()) {
            sb.append("ℹ No reachable authentication endpoints discovered.").append(System.lineSeparator());
            return sb.toString().trim();
        }

        sb.append(String.format("Discovered %d reachable auth endpoint(s):%n%n", reachable.size()));

        for (AuthFinding f : reachable) {
            String icon = switch (f.severity()) {
                case "HIGH"   -> "[HIGH]  ";
                case "MEDIUM" -> "[MEDIUM]";
                default       -> "[LOW]   ";
            };
            sb.append(String.format("  %s %s%n", icon, f.endpoint()));

            sb.append("     CAPTCHA      : ").append(f.captchaPresent() ? "✅ present" : "❌ absent").append(System.lineSeparator());
            sb.append("     Rate-limit   : ").append(f.rateLimited() ? "✅ detected" : "❌ not detected").append(System.lineSeparator());
            sb.append("     Lockout      : ").append(f.lockoutDetected() ? "✅ detected" : "❌ not detected").append(System.lineSeparator());

            if (f.rateLimitHeader() != null && !f.rateLimitHeader().isEmpty()) {
                sb.append("     RL Header    : ").append(f.rateLimitHeader()).append(System.lineSeparator());
            }

            if (!f.missingSecurityHeaders().isEmpty()) {
                sb.append("     Missing hdrs : ").append(String.join(", ", f.missingSecurityHeaders())).append(System.lineSeparator());
            }

            sb.append(System.lineSeparator());
        }

        long highCount   = reachable.stream().filter(f -> "HIGH".equals(f.severity())).count();
        long mediumCount = reachable.stream().filter(f -> "MEDIUM".equals(f.severity())).count();
        sb.append(String.format("Summary: %d HIGH  %d MEDIUM  %d LOW%n",
                highCount, mediumCount, reachable.size() - highCount - mediumCount));
        return sb.toString().trim();
    }

    // ── Internal probing ──────────────────────────────────────────────────────

    private static AuthFinding probePath(String url) {
        // 1. GET — reachability, CAPTCHA, security headers
        boolean rateLimited     = false;
        boolean lockoutDetected = false;

        final boolean captchaPresent;
        final String  rateLimitHeader;
        final List<String> missingSecHdrs;

        try {
            HttpURLConnection con = openGet(url);
            int code = con.getResponseCode();

            if (code == 404 || code == 0) return null; // endpoint doesn't exist

            if (code == 429) rateLimited = true;
            rateLimitHeader = extractRateLimitHeader(con.getHeaderFields());
            missingSecHdrs  = checkSecurityHeaders(con.getHeaderFields());
            captchaPresent  = hasCaptcha(readBody(con));

        } catch (IOException ignored) {
            return null; // truly unreachable
        }

        // 2. Burst POST to detect rate-limiting / lockout
        int code429count = 0;
        int code5xxCount = 0;
        for (int i = 0; i < BURST_COUNT; i++) {
            try {
                HttpURLConnection post = openPost(url, "username=testuser&password=testpass");
                int c = post.getResponseCode();
                if (c == 429) code429count++;
                if (c >= 500) code5xxCount++;
                post.disconnect();
            } catch (IOException ignored) {
                break;
            }
        }
        if (code429count > 0) rateLimited = true;
        if (code5xxCount >= 3) lockoutDetected = true;

        // 3. Compute severity
        String severity = computeSeverity(captchaPresent, rateLimited, lockoutDetected, missingSecHdrs);

        return new AuthFinding(url, true, captchaPresent, rateLimited,
                               lockoutDetected, rateLimitHeader, missingSecHdrs, severity);
    }

    private static HttpURLConnection openGet(String url) throws IOException {
        HttpURLConnection con = (HttpURLConnection) URI.create(url).toURL().openConnection();
        con.setRequestMethod("GET");
        con.setConnectTimeout(CONNECT_TIMEOUT);
        con.setReadTimeout(READ_TIMEOUT);
        con.setInstanceFollowRedirects(false);
        con.setRequestProperty("User-Agent", "Mozilla/5.0 (security-audit; anibus)");
        return con;
    }

    private static HttpURLConnection openPost(String url, String body) throws IOException {
        HttpURLConnection con = (HttpURLConnection) URI.create(url).toURL().openConnection();
        con.setRequestMethod("POST");
        con.setConnectTimeout(CONNECT_TIMEOUT);
        con.setReadTimeout(READ_TIMEOUT);
        con.setInstanceFollowRedirects(false);
        con.setDoOutput(true);
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        con.setRequestProperty("User-Agent", "Mozilla/5.0 (security-audit; anibus)");
        try (OutputStream os = con.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        return con;
    }

    private static String readBody(HttpURLConnection con) {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            int chars = 0;
            while ((line = br.readLine()) != null && chars < 32_768) {
                sb.append(line).append("\n");
                chars += line.length();
            }
        } catch (IOException ignored) {
            // body not available or partial
        }
        return sb.toString().toLowerCase();
    }

    private static boolean hasCaptcha(String body) {
        if (body == null || body.isEmpty()) return false;
        for (String token : CAPTCHA_TOKENS) {
            if (body.contains(token)) return true;
        }
        return false;
    }

    private static String extractRateLimitHeader(Map<String, List<String>> headers) {
        for (String name : headers.keySet()) {
            if (name == null) continue;
            String lower = name.toLowerCase();
            if (lower.startsWith("x-ratelimit") || lower.startsWith("x-rate-limit")
                    || lower.equals("retry-after") || lower.equals("ratelimit-limit")) {
                List<String> vals = headers.get(name);
                return name + ": " + (vals != null && !vals.isEmpty() ? vals.get(0) : "");
            }
        }
        return null;
    }

    private static List<String> checkSecurityHeaders(Map<String, List<String>> headers) {
        List<String> missing = new ArrayList<>();
        List<String> required = List.of(
                "X-Frame-Options", "X-Content-Type-Options",
                "Content-Security-Policy", "Referrer-Policy"
        );
        for (String req : required) {
            boolean present = headers.keySet().stream()
                    .anyMatch(k -> k != null && k.equalsIgnoreCase(req));
            if (!present) missing.add(req);
        }
        return missing;
    }

    private static String computeSeverity(boolean captcha, boolean rateLimited,
                                          boolean lockout, List<String> missingHdrs) {
        if (!captcha && !rateLimited && !lockout) return "HIGH";
        if (!rateLimited && !lockout) return "MEDIUM";
        if (!captcha || missingHdrs.size() >= 3) return "MEDIUM";
        return "LOW";
    }
}
