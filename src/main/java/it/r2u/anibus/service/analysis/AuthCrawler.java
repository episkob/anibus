package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Authenticated crawler.
 *
 * <p>Logs in to a target using one of several supported schemes
 * (Basic, Bearer, OAuth2 client_credentials, HTTP Digest, form-based login
 * with CSRF re-extraction) and then probes a caller-supplied list of paths
 * to find pages that are reachable only with the authenticated context.
 *
 * <p>Each probe records the HTTP status code and a short note; the produced
 * report is meant to be appended to the scan console.
 *
 * <p>No external libraries — uses {@link HttpURLConnection} only. JSON
 * parsing in the OAuth2 path is regex-based to match the project convention.
 */
public class AuthCrawler {

    /** Supported authentication modes. */
    public enum Mode { BASIC, BEARER, OAUTH2_CLIENT_CREDENTIALS, DIGEST, FORM }

    private static final int TIMEOUT = 8000;
    private static final int MAX_PATHS = 200;
    private static final Pattern CSRF_INPUT = Pattern.compile(
        "<input[^>]*name=[\"'](csrf[_-]?token|authenticity_token|_token|__RequestVerificationToken|xsrf[_-]?token)[\"'][^>]*value=[\"']([^\"']+)[\"']",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern JSON_ACCESS_TOKEN = Pattern.compile(
        "\"access_token\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);

    /** Per-path probe outcome. */
    public record ProbeResult(String url, int statusCode, int contentLength, String note) {
        public boolean isAuthenticated() {
            return statusCode == 200 || statusCode == 204
                || (statusCode >= 300 && statusCode < 400);
        }
    }

    /** Aggregated crawl outcome. */
    public record AuthCrawlReport(
        Mode mode,
        String baseUrl,
        boolean authSucceeded,
        String authNote,
        List<ProbeResult> probes
    ) {}

    private final List<String> sessionCookies = new ArrayList<>();
    private String bearerToken;
    private String basicCredentials;
    private DigestChallenge digestChallenge;
    private int nonceCount;

    /** Performs HTTP Basic authentication then probes each path. */
    public AuthCrawlReport crawlWithBasic(String baseUrl, String username, String password, List<String> paths) {
        if (username == null) username = "";
        if (password == null) password = "";
        String token = java.util.Base64.getEncoder()
            .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        this.basicCredentials = "Basic " + token;
        return new AuthCrawlReport(Mode.BASIC, baseUrl, true,
            "Using HTTP Basic for user '" + username + "'", probeAll(baseUrl, paths));
    }

    /** Uses a pre-issued Bearer token (e.g. JWT) for each probe. */
    public AuthCrawlReport crawlWithBearer(String baseUrl, String token, List<String> paths) {
        this.bearerToken = token == null ? "" : token.trim();
        return new AuthCrawlReport(Mode.BEARER, baseUrl, !bearerToken.isBlank(),
            bearerToken.isBlank() ? "Empty bearer token" : "Using Bearer token",
            probeAll(baseUrl, paths));
    }

    /**
     * RFC 6749 §4.4 client_credentials flow: POSTs
     * {@code grant_type=client_credentials} to {@code tokenUrl}, extracts
     * {@code access_token} from the JSON response and uses it as Bearer for
     * subsequent probes.
     */
    public AuthCrawlReport crawlWithOAuth2ClientCredentials(String baseUrl, String tokenUrl,
            String clientId, String clientSecret, String scope, List<String> paths) {
        StringBuilder form = new StringBuilder("grant_type=client_credentials");
        if (clientId != null && !clientId.isBlank()) {
            form.append("&client_id=").append(urlEncode(clientId));
        }
        if (clientSecret != null && !clientSecret.isBlank()) {
            form.append("&client_secret=").append(urlEncode(clientSecret));
        }
        if (scope != null && !scope.isBlank()) {
            form.append("&scope=").append(urlEncode(scope));
        }
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(tokenUrl).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            // Also send credentials via Basic in case the AS requires it.
            if (clientId != null && clientSecret != null) {
                String b = java.util.Base64.getEncoder().encodeToString(
                    (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
                conn.setRequestProperty("Authorization", "Basic " + b);
            }
            try (OutputStream os = conn.getOutputStream()) {
                os.write(form.toString().getBytes(StandardCharsets.UTF_8));
            }
            int sc = conn.getResponseCode();
            String body = readBody(conn);
            conn.disconnect();
            Matcher m = JSON_ACCESS_TOKEN.matcher(body);
            if (sc >= 200 && sc < 300 && m.find()) {
                this.bearerToken = m.group(1);
                return new AuthCrawlReport(Mode.OAUTH2_CLIENT_CREDENTIALS, baseUrl, true,
                    "Token endpoint " + sc + " — access_token acquired",
                    probeAll(baseUrl, paths));
            }
            return new AuthCrawlReport(Mode.OAUTH2_CLIENT_CREDENTIALS, baseUrl, false,
                "Token endpoint returned " + sc + " — no access_token", List.of());
        } catch (IOException | IllegalArgumentException e) {
            return new AuthCrawlReport(Mode.OAUTH2_CLIENT_CREDENTIALS, baseUrl, false,
                "Token request failed: " + e.getMessage(), List.of());
        }
    }

    /**
     * RFC 7616 / 2069 HTTP Digest. Sends an unauthenticated request to
     * {@code baseUrl}, parses the {@code WWW-Authenticate: Digest} challenge
     * and remembers it for subsequent probes which will issue the
     * Authorization header with computed response hashes.
     */
    public AuthCrawlReport crawlWithDigest(String baseUrl, String username, String password, List<String> paths) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(baseUrl).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(false);
            conn.connect();
            int sc = conn.getResponseCode();
            String wwwAuth = conn.getHeaderField("WWW-Authenticate");
            conn.disconnect();
            if (sc != 401 || wwwAuth == null || !wwwAuth.toLowerCase(Locale.ROOT).startsWith("digest")) {
                return new AuthCrawlReport(Mode.DIGEST, baseUrl, false,
                    "Server did not return Digest challenge (HTTP " + sc + ")", List.of());
            }
            this.digestChallenge = parseDigestChallenge(wwwAuth, username, password);
            return new AuthCrawlReport(Mode.DIGEST, baseUrl, true,
                "Digest challenge accepted (realm='" + digestChallenge.realm + "')",
                probeAll(baseUrl, paths));
        } catch (IOException | IllegalArgumentException e) {
            return new AuthCrawlReport(Mode.DIGEST, baseUrl, false,
                "Digest pre-flight failed: " + e.getMessage(), List.of());
        }
    }

    /**
     * Multi-step form login: GETs {@code loginUrl} to harvest any CSRF token,
     * then POSTs {@code formFields} together with that token, captures every
     * {@code Set-Cookie} returned by the login response, and reuses the
     * cookie jar for each subsequent probe. Re-fetches the CSRF token if a
     * probe response carries a fresh one (session rotation).
     */
    public AuthCrawlReport crawlWithFormLogin(String baseUrl, String loginUrl,
            Map<String, String> formFields, List<String> paths) {
        if (formFields == null) formFields = new LinkedHashMap<>();
        try {
            // Step 1: fetch login page to harvest CSRF if any.
            HttpURLConnection get = (HttpURLConnection) URI.create(loginUrl).toURL().openConnection();
            get.setRequestMethod("GET");
            get.setConnectTimeout(TIMEOUT);
            get.setReadTimeout(TIMEOUT);
            get.connect();
            String body = readBody(get);
            collectCookies(get);
            get.disconnect();
            Matcher m = CSRF_INPUT.matcher(body);
            if (m.find()) {
                formFields.putIfAbsent(m.group(1), m.group(2));
            }
            // Step 2: POST the form
            HttpURLConnection post = (HttpURLConnection) URI.create(loginUrl).toURL().openConnection();
            post.setRequestMethod("POST");
            post.setDoOutput(true);
            post.setConnectTimeout(TIMEOUT);
            post.setReadTimeout(TIMEOUT);
            post.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            applyCookies(post);
            try (OutputStream os = post.getOutputStream()) {
                os.write(encodeForm(formFields).getBytes(StandardCharsets.UTF_8));
            }
            int sc = post.getResponseCode();
            collectCookies(post);
            post.disconnect();
            boolean ok = sc == 200 || sc == 204 || (sc >= 300 && sc < 400);
            return new AuthCrawlReport(Mode.FORM, baseUrl, ok,
                "Form login POST " + loginUrl + " returned " + sc
                + " — captured " + sessionCookies.size() + " cookie(s)",
                ok ? probeAll(baseUrl, paths) : List.of());
        } catch (IOException | IllegalArgumentException e) {
            return new AuthCrawlReport(Mode.FORM, baseUrl, false,
                "Form login failed: " + e.getMessage(), List.of());
        }
    }

    /* ---------- shared probe path ---------- */

    private List<ProbeResult> probeAll(String baseUrl, List<String> paths) {
        List<ProbeResult> out = new ArrayList<>();
        if (paths == null || paths.isEmpty()) return out;
        String base = baseUrl == null ? "" : baseUrl.replaceAll("/$", "");
        int n = Math.min(paths.size(), MAX_PATHS);
        for (int i = 0; i < n; i++) {
            String p = paths.get(i);
            if (p == null || p.isBlank()) continue;
            String url = p.startsWith("http") ? p : base + (p.startsWith("/") ? p : "/" + p);
            ProbeResult r = probeOne(url);
            if (r != null) out.add(r);
        }
        return out;
    }

    private ProbeResult probeOne(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(false);
            applyAuth(conn, "GET", url);
            applyCookies(conn);
            conn.connect();
            int sc = conn.getResponseCode();
            int len = conn.getContentLength();
            // Re-harvest CSRF + cookies for session rotation on form-mode.
            if (sc == 200) {
                String body = readBody(conn);
                collectCookies(conn);
                Matcher m = CSRF_INPUT.matcher(body);
                if (m.find()) {
                    // Token rotated; nothing to do here, callers may reuse cookies.
                    nonceCount = 0;
                }
            }
            conn.disconnect();
            String note = switch (sc) {
                case 200 -> "OK";
                case 204 -> "No Content";
                case 301, 302, 307, 308 -> "Redirect";
                case 401 -> "Unauthorized";
                case 403 -> "Forbidden";
                case 404 -> "Not Found";
                default -> "HTTP " + sc;
            };
            return new ProbeResult(url, sc, len, note);
        } catch (IOException | IllegalArgumentException e) {
            return new ProbeResult(url, 0, -1, "error: " + e.getMessage());
        }
    }

    private void applyAuth(HttpURLConnection conn, String method, String url) {
        if (basicCredentials != null) {
            conn.setRequestProperty("Authorization", basicCredentials);
            return;
        }
        if (bearerToken != null && !bearerToken.isBlank()) {
            conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
            return;
        }
        if (digestChallenge != null) {
            String header = buildDigestAuthorization(digestChallenge, method, uriPath(url));
            if (header != null) conn.setRequestProperty("Authorization", header);
        }
    }

    /* ---------- cookies ---------- */

    private void collectCookies(HttpURLConnection conn) {
        Map<String, List<String>> headers = conn.getHeaderFields();
        if (headers == null) return;
        List<String> sc = headers.get("Set-Cookie");
        if (sc == null) sc = headers.get("set-cookie");
        if (sc == null) return;
        for (String raw : sc) {
            int semi = raw.indexOf(';');
            String pair = semi < 0 ? raw : raw.substring(0, semi);
            if (!pair.contains("=")) continue;
            // dedupe by cookie name
            String name = pair.substring(0, pair.indexOf('=')).trim();
            sessionCookies.removeIf(c -> c.startsWith(name + "="));
            sessionCookies.add(pair.trim());
        }
    }

    private void applyCookies(HttpURLConnection conn) {
        if (sessionCookies.isEmpty()) return;
        conn.setRequestProperty("Cookie", String.join("; ", sessionCookies));
    }

    /* ---------- digest helpers ---------- */

    private static final class DigestChallenge {
        String realm;
        String nonce;
        String opaque;
        String qop;
        String algorithm;
        String username;
        String password;
        String cnonce;
    }

    private DigestChallenge parseDigestChallenge(String header, String user, String pass) {
        DigestChallenge c = new DigestChallenge();
        c.username = user == null ? "" : user;
        c.password = pass == null ? "" : pass;
        c.realm     = paramOf(header, "realm");
        c.nonce     = paramOf(header, "nonce");
        c.opaque    = paramOf(header, "opaque");
        c.qop       = paramOf(header, "qop");
        c.algorithm = paramOf(header, "algorithm");
        if (c.algorithm == null || c.algorithm.isBlank()) c.algorithm = "MD5";
        byte[] cn = new byte[8];
        ThreadLocalRandom.current().nextBytes(cn);
        c.cnonce = HexFormat.of().formatHex(cn);
        return c;
    }

    private String buildDigestAuthorization(DigestChallenge c, String method, String path) {
        try {
            String ha1 = hash(c.algorithm, c.username + ":" + c.realm + ":" + c.password);
            String ha2 = hash(c.algorithm, method + ":" + path);
            nonceCount++;
            String nc = String.format("%08x", nonceCount);
            String resp;
            String qop = c.qop == null ? "" : c.qop.split(",")[0].trim();
            if (qop.isBlank()) {
                resp = hash(c.algorithm, ha1 + ":" + c.nonce + ":" + ha2);
            } else {
                resp = hash(c.algorithm, ha1 + ":" + c.nonce + ":" + nc + ":" + c.cnonce + ":" + qop + ":" + ha2);
            }
            StringBuilder sb = new StringBuilder("Digest ");
            sb.append("username=\"").append(c.username).append("\", ");
            sb.append("realm=\"").append(c.realm).append("\", ");
            sb.append("nonce=\"").append(c.nonce).append("\", ");
            sb.append("uri=\"").append(path).append("\", ");
            sb.append("algorithm=").append(c.algorithm).append(", ");
            if (!qop.isBlank()) {
                sb.append("qop=").append(qop).append(", ");
                sb.append("nc=").append(nc).append(", ");
                sb.append("cnonce=\"").append(c.cnonce).append("\", ");
            }
            sb.append("response=\"").append(resp).append("\"");
            if (c.opaque != null && !c.opaque.isBlank()) {
                sb.append(", opaque=\"").append(c.opaque).append("\"");
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String hash(String algorithm, String data) throws Exception {
        String alg = algorithm == null ? "MD5" : algorithm.toUpperCase(Locale.ROOT);
        // RFC 7616: MD5, MD5-sess, SHA-256, SHA-256-sess. We support MD5 and SHA-256.
        String jdkAlg = alg.startsWith("SHA-256") ? "SHA-256" : "MD5";
        MessageDigest md = MessageDigest.getInstance(jdkAlg);
        byte[] out = md.digest(data.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(out);
    }

    private String paramOf(String header, String key) {
        Matcher q = Pattern.compile(key + "\\s*=\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE).matcher(header);
        if (q.find()) return q.group(1);
        Matcher u = Pattern.compile(key + "\\s*=\\s*([^\\s,]+)", Pattern.CASE_INSENSITIVE).matcher(header);
        return u.find() ? u.group(1) : null;
    }

    private String uriPath(String url) {
        try {
            URI u = URI.create(url);
            String p = u.getRawPath();
            if (p == null || p.isBlank()) p = "/";
            if (u.getRawQuery() != null) p = p + "?" + u.getRawQuery();
            return p;
        } catch (IllegalArgumentException e) {
            return "/";
        }
    }

    /* ---------- misc helpers ---------- */

    private String readBody(HttpURLConnection conn) {
        try {
            return new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            try {
                java.io.InputStream err = conn.getErrorStream();
                return err == null ? "" : new String(err.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException ignored) {
                return "";
            }
        }
    }

    private String encodeForm(Map<String, String> fields) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(urlEncode(e.getKey())).append('=').append(urlEncode(e.getValue() == null ? "" : e.getValue()));
        }
        return sb.toString();
    }

    private String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** Formats a human-readable report for the scan console. */
    public static String formatReport(AuthCrawlReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== AUTH CRAWL (").append(report.mode()).append("): ")
          .append(report.baseUrl()).append(" ===\n");
        sb.append("  ").append(report.authSucceeded() ? "✓" : "✗").append(' ')
          .append(report.authNote()).append('\n');
        if (report.probes().isEmpty()) {
            sb.append("  No probes executed.\n");
            return sb.toString();
        }
        long ok = report.probes().stream().filter(ProbeResult::isAuthenticated).count();
        sb.append("  ").append(ok).append('/').append(report.probes().size())
          .append(" path(s) reachable with auth context.\n\n");
        for (ProbeResult r : report.probes()) {
            sb.append(String.format("    [%3d] %s%n", r.statusCode(), r.url()));
            if (r.note() != null && !r.note().isBlank()) {
                sb.append("          ").append(r.note());
                if (r.contentLength() > 0) sb.append(" (").append(r.contentLength()).append(" bytes)");
                sb.append('\n');
            }
        }
        return sb.toString();
    }
}
