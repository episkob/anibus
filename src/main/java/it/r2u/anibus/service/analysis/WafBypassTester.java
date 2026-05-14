package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleConsumer;

/**
 * WAF bypass tester.
 *
 * Sends a payload that is commonly blocked by Web Application Firewalls
 * (Cloudflare, AWS WAF, Imperva, ModSecurity, Akamai, Sucuri, F5, Fortinet, ...).
 * Then re-issues the same request with a series of well-known bypass mutations
 * (header IP-spoofing, case alternation, encoding tricks, comment splitting,
 * HTTP method override, etc.) and compares the response to the blocked baseline.
 *
 * A technique is reported as a "potential bypass" when:
 *   - Baseline was blocked (HTTP 403/406/429/501/503 or "blocked" body keywords), AND
 *   - The variant returned a non-block status (typically 200) or a noticeably
 *     different body length.
 *
 * This module performs **detection only** — it never sends payloads designed
 * to exploit, only canary strings that trigger generic WAF signatures.
 */
public class WafBypassTester {

    private static final int TIMEOUT_MS = 8000;

    /** Generic XSS-shaped probe — triggers nearly all WAF rule sets. */
    public static final String DEFAULT_PROBE = "<script>alert(1)</script>";
    /** Alternative SQLi-shaped probe. */
    public static final String SQLI_PROBE    = "' OR '1'='1'-- -";

    /** Outcome for one bypass technique attempt. */
    public record BypassAttempt(
        String technique,
        int statusCode,
        int responseSize,
        boolean potentialBypass,
        String detail
    ) {}

    /** Aggregate report for a target. */
    public record BypassReport(
        String targetUrl,
        String probe,
        String parameter,
        int baselineStatus,
        int baselineSize,
        boolean baselineBlocked,
        String detectedWaf,
        @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
        List<BypassAttempt> attempts
    ) {
        public BypassReport {
            attempts = attempts == null ? List.of() : List.copyOf(attempts);
        }
        public long successCount() {
            return attempts.stream().filter(BypassAttempt::potentialBypass).count();
        }
    }

    /**
     * Run WAF bypass tests against {@code targetUrl} using a default probe
     * injected into parameter {@code paramName} (defaults to "q").
     */
    public BypassReport test(String targetUrl, String paramName, String probe,
                             DoubleConsumer progress) {
        String param = (paramName == null || paramName.isBlank()) ? "q" : paramName;
        String activeProbe = (probe == null || probe.isBlank()) ? DEFAULT_PROBE : probe;

        // 1. Baseline: send raw probe, observe block.
        Response baseline = send(buildUrl(targetUrl, param, activeProbe), Map.of(), "GET");
        boolean blocked = isBlocked(baseline);
        String detectedWaf = fingerprintWaf(baseline);

        // 2. Define mutations.
        List<Mutation> mutations = buildMutations(targetUrl, param, activeProbe);

        List<BypassAttempt> results = new ArrayList<>();
        int total = mutations.size();
        int done = 0;
        for (Mutation m : mutations) {
            Response r = send(m.url(), m.headers(), m.method());
            boolean bypass = blocked && !isBlocked(r) && r.status() > 0;
            String detail = bypass
                ? String.format("status %d → %d, size %d → %d",
                    baseline.status(), r.status(), baseline.size(), r.size())
                : String.format("status %d, size %d", r.status(), r.size());
            results.add(new BypassAttempt(m.name(), r.status(), r.size(), bypass, detail));
            done++;
            if (progress != null) progress.accept((double) done / total);
        }

        return new BypassReport(targetUrl, activeProbe, param,
            baseline.status(), baseline.size(), blocked, detectedWaf, results);
    }

    /** Pretty-prints a report for the console. */
    public static String formatReport(BypassReport r) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== WAF Bypass Report ===\n");
        sb.append("Target     : ").append(r.targetUrl()).append("\n");
        sb.append("Parameter  : ").append(r.parameter()).append("\n");
        sb.append("Probe      : ").append(r.probe()).append("\n");
        sb.append("Detected   : ").append(r.detectedWaf() == null ? "no WAF fingerprint" : r.detectedWaf()).append("\n");
        sb.append(String.format("Baseline   : status=%d size=%d %s%n",
            r.baselineStatus(), r.baselineSize(),
            r.baselineBlocked() ? "[BLOCKED]" : "[passed — no WAF in path?]"));

        if (!r.baselineBlocked()) {
            sb.append("\nBaseline request was not blocked. Either no WAF is present, the probe is whitelisted,\n")
              .append("or the WAF runs in passive/log-only mode. Bypass tests still listed below.\n");
        }

        sb.append("\nTechnique                                 | Status | Size  | Result\n");
        sb.append("------------------------------------------+--------+-------+----------\n");
        for (BypassAttempt a : r.attempts()) {
            sb.append(String.format("%-42s | %-6d | %-5d | %s%n",
                truncate(a.technique(), 42), a.statusCode(), a.responseSize(),
                a.potentialBypass() ? "POTENTIAL BYPASS" : "blocked/no-diff"));
        }
        sb.append(String.format("%nSummary: %d potential bypass technique(s) of %d tested.%n",
            r.successCount(), r.attempts().size()));
        if (r.successCount() > 0) {
            sb.append("Hint: replay flagged techniques manually with a real payload to confirm.\n");
        }
        return sb.toString();
    }

    // ── Mutations ────────────────────────────────────────────────────────────

    private record Mutation(String name, String url, Map<String, String> headers, String method) {}

    private List<Mutation> buildMutations(String targetUrl, String param, String probe) {
        List<Mutation> list = new ArrayList<>();

        // 1. IP-spoofing headers (trick origin-allowlist WAFs / dev-bypass rules).
        list.add(new Mutation("X-Forwarded-For: 127.0.0.1",
            buildUrl(targetUrl, param, probe),
            Map.of("X-Forwarded-For", "127.0.0.1"), "GET"));
        list.add(new Mutation("X-Real-IP: 127.0.0.1",
            buildUrl(targetUrl, param, probe),
            Map.of("X-Real-IP", "127.0.0.1"), "GET"));
        list.add(new Mutation("X-Originating-IP: 127.0.0.1",
            buildUrl(targetUrl, param, probe),
            Map.of("X-Originating-IP", "127.0.0.1"), "GET"));
        list.add(new Mutation("X-Remote-IP: 127.0.0.1",
            buildUrl(targetUrl, param, probe),
            Map.of("X-Remote-IP", "127.0.0.1"), "GET"));
        list.add(new Mutation("X-Client-IP: 127.0.0.1",
            buildUrl(targetUrl, param, probe),
            Map.of("X-Client-IP", "127.0.0.1"), "GET"));
        list.add(new Mutation("True-Client-IP: 127.0.0.1",
            buildUrl(targetUrl, param, probe),
            Map.of("True-Client-IP", "127.0.0.1"), "GET"));
        list.add(new Mutation("X-Forwarded-Host: localhost",
            buildUrl(targetUrl, param, probe),
            Map.of("X-Forwarded-Host", "localhost"), "GET"));

        // 2. Method overrides (some WAFs only inspect GET payloads).
        list.add(new Mutation("X-HTTP-Method-Override: GET (via POST)",
            buildUrl(targetUrl, param, probe),
            Map.of("X-HTTP-Method-Override", "GET"), "POST"));
        list.add(new Mutation("Method: HEAD",
            buildUrl(targetUrl, param, probe), Map.of(), "HEAD"));
        list.add(new Mutation("Method: OPTIONS",
            buildUrl(targetUrl, param, probe), Map.of(), "OPTIONS"));

        // 3. Payload mutations (re-encoded into URL).
        list.add(new Mutation("Case alternation",
            buildUrlRaw(targetUrl, param, urlEncode(alternateCase(probe))), Map.of(), "GET"));
        list.add(new Mutation("Double URL-encoding",
            buildUrlRaw(targetUrl, param, doubleEncode(probe)), Map.of(), "GET"));
        list.add(new Mutation("Triple URL-encoding",
            buildUrlRaw(targetUrl, param, doubleEncode(doubleEncode(probe))), Map.of(), "GET"));
        list.add(new Mutation("Unicode-escape (\\uXXXX)",
            buildUrlRaw(targetUrl, param, urlEncode(unicodeEscape(probe))), Map.of(), "GET"));
        list.add(new Mutation("HTML-entity encoding",
            buildUrlRaw(targetUrl, param, urlEncode(htmlEntityEncode(probe))), Map.of(), "GET"));
        list.add(new Mutation("Null-byte injection (%00)",
            buildUrlRaw(targetUrl, param, "%00" + urlEncode(probe)), Map.of(), "GET"));
        list.add(new Mutation("Tab/whitespace splitting",
            buildUrlRaw(targetUrl, param, urlEncode(whitespaceSplit(probe))), Map.of(), "GET"));
        list.add(new Mutation("Comment splitting (<!---->/* */)",
            buildUrlRaw(targetUrl, param, urlEncode(commentSplit(probe))), Map.of(), "GET"));
        list.add(new Mutation("Param-pollution (HPP)",
            targetUrl + (targetUrl.contains("?") ? "&" : "?")
                + param + "=safe&" + param + "=" + urlEncode(probe),
            Map.of(), "GET"));

        // 4. Content-type / Host confusion.
        list.add(new Mutation("Content-Type: application/xml",
            buildUrl(targetUrl, param, probe),
            Map.of("Content-Type", "application/xml"), "GET"));
        list.add(new Mutation("Host header tamper (localhost)",
            buildUrl(targetUrl, param, probe),
            Map.of("Host", "localhost"), "GET"));

        // 5. User-Agent / Referer cloaking.
        list.add(new Mutation("UA: Googlebot",
            buildUrl(targetUrl, param, probe),
            Map.of("User-Agent",
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"), "GET"));
        list.add(new Mutation("Referer: same-origin",
            buildUrl(targetUrl, param, probe),
            Map.of("Referer", targetUrl), "GET"));

        return list;
    }

    // ── WAF fingerprint from response headers/body ───────────────────────────

    private static String fingerprintWaf(Response r) {
        if (r == null) return null;
        String headers = r.headersString().toLowerCase();
        String body = r.body() == null ? "" : r.body().toLowerCase();

        if (headers.contains("cf-ray") || headers.contains("server: cloudflare")) return "Cloudflare";
        if (headers.contains("x-amzn-requestid") || body.contains("aws") && body.contains("waf")) return "AWS WAF";
        if (headers.contains("x-iinfo") || body.contains("incapsula")) return "Imperva/Incapsula";
        if (headers.contains("x-sucuri-id") || body.contains("sucuri")) return "Sucuri";
        if (headers.contains("akamai") || headers.contains("akamaighost")) return "Akamai";
        if (body.contains("mod_security") || body.contains("modsecurity")) return "ModSecurity";
        if (headers.contains("x-cdn: fastly")) return "Fastly";
        if (headers.contains("x-sd-fortiweb")) return "Fortinet FortiWeb";
        if (headers.contains("barracuda")) return "Barracuda";
        if (headers.contains("f5-bigip") || headers.contains("bigipserver")) return "F5 BIG-IP";
        if (body.contains("wallarm")) return "Wallarm";
        if (body.contains("reblaze")) return "Reblaze";
        return null;
    }

    // ── Mutation helpers ─────────────────────────────────────────────────────

    private static String alternateCase(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append((i % 2 == 0) ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        return sb.toString();
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String doubleEncode(String s) {
        String once = urlEncode(s);
        return once.replace("%", "%25");
    }

    private static String unicodeEscape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (Character.isLetterOrDigit(c)) sb.append(c);
            else sb.append(String.format("\\u%04x", (int) c));
        }
        return sb.toString();
    }

    private static String htmlEntityEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) sb.append("&#").append((int) c).append(';');
        return sb.toString();
    }

    private static String whitespaceSplit(String s) {
        // Insert horizontal tabs around keywords likely flagged by signatures.
        return s.replace("<script", "<\tscript")
                .replace("alert", "al\tert")
                .replace("OR", "O\tR")
                .replace("UNION", "UNI\tON");
    }

    private static String commentSplit(String s) {
        return s.replace("script", "scr<!---->ipt")
                .replace("SELECT", "SEL/*!*/ECT")
                .replace("UNION",  "UNI/*!*/ON");
    }

    // ── HTTP ─────────────────────────────────────────────────────────────────

    private record Response(int status, int size, String body, Map<String, List<String>> headers) {
        String headersString() {
            if (headers == null) return "";
            StringBuilder sb = new StringBuilder();
            headers.forEach((k, v) -> {
                if (k == null) return;
                sb.append(k).append(": ").append(String.join(",", v)).append('\n');
            });
            return sb.toString();
        }
    }

    private static boolean isBlocked(Response r) {
        if (r == null) return false;
        int s = r.status();
        if (s == 401 || s == 403 || s == 406 || s == 419 || s == 429 || s == 444
            || s == 451 || s == 501 || s == 503) return true;
        String body = r.body() == null ? "" : r.body().toLowerCase();
        return body.contains("access denied")
            || body.contains("blocked by")
            || body.contains("request blocked")
            || body.contains("attention required")  // Cloudflare challenge
            || body.contains("incapsula incident")
            || body.contains("the request was rejected")
            || body.contains("mod_security")
            || body.contains("not acceptable");
    }

    private static Response send(String url, Map<String, String> headers, String method) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod(method == null ? "GET" : method);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setInstanceFollowRedirects(false);
            if (headers != null) {
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    try { conn.setRequestProperty(e.getKey(), e.getValue()); }
                    catch (IllegalArgumentException ignored) { /* JDK blocks restricted headers like Host */ }
                }
            }
            if ("POST".equalsIgnoreCase(method)) {
                conn.setDoOutput(true);
                conn.getOutputStream().write(new byte[0]);
            }
            int code;
            try { code = conn.getResponseCode(); }
            catch (IOException ioe) { code = conn.getResponseCode(); }
            byte[] data;
            try (var in = (code >= 400 && conn.getErrorStream() != null)
                    ? conn.getErrorStream() : conn.getInputStream()) {
                data = in == null ? new byte[0] : in.readAllBytes();
            } catch (IOException ioe) {
                data = new byte[0];
            }
            String body = new String(data, StandardCharsets.UTF_8);
            Map<String, List<String>> hdrs = new LinkedHashMap<>();
            conn.getHeaderFields().forEach((k, v) -> { if (k != null) hdrs.put(k, v); });
            conn.disconnect();
            return new Response(code, data.length, body, hdrs);
        } catch (IOException | IllegalArgumentException e) {
            return new Response(-1, 0, "", Map.of());
        }
    }

    // ── URL builders ─────────────────────────────────────────────────────────

    private static String buildUrl(String base, String param, String value) {
        String sep = base.contains("?") ? "&" : "?";
        return base + sep + param + "=" + urlEncode(value);
    }

    /** Caller has already URL-encoded {@code rawValue}. */
    private static String buildUrlRaw(String base, String param, String rawValue) {
        String sep = base.contains("?") ? "&" : "?";
        return base + sep + param + "=" + rawValue;
    }

    private static String truncate(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }
}
