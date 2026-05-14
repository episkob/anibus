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

    /** Reflection context — where the canary lands in the response. */
    public enum Context {
        HTML_TEXT,          // between tags, classic <h1>CANARY</h1>
        HTML_ATTRIBUTE,     // inside attribute value <input value="CANARY">
        SCRIPT_BLOCK,       // inside <script>...CANARY...</script>
        JS_STRING,          // inside a JS string literal var x="CANARY"
        STYLE_BLOCK,        // inside <style> or style="..."
        HTML_COMMENT,       // inside <!-- CANARY -->
        URL_ATTRIBUTE,      // href / src / action containing CANARY
        UNKNOWN
    }

    /** Result of a single XSS probe. */
    public record XssResult(
        String url,
        String parameter,
        String payload,
        boolean reflected,
        String evidence,
        String pocCurl,
        Context context,
        String escapeHint,
        boolean stored,
        String verifyUrl
    ) {
        public String risk() {
            if (!reflected) return "NONE";
            String base = switch (context) {
                case SCRIPT_BLOCK, JS_STRING, URL_ATTRIBUTE -> "CRITICAL";
                case HTML_TEXT, HTML_ATTRIBUTE              -> "HIGH";
                case STYLE_BLOCK                            -> "MEDIUM";
                case HTML_COMMENT, UNKNOWN                  -> "LOW";
            };
            // Stored XSS is always escalated to CRITICAL regardless of context
            // (persistence drastically raises impact).
            return stored ? "CRITICAL" : base;
        }
        /** Reproducible PoC URL with payload pre-injected. */
        public String pocUrl() { return url; }
        /** Kind of XSS: "stored" or "reflected". */
        public String kind() { return stored ? "stored" : "reflected"; }
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

    /**
     * Probes for stored (persistent) XSS by injecting payloads through {@code injectUrl}
     * and then re-fetching {@code verifyUrl} to see if the canary appears unescaped.
     *
     * <p>Typical pattern: submit a comment / profile bio / message via {@code injectUrl},
     * then re-fetch the page that displays it. Findings with {@code stored=true} are
     * automatically escalated to CRITICAL risk.</p>
     *
     * @param injectUrl  URL that accepts the user-controlled parameter (e.g. comment endpoint)
     * @param parameters Parameter names to inject into
     * @param verifyUrl  URL that should subsequently render the persisted value
     * @param progress   0.0–1.0 callback (may be null)
     */
    public List<XssResult> scanStored(String injectUrl, List<String> parameters,
                                      String verifyUrl, DoubleConsumer progress) {
        List<XssResult> findings = new ArrayList<>();
        if (injectUrl == null || injectUrl.isBlank()
                || verifyUrl == null || verifyUrl.isBlank()) return findings;

        List<String> params = (parameters == null || parameters.isEmpty())
            ? List.of("comment", "message", "body", "content", "text", "bio", "name")
            : parameters;

        int total = params.size() * PAYLOADS.size();
        int done = 0;

        for (String param : params) {
            for (String payload : PAYLOADS) {
                XssResult result = probeStored(injectUrl, param, payload, verifyUrl);
                if (result != null) findings.add(result);
                done++;
                if (progress != null) progress.accept((double) done / total);
            }
        }
        return findings;
    }

    private XssResult probeStored(String injectUrl, String param, String payload, String verifyUrl) {
        try {
            String encoded = URLEncoder.encode(payload, StandardCharsets.UTF_8);
            String separator = injectUrl.contains("?") ? "&" : "?";
            String submitUrl = injectUrl + separator + param + "=" + encoded;

            // 1. Inject (GET form-style; sufficient for many guestbook / search-history sinks)
            HttpURLConnection inj = openConnection(submitUrl);
            inj.setRequestMethod("GET");
            inj.setConnectTimeout(TIMEOUT);
            inj.setReadTimeout(TIMEOUT);
            inj.setInstanceFollowRedirects(true);
            inj.connect();
            inj.getInputStream().readAllBytes();
            inj.disconnect();

            // 2. Re-fetch verify URL and look for the canary
            HttpURLConnection ver = openConnection(verifyUrl);
            ver.setRequestMethod("GET");
            ver.setConnectTimeout(TIMEOUT);
            ver.setReadTimeout(TIMEOUT);
            ver.setInstanceFollowRedirects(true);
            ver.connect();
            String body = new String(ver.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            ver.disconnect();

            boolean reflected = body.contains(payload) || body.contains(CANARY);
            if (reflected) {
                String evidence = extractEvidence(body, CANARY, 80);
                String curl = "curl -i '" + submitUrl.replace("'", "'\\''") + "' && curl -i '"
                    + verifyUrl.replace("'", "'\\''") + "'";
                Context ctx = detectContext(body, CANARY);
                String hint = escapeHintFor(ctx);
                return new XssResult(submitUrl, param, payload, true, evidence, curl,
                                     ctx, hint, true, verifyUrl);
            }
        } catch (IOException ignored) { }
        return null;
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
                String curl = "curl -i '" + probeUrl.replace("'", "'\\''") + "'";
                Context ctx = detectContext(body, CANARY);
                String hint = escapeHintFor(ctx);
                return new XssResult(probeUrl, param, payload, true, evidence, curl,
                                     ctx, hint, false, null);
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

    /**
     * Determines the lexical context where {@code needle} appears in the response body.
     * Uses lightweight heuristics on a window around the first occurrence.
     */
    static Context detectContext(String body, String needle) {
        int idx = body.indexOf(needle);
        if (idx < 0) return Context.UNKNOWN;
        String before = body.substring(Math.max(0, idx - 512), idx);
        String beforeLower = before.toLowerCase();

        // HTML comment <!-- ... -->
        int cmtOpen = beforeLower.lastIndexOf("<!--");
        int cmtClose = beforeLower.lastIndexOf("-->");
        if (cmtOpen > cmtClose) return Context.HTML_COMMENT;

        // Inside <script>...</script>
        int scriptOpen = beforeLower.lastIndexOf("<script");
        int scriptClose = beforeLower.lastIndexOf("</script");
        if (scriptOpen > scriptClose) {
            // Inside script — check if inside a quoted string
            String afterTag = before.substring(beforeLower.indexOf('>', scriptOpen) + 1);
            if (insideQuotedString(afterTag)) return Context.JS_STRING;
            return Context.SCRIPT_BLOCK;
        }

        // Inside <style>...</style>
        int styleOpen = beforeLower.lastIndexOf("<style");
        int styleClose = beforeLower.lastIndexOf("</style");
        if (styleOpen > styleClose) return Context.STYLE_BLOCK;

        // Inside an open tag — attribute context
        int lastLt = before.lastIndexOf('<');
        int lastGt = before.lastIndexOf('>');
        if (lastLt > lastGt) {
            String tagFragment = beforeLower.substring(lastLt);
            // URL-bearing attributes
            if (tagFragment.matches(".*\\b(href|src|action|formaction|xlink:href|data|poster|background)\\s*=\\s*[\"']?[^\"']*$")) {
                return Context.URL_ATTRIBUTE;
            }
            // Inline style attribute
            if (tagFragment.matches(".*\\bstyle\\s*=\\s*[\"']?[^\"']*$")) {
                return Context.STYLE_BLOCK;
            }
            return Context.HTML_ATTRIBUTE;
        }

        return Context.HTML_TEXT;
    }

    /** Checks whether the position at the end of {@code fragment} is inside an unclosed JS string literal. */
    private static boolean insideQuotedString(String fragment) {
        boolean inSingle = false, inDouble = false, inBacktick = false;
        boolean escape = false;
        for (int i = 0; i < fragment.length(); i++) {
            char c = fragment.charAt(i);
            if (escape) { escape = false; continue; }
            if (c == '\\') { escape = true; continue; }
            if (!inDouble && !inBacktick && c == '\'') inSingle = !inSingle;
            else if (!inSingle && !inBacktick && c == '"') inDouble = !inDouble;
            else if (!inSingle && !inDouble && c == '`') inBacktick = !inBacktick;
        }
        return inSingle || inDouble || inBacktick;
    }

    private static String escapeHintFor(Context ctx) {
        return switch (ctx) {
            case HTML_TEXT       -> "HTML-encode (&lt; &gt; &amp; &quot; &#39;) before insertion into element text";
            case HTML_ATTRIBUTE  -> "HTML-attribute encode and always quote the attribute value";
            case SCRIPT_BLOCK    -> "Do NOT inject into <script> raw; use JSON.stringify or move data to data-* attributes";
            case JS_STRING       -> "JavaScript string encode (\\xHH / \\uHHHH) and quote the literal";
            case STYLE_BLOCK     -> "CSS escape (\\HH) and reject expressions / url() with javascript:";
            case URL_ATTRIBUTE   -> "Validate scheme (http/https only), reject javascript:/data:/vbscript:, then URL-encode";
            case HTML_COMMENT    -> "Avoid placing user input in HTML comments — strip '--' sequences at minimum";
            case UNKNOWN         -> "Apply context-specific encoding once the sink is identified";
        };
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
                sb.append("\n  [").append(r.risk()).append("] ").append(r.kind())
                  .append(" · param=").append(r.parameter()).append("\n");
                sb.append("    payload : ").append(r.payload()).append("\n");
                sb.append("    context : ").append(r.context()).append("\n");
                sb.append("    PoC URL : ").append(r.pocUrl()).append("\n");
                if (r.verifyUrl() != null)
                    sb.append("    verify  : ").append(r.verifyUrl()).append("\n");
                sb.append("    PoC curl: ").append(r.pocCurl()).append("\n");
                if (r.escapeHint() != null && !r.escapeHint().isBlank())
                    sb.append("    fix     : ").append(r.escapeHint()).append("\n");
                if (!r.evidence().isBlank())
                    sb.append("    evidence: ").append(r.evidence()).append("\n");
            }
        }
        return sb.toString();
    }
}
