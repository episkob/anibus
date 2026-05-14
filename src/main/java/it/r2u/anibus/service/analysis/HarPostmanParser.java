package it.r2u.anibus.service.analysis;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.r2u.anibus.model.EndpointInfo;

/**
 * Lightweight parser for HAR (HTTP Archive 1.2) and Postman Collection v2.x JSON
 * exports. Extracts endpoints (method + url + parameters) as {@link EndpointInfo}
 * so they can feed into {@code ApiSecurityModeService} alongside OpenAPI specs.
 *
 * <p>Uses regex-driven extraction in the same style as the existing OpenAPI
 * scanner — no external JSON dependency. Trade-off: tolerates whitespace/order
 * variations but does not validate schema. Good-enough for endpoint discovery,
 * not a substitute for a full JSON parser.</p>
 *
 * <p>Auto-detects format by the presence of {@code "log"} / {@code "entries"}
 * (HAR) versus {@code "info"} / {@code "item"} (Postman). Unknown payloads
 * return an empty list.</p>
 */
public final class HarPostmanParser {

    /** Format hint reported back to the caller. */
    public enum Format { HAR, POSTMAN, UNKNOWN }

    /** Parse result: detected format + extracted endpoints. */
    public record ParseResult(Format format, List<EndpointInfo> endpoints) {}

    // HAR: each entry has   "request": { "method": "...", "url": "..." }
    private static final Pattern HAR_REQUEST = Pattern.compile(
        "\"request\"\\s*:\\s*\\{[^{}]*?\"method\"\\s*:\\s*\"([A-Z]+)\"[^{}]*?\"url\"\\s*:\\s*\"([^\"]+)\"",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );
    // Reverse order: url first, then method
    private static final Pattern HAR_REQUEST_REV = Pattern.compile(
        "\"request\"\\s*:\\s*\\{[^{}]*?\"url\"\\s*:\\s*\"([^\"]+)\"[^{}]*?\"method\"\\s*:\\s*\"([A-Z]+)\"",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // Postman v2.x: "request": { "method": "GET", "url": "https://..." }
    private static final Pattern POSTMAN_REQUEST_STR = Pattern.compile(
        "\"method\"\\s*:\\s*\"([A-Z]+)\"\\s*,\\s*(?:\"header\"\\s*:\\s*\\[[^\\]]*\\]\\s*,\\s*)?\"url\"\\s*:\\s*\"([^\"]+)\"",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );
    // Postman v2.x: "request": { "method":"GET", "url": { "raw": "https://..." } }
    private static final Pattern POSTMAN_REQUEST_OBJ = Pattern.compile(
        "\"method\"\\s*:\\s*\"([A-Z]+)\"\\s*[\\s\\S]{0,400}?\"url\"\\s*:\\s*\\{[^{}]*?\"raw\"\\s*:\\s*\"([^\"]+)\"",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    private static final Pattern QUERY_PARAM = Pattern.compile("([^&?=]+)=([^&]*)");

    private HarPostmanParser() { /* no instances */ }

    /** Auto-detects the format and parses. */
    public static ParseResult parse(String json) {
        if (json == null || json.isBlank()) {
            return new ParseResult(Format.UNKNOWN, List.of());
        }
        Format fmt = detect(json);
        return switch (fmt) {
            case HAR     -> new ParseResult(Format.HAR, parseHar(json));
            case POSTMAN -> new ParseResult(Format.POSTMAN, parsePostman(json));
            case UNKNOWN -> new ParseResult(Format.UNKNOWN, List.of());
        };
    }

    /** Returns the detected format without doing full extraction. */
    public static Format detect(String json) {
        if (json == null) return Format.UNKNOWN;
        String head = json.length() > 4096 ? json.substring(0, 4096) : json;
        boolean har = head.contains("\"log\"") && head.contains("\"entries\"");
        boolean postman = head.contains("\"info\"")
                       && (head.contains("\"_postman_id\"")
                           || head.contains("\"schema\"")
                           || head.contains("\"item\""));
        if (har && !postman) return Format.HAR;
        if (postman && !har) return Format.POSTMAN;
        if (har) return Format.HAR;
        if (postman) return Format.POSTMAN;
        return Format.UNKNOWN;
    }

    private static List<EndpointInfo> parseHar(String json) {
        List<EndpointInfo> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        Matcher m = HAR_REQUEST.matcher(json);
        while (m.find()) {
            addEndpoint(out, seen, m.group(1), m.group(2), "HAR");
        }
        m = HAR_REQUEST_REV.matcher(json);
        while (m.find()) {
            addEndpoint(out, seen, m.group(2), m.group(1), "HAR");
        }
        return out;
    }

    private static List<EndpointInfo> parsePostman(String json) {
        List<EndpointInfo> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        Matcher m = POSTMAN_REQUEST_OBJ.matcher(json);
        while (m.find()) {
            addEndpoint(out, seen, m.group(1), unescape(m.group(2)), "POSTMAN");
        }
        m = POSTMAN_REQUEST_STR.matcher(json);
        while (m.find()) {
            addEndpoint(out, seen, m.group(1), unescape(m.group(2)), "POSTMAN");
        }
        return out;
    }

    private static void addEndpoint(List<EndpointInfo> out, Set<String> seen,
                                    String method, String url, String context) {
        if (method == null || url == null) return;
        String m = method.trim().toUpperCase(Locale.ROOT);
        String u = url.trim();
        if (m.isEmpty() || u.isEmpty()) return;
        // Skip Postman variables ({{baseUrl}}) and obviously non-HTTP entries
        if (u.contains("{{") && !u.contains("://")) return;
        String dedupKey = m + " " + u;
        if (!seen.add(dedupKey)) return;

        String baseUrl = "";
        String path = u;
        List<String> params = new ArrayList<>();
        try {
            URI uri = URI.create(u);
            if (uri.getScheme() != null && uri.getHost() != null) {
                baseUrl = uri.getScheme() + "://" + uri.getAuthority();
                path = uri.getRawPath() == null ? "/" : uri.getRawPath();
            }
            String q = uri.getRawQuery();
            if (q != null) {
                Matcher pm = QUERY_PARAM.matcher(q);
                while (pm.find()) {
                    String name = pm.group(1);
                    if (!name.isBlank() && !params.contains(name)) params.add(name);
                }
            }
        } catch (IllegalArgumentException ignored) { /* keep raw url */ }

        Map<String, String> headers = new LinkedHashMap<>();
        out.add(new EndpointInfo(u, baseUrl, path, m,
                Collections.unmodifiableList(params),
                headers, context, false));
    }

    private static String unescape(String s) {
        if (s == null) return null;
        return s.replace("\\/", "/")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }

    /** Human-readable summary of a parse result. */
    public static String formatReport(ParseResult result, String sourceName) {
        StringBuilder sb = new StringBuilder("=== HAR/POSTMAN IMPORT: ")
            .append(sourceName == null ? "input" : sourceName).append(" ===\n");
        sb.append("  Format    : ").append(result.format()).append("\n");
        sb.append("  Endpoints : ").append(result.endpoints().size()).append("\n");
        if (result.endpoints().isEmpty()) return sb.toString();

        Map<String, Integer> byMethod = new LinkedHashMap<>();
        Set<String> hosts = new LinkedHashSet<>();
        for (EndpointInfo e : result.endpoints()) {
            byMethod.merge(e.getHttpMethod(), 1, Integer::sum);
            if (e.getBaseUrl() != null && !e.getBaseUrl().isBlank()) hosts.add(e.getBaseUrl());
        }
        sb.append("  Methods   : ").append(byMethod).append("\n");
        sb.append("  Hosts     : ").append(hosts.isEmpty() ? "(relative)" : hosts).append("\n");

        sb.append("\n  Sample (first 10):\n");
        int n = Math.min(10, result.endpoints().size());
        for (int i = 0; i < n; i++) {
            EndpointInfo e = result.endpoints().get(i);
            sb.append("    ").append(e.getHttpMethod()).append(" ").append(e.getUrl());
            if (e.getParameters() != null && !e.getParameters().isEmpty()) {
                sb.append("  params=").append(e.getParameters());
            }
            sb.append("\n");
        }
        return sb.toString();
    }
}
