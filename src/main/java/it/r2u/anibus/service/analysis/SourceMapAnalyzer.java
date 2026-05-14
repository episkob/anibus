package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fetches and parses JavaScript Source Maps (.js.map files).
 *
 * When a server exposes source maps, Anibus can reconstruct the original
 * source file names and, where available, the original source content,
 * enabling much deeper static analysis than minified bundles allow.
 *
 * Supports Source Map v3 format (most common: Webpack, Vite, Rollup, esbuild).
 */
public class SourceMapAnalyzer {

    private static final int TIMEOUT_MS = 8000;
    private static final int MAX_SIZE   = 10 * 1024 * 1024; // 10 MB

    public record SourceFile(
            String path,        // original source path from "sources" array
            String content,     // original source (from "sourcesContent") or ""
            boolean hasContent
    ) {}

    public record SourceMapResult(
            String mapUrl,
            int    version,
            String file,        // generated file name (usually the .js filename)
            List<SourceFile> sources,
            String rawJson,
            String error        // non-null if fetch/parse failed
    ) {
        public boolean ok() { return error == null; }
    }

    /**
     * Given a JS URL, attempts to locate and fetch its source map by:
     * 1. Appending ".map" to the URL
     * 2. Reading the {@code //# sourceMappingURL=} comment from the JS
     *
     * @param jsUrl full URL to the JavaScript file (http/https)
     * @return parsed result (check {@link SourceMapResult#ok()})
     */
    public SourceMapResult analyzeFromJsUrl(String jsUrl) {
        // First try reading the JS to find the sourceMappingURL comment
        String mapUrl = resolveMapUrlFromJs(jsUrl);
        if (mapUrl == null) {
            // Fallback: just append .map
            mapUrl = jsUrl.endsWith(".js") ? jsUrl + ".map" : jsUrl + ".map";
        }
        return fetchAndParse(mapUrl);
    }

    /**
     * Directly fetch and parse a source map from a known URL.
     */
    public SourceMapResult fetchAndParse(String mapUrl) {
        try {
            String json = fetchText(mapUrl);
            if (json == null || json.isBlank())
                return error(mapUrl, "Empty response or fetch failed");
            return parse(mapUrl, json);
        } catch (Exception e) {
            return error(mapUrl, e.getMessage());
        }
    }

    // ── Parser ────────────────────────────────────────────────────────────

    private SourceMapResult parse(String mapUrl, String json) {
        int version = extractInt(json, "version", 3);
        String file = extractString(json, "file", "");

        List<String> sourcePaths    = extractArray(json, "sources");
        List<String> sourcesContent = extractArray(json, "sourcesContent");

        List<SourceFile> files = new ArrayList<>();
        for (int i = 0; i < sourcePaths.size(); i++) {
            String path    = sourcePaths.get(i);
            boolean hasSrc = i < sourcesContent.size()
                    && sourcesContent.get(i) != null
                    && !sourcesContent.get(i).equals("null");
            String content = hasSrc ? sourcesContent.get(i) : "";
            files.add(new SourceFile(path, content, hasSrc));
        }

        return new SourceMapResult(mapUrl, version, file, files, json, null);
    }

    // ── sourceMappingURL detection ────────────────────────────────────────

    private String resolveMapUrlFromJs(String jsUrl) {
        try {
            String js = fetchText(jsUrl);
            if (js == null) return null;
            // Read only last 1024 chars for performance
            String tail = js.length() > 1024 ? js.substring(js.length() - 1024) : js;
            Pattern p = Pattern.compile("//[#@]\\s*sourceMappingURL=([^\\s\\r\\n]+)");
            Matcher m = p.matcher(tail);
            if (!m.find()) return null;
            String ref = m.group(1).trim();
            if (ref.startsWith("http://") || ref.startsWith("https://")) return ref;
            // relative → resolve against JS URL
            int slash = jsUrl.lastIndexOf('/');
            return (slash >= 0 ? jsUrl.substring(0, slash + 1) : jsUrl + "/") + ref;
        } catch (Exception e) {
            return null;
        }
    }

    // ── Format report ─────────────────────────────────────────────────────

    /**
     * Produce a human-readable summary of a SourceMapResult.
     */
    public static String formatReport(SourceMapResult result) {
        if (!result.ok()) {
            return "Source Map fetch failed: " + result.error();
        }
        StringBuilder sb = new StringBuilder();
        sb.append("=== Source Map Analysis ===\n");
        sb.append("Map URL : ").append(result.mapUrl()).append("\n");
        sb.append("Version : ").append(result.version()).append("\n");
        if (!result.file().isBlank())
            sb.append("File    : ").append(result.file()).append("\n");
        sb.append("Sources : ").append(result.sources().size()).append(" files\n\n");

        // Group by top-level directory
        Map<String, List<SourceFile>> byDir = new LinkedHashMap<>();
        for (SourceFile sf : result.sources()) {
            String dir = parentDir(sf.path());
            byDir.computeIfAbsent(dir, k -> new ArrayList<>()).add(sf);
        }

        int withContent = (int) result.sources().stream()
                .filter(SourceFile::hasContent).count();

        sb.append(String.format("%-60s  %s%n", "Path", "Has Source"));
        sb.append("─".repeat(70)).append("\n");
        for (SourceFile sf : result.sources()) {
            sb.append(String.format("%-60s  %s%n",
                    truncate(sf.path(), 60),
                    sf.hasContent() ? "✓" : "—"));
        }
        sb.append("\n");
        sb.append("Source content embedded: ").append(withContent)
                .append(" / ").append(result.sources().size()).append(" files\n");
        return sb.toString();
    }

    /** Run WebSourceAnalyzer + JavaScriptSecurityAnalyzer crypto-key scan over all embedded source content. */
    public static List<it.r2u.anibus.model.LeakInfo> extractLeaks(SourceMapResult result) {
        if (!result.ok()) return List.of();
        List<it.r2u.anibus.model.LeakInfo> leaks = new ArrayList<>();
        for (SourceFile sf : result.sources()) {
            if (sf.hasContent() && !sf.content().isBlank()) {
                leaks.addAll(WebSourceAnalyzer.analyzeSource(sf.content()));
                leaks.addAll(JavaScriptSecurityAnalyzer.extractCryptoLeaks(sf.content()));
            }
        }
        return leaks;
    }

    // ── JSON micro-parser (no external deps) ─────────────────────────────

    private static int extractInt(String json, String key, int fallback) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : fallback;
    }

    private static String extractString(String json, String key, String fallback) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"\\\\]*)\"").matcher(json);
        return m.find() ? m.group(1) : fallback;
    }

    /**
     * Extract a JSON string array like {@code "key": ["a","b","c"]} or
     * mixed with null values like {@code "sourcesContent": ["code",null]}.
     */
    private static List<String> extractArray(String json, String key) {
        List<String> out = new ArrayList<>();
        // find the array start
        Pattern start = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[");
        Matcher ms = start.matcher(json);
        if (!ms.find()) return out;

        int idx = ms.end();
        // walk the array character by character
        while (idx < json.length()) {
            // skip whitespace
            while (idx < json.length() && Character.isWhitespace(json.charAt(idx))) idx++;
            if (idx >= json.length()) break;
            char c = json.charAt(idx);
            if (c == ']') break;
            if (c == '"') {
                // quoted string
                StringBuilder sb = new StringBuilder();
                idx++;
                while (idx < json.length()) {
                    char ch = json.charAt(idx);
                    if (ch == '"') break;
                    if (ch == '\\') {
                        idx++;
                        if (idx < json.length()) {
                            char esc = json.charAt(idx);
                            sb.append(switch (esc) {
                                case 'n' -> '\n'; case 'r' -> '\r'; case 't' -> '\t';
                                case '"' -> '"'; case '\\' -> '\\';
                                default  -> esc;
                            });
                        }
                    } else {
                        sb.append(ch);
                    }
                    idx++;
                }
                out.add(sb.toString());
                idx++; // skip closing "
            } else if (json.startsWith("null", idx)) {
                out.add(null);
                idx += 4;
            } else {
                idx++; // skip comma or unknown
            }
        }
        return out;
    }

    // ── HTTP fetch ───────────────────────────────────────────────────────

    private String fetchText(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection)
                    URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "Anibus/1.8.0");
            if (conn.getResponseCode() != 200) return null;
            InputStream in = conn.getInputStream();
            byte[] bytes = in.readNBytes(MAX_SIZE);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException ignored) {
            return null;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static String parentDir(String path) {
        int slash = path.lastIndexOf('/');
        return slash > 0 ? path.substring(0, slash) : "/";
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : "…" + s.substring(s.length() - (max - 1));
    }

    private static SourceMapResult error(String url, String msg) {
        return new SourceMapResult(url, 0, "", List.of(), "", msg);
    }
}
