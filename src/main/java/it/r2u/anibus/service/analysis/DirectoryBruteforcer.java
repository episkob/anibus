package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.DoubleConsumer;

/**
 * Directory/path brute-forcer.
 * Tries a built-in wordlist of common admin/config/backup paths and reports
 * any paths that return a non-404 status code.
 */
public class DirectoryBruteforcer {

    private static final int TIMEOUT = 5000;
    private static final List<String> BACKUP_SUFFIXES = List.of(".bak", ".old", ".orig", "~", ".swp");

    private static final List<String> WORDLIST = List.of(
        "admin", "administrator", "login", "panel", "dashboard", "cpanel",
        "wp-admin", "wp-login.php", "wp-config.php", ".env", ".git/config",
        ".htaccess", ".htpasswd", "config.php", "config.json", "config.yml",
        "settings.php", "database.php", "db.php", "backup", "backup.zip",
        "backup.tar.gz", "dump.sql", "site.tar.gz", "www.zip", "old",
        "test", "debug", "phpinfo.php", "info.php", "status", "health",
        "api", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui",
        "swagger.json", "openapi.json", "v1/swagger.json", "actuator",
        "actuator/env", "actuator/health", "actuator/mappings",
        "server-status", "server-info", "nginx_status", "robots.txt",
        "sitemap.xml", "crossdomain.xml", "security.txt", ".well-known/security.txt",
        "trace", "xmlrpc.php", "readme.html", "license.txt", "changelog.txt",
        "upload", "uploads", "files", "images", "assets", "static",
        "phpmyadmin", "pma", "adminer.php", "shell.php", "cmd.php"
    );

    public record PathResult(
        String url,
        int statusCode,
        int contentLength,
        String note,
        String contentType,
        String server,
        String xPoweredBy
    ) {
        public boolean isInteresting() {
            return statusCode != 404 && statusCode != 0;
        }
    }

    /**
     * Probes the target base URL with each wordlist entry.
     *
     * @param baseUrl  Target (e.g. "https://example.com")
     * @param progress 0.0–1.0 progress callback
     * @return All findings (filter by {@link PathResult#isInteresting()} for hits)
     */
    public List<PathResult> scan(String baseUrl, DoubleConsumer progress) {
        List<PathResult> findings = new ArrayList<>();
        if (baseUrl == null || baseUrl.isBlank()) return findings;

        String base = baseUrl.replaceAll("/$", "");
        List<String> queue = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String path : WORDLIST) {
            String candidate = base + "/" + path;
            queue.add(candidate);
            seen.add(candidate);
        }

        int done = 0;
        while (done < queue.size()) {
            String candidate = queue.get(done);
            PathResult r = probe(candidate);
            if (r != null && r.isInteresting()) {
                findings.add(r);
                for (String backupUrl : buildBackupCandidates(r.url())) {
                    if (seen.add(backupUrl)) {
                        queue.add(backupUrl);
                    }
                }
                // Tech-specific extension auto-add: if the server clearly hosts PHP/ASP.NET/Java,
                // re-probe the same candidate with the matching extension so we catch e.g. /admin.php
                // when the wordlist only contains "admin".
                for (String extUrl : buildExtensionCandidates(candidate, r)) {
                    if (seen.add(extUrl)) {
                        queue.add(extUrl);
                    }
                }
            }
            done++;
            if (progress != null) progress.accept((double) done / Math.max(done, queue.size()));
        }
        return findings;
    }

    /**
     * Scans the target with a caller-supplied wordlist, optional extra extensions,
     * and bounded recursion depth. When a finding is interesting and recursion
     * depth allows, the same wordlist is re-applied beneath that path (limited
     * by {@code recursionDepth}). Pass {@code null}/empty for {@code customWordlist}
     * to fall back to the built-in list; {@code recursionDepth=0} disables recursion.
     */
    public List<PathResult> scan(String baseUrl, List<String> customWordlist,
                                 List<String> extraExtensions, int recursionDepth,
                                 DoubleConsumer progress) {
        List<PathResult> findings = new ArrayList<>();
        if (baseUrl == null || baseUrl.isBlank()) return findings;
        String base = baseUrl.replaceAll("/$", "");
        List<String> words = (customWordlist == null || customWordlist.isEmpty())
                ? WORDLIST : customWordlist;
        List<String> exts = extraExtensions == null ? List.of() : extraExtensions;
        List<String> queue = new ArrayList<>();
        java.util.Map<String, Integer> depthOf = new java.util.HashMap<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String w : words) {
            String c = base + "/" + w;
            if (seen.add(c)) { queue.add(c); depthOf.put(c, 0); }
            for (String ext : exts) {
                String suffix = ext.startsWith(".") ? ext : "." + ext;
                String ce = c + suffix;
                if (seen.add(ce)) { queue.add(ce); depthOf.put(ce, 0); }
            }
        }
        int done = 0;
        while (done < queue.size()) {
            String candidate = queue.get(done);
            int d = depthOf.getOrDefault(candidate, 0);
            PathResult r = probe(candidate);
            if (r != null && r.isInteresting()) {
                findings.add(r);
                for (String backup : buildBackupCandidates(r.url())) {
                    if (seen.add(backup)) { queue.add(backup); depthOf.put(backup, d); }
                }
                if (d < Math.max(0, recursionDepth)) {
                    for (String w : words) {
                        String c = candidate + "/" + w;
                        if (seen.add(c)) { queue.add(c); depthOf.put(c, d + 1); }
                    }
                }
            }
            done++;
            if (progress != null) progress.accept((double) done / Math.max(done, queue.size()));
        }
        return findings;
    }

    /**
     * IIS short-name (8.3) enumeration probe.
     *
     * <p>Older IIS versions leak short-name information through differing HTTP
     * status codes for paths containing {@code *~1*} — a 404 indicates the
     * pattern matched at least one file, while a 400 indicates a syntactically
     * invalid match. Iterates the alphabet and returns leading letters whose
     * probe returned 404 (i.e. files starting with that letter likely exist).
     *
     * <p>Heuristic only — used as a starting point for manual short-name
     * brute-forcing on Windows targets.
     */
    public List<String> probeIisShortNames(String baseUrl) {
        List<String> hits = new ArrayList<>();
        if (baseUrl == null || baseUrl.isBlank()) return hits;
        String base = baseUrl.replaceAll("/$", "");
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (int i = 0; i < alphabet.length(); i++) {
            char letter = alphabet.charAt(i);
            // %2A == '*' — handcoded so URI.create accepts the path.
            String probe = base + "/" + letter + "%2A~1%2A/.aspx";
            try {
                HttpURLConnection c = (HttpURLConnection) URI.create(probe).toURL().openConnection();
                c.setRequestMethod("GET");
                c.setConnectTimeout(TIMEOUT);
                c.setReadTimeout(TIMEOUT);
                c.setInstanceFollowRedirects(false);
                c.connect();
                int sc = c.getResponseCode();
                c.disconnect();
                // 404 (path-matches-pattern) is the leak indicator on vulnerable IIS;
                // 400 means the pattern matched no name.
                if (sc == 404) hits.add(String.valueOf(letter));
            } catch (IOException | IllegalArgumentException ignored) {
                // network / parsing failure — skip this letter
            }
        }
        return hits;
    }

    private List<String> buildBackupCandidates(String url) {
        List<String> variants = new ArrayList<>();
        if (url == null || url.isBlank() || hasBackupSuffix(url)) {
            return variants;
        }
        for (String suffix : BACKUP_SUFFIXES) {
            variants.add(url + suffix);
        }
        return variants;
    }

    /**
     * If the discovered path returns hints of a specific server stack
     * (PHP, ASP.NET, Java/Tomcat), suggest the same path with the matching
     * file extension so we can catch /admin.php, /admin.aspx, /admin.jsp etc.
     */
    private List<String> buildExtensionCandidates(String url, PathResult r) {
        List<String> variants = new ArrayList<>();
        if (url == null || url.isBlank() || r == null) return variants;
        if (url.matches(".*\\.[a-zA-Z0-9]{2,6}$")) return variants; // already has an extension
        String hay = ((r.contentType() == null ? "" : r.contentType()) + " "
                    + (r.server()      == null ? "" : r.server())      + " "
                    + (r.xPoweredBy() == null ? "" : r.xPoweredBy())).toLowerCase();
        if (hay.contains("php")) {
            variants.add(url + ".php");
            variants.add(url + ".phtml");
        }
        if (hay.contains("asp.net") || hay.contains("iis") || hay.contains("microsoft-")) {
            variants.add(url + ".aspx");
            variants.add(url + ".asp");
        }
        if (hay.contains("tomcat") || hay.contains("jetty") || hay.contains("jsp") || hay.contains("coyote")) {
            variants.add(url + ".jsp");
            variants.add(url + ".do");
            variants.add(url + ".action");
        }
        return variants;
    }

    private boolean hasBackupSuffix(String url) {
        String lower = url.toLowerCase();
        return lower.endsWith(".bak")
                || lower.endsWith(".old")
                || lower.endsWith(".orig")
                || lower.endsWith("~")
                || lower.endsWith(".swp");
    }

    private PathResult probe(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(false);
            conn.connect();

            int status = conn.getResponseCode();
            int length = conn.getContentLength();
            String contentType = headerOrNa(conn, "Content-Type");
            String server = headerOrNa(conn, "Server");
            String xPoweredBy = headerOrNa(conn, "X-Powered-By");
            String redirectLocation = (status >= 300 && status < 400) ? conn.getHeaderField("Location") : null;
            conn.disconnect();

            String note = switch (status) {
                case 200 -> "Accessible";
                case 301, 302, 307, 308 -> "Redirect → " + redirectLocation;
                case 401 -> "Unauthorized (exists but protected)";
                case 403 -> "Forbidden (exists but access denied)";
                case 500 -> "Server Error (path exists)";
                default  -> "HTTP " + status;
            };
            return new PathResult(url, status, length, note, contentType, server, xPoweredBy);
        } catch (IOException | IllegalArgumentException ignored) {
            return null;
        }
    }

    private static String headerOrNa(HttpURLConnection conn, String name) {
        String v = conn.getHeaderField(name);
        return (v == null || v.isBlank()) ? "n/a" : v.trim();
    }

    public static String formatReport(List<PathResult> results, String baseUrl) {
        StringBuilder sb = new StringBuilder("=== DIR BRUTEFORCE: ").append(baseUrl).append(" ===\n");
        if (results == null || results.isEmpty()) {
            sb.append("  No interesting paths found.\n");
            return sb.toString();
        }
        // Group by status tier
        List<PathResult> open     = results.stream().filter(r -> r.statusCode() == 200).toList();
        List<PathResult> redirect = results.stream().filter(r -> r.statusCode() >= 301 && r.statusCode() < 400).toList();
        List<PathResult> other    = results.stream().filter(r -> r.statusCode() >= 400).toList();

        if (!open.isEmpty()) {
            sb.append("\n  ── Accessible (200) ─────────────────────────────────\n");
            open.forEach(r -> appendWithHeaders(sb, r));
        }
        if (!redirect.isEmpty()) {
            sb.append("\n  ── Redirects ─────────────────────────────────────────\n");
            redirect.forEach(r -> {
                appendWithHeaders(sb, r);
                sb.append("        → ").append(r.note()).append("\n");
            });
        }
        if (!other.isEmpty()) {
            sb.append("\n  ── Auth/Errors ────────────────────────────────────────\n");
            other.forEach(r -> {
                appendWithHeaders(sb, r);
                sb.append("        (").append(r.note()).append(")\n");
            });
        }
        sb.append("\n  Total: ").append(results.size()).append(" finding(s)\n");
        return sb.toString();
    }

    private static void appendWithHeaders(StringBuilder sb, PathResult r) {
        sb.append("    [").append(r.statusCode()).append("] ").append(r.url()).append("\n");
        boolean hasHeader = !"n/a".equals(r.contentType())
                || !"n/a".equals(r.server())
                || !"n/a".equals(r.xPoweredBy());
        if (hasHeader) {
            sb.append("        Content-Type: ").append(r.contentType())
              .append(" | Server: ").append(r.server())
              .append(" | X-Powered-By: ").append(r.xPoweredBy())
              .append("\n");
        }
    }
}
