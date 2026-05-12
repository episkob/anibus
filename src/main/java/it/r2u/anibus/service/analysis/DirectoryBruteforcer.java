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
        String note
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
            }
            done++;
            if (progress != null) progress.accept((double) done / Math.max(done, queue.size()));
        }
        return findings;
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
            conn.disconnect();

            String note = switch (status) {
                case 200 -> "Accessible";
                case 301, 302, 307, 308 -> "Redirect → " + conn.getHeaderField("Location");
                case 401 -> "Unauthorized (exists but protected)";
                case 403 -> "Forbidden (exists but access denied)";
                case 500 -> "Server Error (path exists)";
                default  -> "HTTP " + status;
            };
            return new PathResult(url, status, length, note);
        } catch (IOException | IllegalArgumentException ignored) {
            return null;
        }
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
            open.forEach(r -> sb.append("    [200] ").append(r.url()).append("\n"));
        }
        if (!redirect.isEmpty()) {
            sb.append("\n  ── Redirects ─────────────────────────────────────────\n");
            redirect.forEach(r -> sb.append("    [").append(r.statusCode()).append("] ")
                .append(r.url()).append("  → ").append(r.note()).append("\n"));
        }
        if (!other.isEmpty()) {
            sb.append("\n  ── Auth/Errors ────────────────────────────────────────\n");
            other.forEach(r -> sb.append("    [").append(r.statusCode()).append("] ")
                .append(r.url()).append("  (").append(r.note()).append(")\n"));
        }
        sb.append("\n  Total: ").append(results.size()).append(" finding(s)\n");
        return sb.toString();
    }
}
