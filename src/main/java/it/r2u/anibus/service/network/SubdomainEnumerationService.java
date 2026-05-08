package it.r2u.anibus.service.network;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enumerates subdomains of a target domain using:
 * 1. crt.sh (Certificate Transparency logs) — passive, no auth required
 * 2. DNS brute-force against a built-in wordlist
 *
 * All findings are deduplicated and DNS-verified before returning.
 */
public class SubdomainEnumerationService {

    private static final int TIMEOUT_MS   = 8000;
    private static final int MAX_CRTSH    = 500;

    /** Compact but effective wordlist covering the most common subdomains. */
    private static final String[] WORDLIST = {
            "www", "mail", "smtp", "pop", "pop3", "imap", "ftp", "sftp",
            "dev", "staging", "test", "uat", "qa", "beta", "alpha",
            "api", "api2", "api-v1", "api-v2", "graphql", "rest",
            "admin", "panel", "dashboard", "manage", "mgmt", "control",
            "vpn", "ssh", "rdp", "remote", "gateway", "proxy",
            "cdn", "static", "assets", "media", "img", "images",
            "blog", "shop", "store", "portal", "app", "apps",
            "auth", "login", "sso", "oauth",
            "db", "database", "mysql", "postgres", "redis", "mongo",
            "jenkins", "ci", "cd", "gitlab", "github", "bitbucket",
            "jira", "confluence", "wiki", "docs", "help",
            "monitor", "status", "metrics", "grafana", "kibana",
            "k8s", "kubernetes", "docker", "registry",
            "ns1", "ns2", "dns", "mx", "mx1", "mx2",
            "intranet", "internal", "corp", "lan",
            "backup", "archive", "old", "legacy",
            "webmail", "owa", "exchange",
            "s3", "storage", "files", "upload", "download",
            "support", "ticket", "crm", "erp"
    };

    public record SubdomainResult(
            String subdomain,
            String resolvedIp,
            String source      // "crt.sh" or "brute-force"
    ) {}

    /**
     * Enumerate subdomains for the given root domain.
     *
     * @param rootDomain      e.g. "example.com"
     * @param brute           also run DNS brute-force wordlist
     * @param progressCallback progress [0..1]; may be null
     * @return deduplicated list of live subdomains
     */
    public List<SubdomainResult> enumerate(String rootDomain,
                                           boolean brute,
                                           Consumer<Double> progressCallback) {
        Set<String> seen = new HashSet<>();
        List<SubdomainResult> results = new ArrayList<>();

        // ── Phase 1: crt.sh ────────────────────────────────────────────
        List<String> fromCrt = queryCrtSh(rootDomain);
        int total = fromCrt.size() + (brute ? WORDLIST.length : 0);
        int done  = 0;

        for (String host : fromCrt) {
            String norm = host.toLowerCase().trim();
            if (norm.startsWith("*.")) norm = norm.substring(2);
            if (seen.add(norm)) {
                SubdomainResult r = resolveAndBuild(norm, "crt.sh");
                if (r != null) results.add(r);
            }
            if (progressCallback != null && total > 0)
                progressCallback.accept((double) ++done / total);
        }

        // ── Phase 2: DNS brute-force ───────────────────────────────────
        if (brute) {
            for (String word : WORDLIST) {
                String fqdn = word + "." + rootDomain;
                if (seen.add(fqdn)) {
                    SubdomainResult r = resolveAndBuild(fqdn, "brute-force");
                    if (r != null) results.add(r);
                }
                if (progressCallback != null && total > 0)
                    progressCallback.accept((double) ++done / total);
            }
        }

        results.sort((a, b) -> a.subdomain().compareToIgnoreCase(b.subdomain()));
        return results;
    }

    // ── crt.sh API ────────────────────────────────────────────────────────

    private List<String> queryCrtSh(String domain) {
        List<String> names = new ArrayList<>();
        try {
            String url = "https://crt.sh/?q=%25." + domain + "&output=json";
            HttpURLConnection conn = (HttpURLConnection)
                    URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "Anibus/1.8.0");
            conn.setRequestProperty("Accept", "application/json");

            if (conn.getResponseCode() != 200) return names;

            String json = readBody(conn.getInputStream());
            // Extract "name_value" fields without pulling in a JSON library
            Pattern p = Pattern.compile("\"name_value\"\\s*:\\s*\"([^\"]+)\"");
            Matcher m = p.matcher(json);
            int count = 0;
            while (m.find() && count < MAX_CRTSH) {
                // crt.sh may return \n-separated multi-value entries
                for (String name : m.group(1).split("\\\\n")) {
                    names.add(name.trim());
                    count++;
                }
            }
        } catch (IOException | IllegalArgumentException ignored) {}
        return names;
    }

    // ── DNS resolution ────────────────────────────────────────────────────

    private SubdomainResult resolveAndBuild(String host, String source) {
        try {
            InetAddress addr = InetAddress.getByName(host);
            return new SubdomainResult(host, addr.getHostAddress(), source);
        } catch (UnknownHostException e) {
            return null; // not live — skip
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────

    private String readBody(InputStream in) throws IOException {
        return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }

    /**
     * Format results as a human-readable report string.
     */
    public static String formatReport(List<SubdomainResult> results, String domain) {
        if (results.isEmpty())
            return "No live subdomains found for " + domain + ".";

        StringBuilder sb = new StringBuilder();
        sb.append("=== Subdomain Enumeration: ").append(domain)
                .append(" (").append(results.size()).append(" found) ===\n\n");
        for (SubdomainResult r : results) {
            sb.append(String.format("%-50s  %-18s  [%s]%n",
                    r.subdomain(), r.resolvedIp(), r.source()));
        }
        return sb.toString();
    }
}
