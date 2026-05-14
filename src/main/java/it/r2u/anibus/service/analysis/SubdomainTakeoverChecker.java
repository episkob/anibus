package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Subdomain Takeover Checker
 *
 * Checks common subdomain names for fingerprints of dangling DNS entries
 * pointing to unclaimed resources on GitHub Pages, Heroku, AWS S3, etc.
 * No external APIs required — all detection is HTTP-based fingerprinting.
 */
public class SubdomainTakeoverChecker {

    public record TakeoverFinding(
        String subdomain,
        String platform,
        String fingerprint,
        boolean vulnerable
    ) {}

    private static final String[] SUBDOMAIN_PREFIXES = {
        "www", "mail", "remote", "blog", "webmail", "server",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
        "portal", "ns", "admin", "dev", "staging", "api",
        "cdn", "static", "assets", "img", "media", "help", "support",
        "app", "web", "cloud", "demo", "docs", "status", "beta"
    };

    // HTTP response body fingerprints mapped to known vulnerable platforms
    private static final Map<String, String> FINGERPRINTS = Map.ofEntries(
        Map.entry("There isn't a GitHub Pages site here", "GitHub Pages"),
        Map.entry("No such app", "Heroku"),
        Map.entry("NoSuchBucket", "AWS S3"),
        Map.entry("The specified container does not exist", "Azure Blob Storage"),
        Map.entry("project not found", "Surge.sh"),
        Map.entry("Fastly error: unknown domain", "Fastly"),
        Map.entry("The item you requested was not found", "SendGrid"),
        Map.entry("Status page not found", "Statuspage.io"),
        Map.entry("This UserVoice subdomain is either invalid", "UserVoice"),
        Map.entry("Repository not found", "GitHub"),
        Map.entry("Unrecognized domain", "Netlify"),
        Map.entry("is not a registered InCloud YouTrack", "JetBrains YouTrack"),
        Map.entry("does not exist in our system", "Tilda"),
        Map.entry("The page you're looking for doesn't exist", "Webflow"),
        Map.entry("Sorry, We Couldn\u2019t Find That Page", "Shopify"),
        Map.entry("ghost: Failed to lookup view", "Ghost"),
        Map.entry("404 Not Found", "Cargo"),
        // Modern platforms (v2)
        Map.entry("The deployment could not be found on Vercel", "Vercel"),
        Map.entry("DEPLOYMENT_NOT_FOUND", "Vercel"),
        Map.entry("Not Found - Request ID:", "Render"),
        Map.entry("404 page not found", "Fly.io"),
        Map.entry("The site configured at this address does not contain the requested file", "Pantheon"),
        Map.entry("page not found", "Strikingly"),
        Map.entry("Whatever you were looking for doesn't currently exist", "Tumblr"),
        Map.entry("There's nothing here, yet.", "Tumblr"),
        Map.entry("Trying to access your account?", "Campaign Monitor"),
        Map.entry("Domain mapping upgrade for this domain not found", "WordPress"),
        Map.entry("Sorry, this shop is currently unavailable", "Shopify Store"),
        Map.entry("Unable to satisfy request: host not in domain", "AWS Elastic Beanstalk"),
        Map.entry("is not a Smartling page", "Smartling"),
        Map.entry("You may have mistyped the address or the page may have moved", "Acquia"),
        Map.entry("It looks like you may have taken a wrong turn somewhere", "Ngrok"),
        Map.entry("Tunnel *.ngrok.io not found", "Ngrok"),
        Map.entry("This Help Center no longer exists", "Help Scout"),
        Map.entry("Sorry, this page is no longer available", "Wishpond"),
        Map.entry("Project doesnt exist... yet!", "Readme.io"),
        Map.entry("This domain is not configured", "Worksites.net"),
        Map.entry("\"errorCode\":\"NOT_FOUND\"", "Railway"),
        Map.entry("LeadPages", "LeadPages")
    );

    private final int timeoutMs;

    public SubdomainTakeoverChecker(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public SubdomainTakeoverChecker() {
        this(4000);
    }

    public List<TakeoverFinding> check(String domain) {
        List<TakeoverFinding> results = new ArrayList<>();
        for (String prefix : SUBDOMAIN_PREFIXES) {
            TakeoverFinding finding = probe(prefix + "." + domain);
            if (finding != null) results.add(finding);
        }
        return results;
    }

    private TakeoverFinding probe(String subdomain) {
        try {
            HttpURLConnection conn = (HttpURLConnection)
                URI.create("http://" + subdomain).toURL().openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(false);
            conn.connect();

            int code = conn.getResponseCode();
            if (code >= 400) {
                String body = readBody(conn, code);
                for (Map.Entry<String, String> fp : FINGERPRINTS.entrySet()) {
                    if (body.contains(fp.getKey())) {
                        return new TakeoverFinding(subdomain, fp.getValue(), fp.getKey(), true);
                    }
                }
            }
        } catch (IOException | IllegalArgumentException ignored) {
            // Unreachable subdomain — skip
        }
        return null;
    }

    private String readBody(HttpURLConnection conn, int code) {
        try {
            InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (is == null) return "";
            byte[] bytes = is.readAllBytes();
            String body = new String(bytes);
            return body.length() > 2000 ? body.substring(0, 2000) : body;
        } catch (IOException ignored) {
            return "";
        }
    }

    public static String formatReport(List<TakeoverFinding> findings, String domain) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("       SUBDOMAIN TAKEOVER SCAN — ").append(domain).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        List<TakeoverFinding> vulnerable = findings.stream()
            .filter(TakeoverFinding::vulnerable).toList();

        if (vulnerable.isEmpty()) {
            sb.append("  ✓ No subdomain takeover vectors found.\n");
        } else {
            sb.append(String.format("  ⚠ VULNERABLE: %d subdomain(s) may be takeable!\n\n",
                vulnerable.size()));
            for (TakeoverFinding f : vulnerable) {
                sb.append(String.format("  Subdomain   : %s\n", f.subdomain()));
                sb.append(String.format("  Platform    : %s\n", f.platform()));
                sb.append(String.format("  Fingerprint : \"%s\"\n\n", f.fingerprint()));
            }
        }
        sb.append(String.format("  Checked %d subdomains total.\n", findings.size()));
        return sb.toString();
    }
}
