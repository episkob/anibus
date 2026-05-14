package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive recon utility.
 *
 * Collects metadata only (status, headers, title, robots, sitemap, favicon hash)
 * and does not send active exploit payloads.
 */
public class PassiveReconService {

    public record PassiveReconResult(
        String targetUrl,
        int statusCode,
        String finalUrl,
        String pageTitle,
        Map<String, String> headers,
        boolean robotsFound,
        boolean sitemapFound,
        String faviconSha256,
        List<CookieFlagsAuditor.CookieFinding> cookieFindings,
        CsrfTokenExtractor.CsrfToken csrfToken,
        List<String> notes
    ) {}

    private static final Pattern TITLE_PATTERN =
        Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private final HttpClient client;

    public PassiveReconService() {
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(7))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    public PassiveReconResult scan(String targetUrl) {
        List<String> notes = new ArrayList<>();
        Map<String, String> headers = new LinkedHashMap<>();
        List<CookieFlagsAuditor.CookieFinding> cookieFindings = List.of();
        CsrfTokenExtractor.CsrfToken csrfToken = null;
        int statusCode = -1;
        String finalUrl = targetUrl;
        String title = "n/a";
        boolean robots = false;
        boolean sitemap = false;
        String faviconHash = "n/a";

        try {
            URI baseUri = URI.create(targetUrl);
            HttpResponse<String> page = sendGet(baseUri);
            statusCode = page.statusCode();
            finalUrl = page.uri().toString();

            page.headers().map().forEach((k, v) -> {
                if (!v.isEmpty()) {
                    headers.put(k, v.get(0));
                }
            });

            boolean httpsContext = "https".equalsIgnoreCase(page.uri().getScheme());
            cookieFindings = CookieFlagsAuditor.audit(
                page.headers().allValues("set-cookie"), httpsContext);

            title = extractTitle(page.body());
            csrfToken = CsrfTokenExtractor.extract(page.body());
            robots = exists(buildSiblingUri(baseUri, "/robots.txt"));
            sitemap = exists(buildSiblingUri(baseUri, "/sitemap.xml"));
            faviconHash = fetchFaviconHash(baseUri, notes);
        } catch (IOException | InterruptedException | IllegalArgumentException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            notes.add("Probe error: " + e.getMessage());
        }

        return new PassiveReconResult(
            targetUrl,
            statusCode,
            finalUrl,
            title,
            headers,
            robots,
            sitemap,
            faviconHash,
            cookieFindings,
            csrfToken,
            notes
        );
    }

    private HttpResponse<String> sendGet(URI uri) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(10))
            .header("User-Agent", "Anibus/2.0 PassiveRecon")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .GET()
            .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private boolean exists(URI uri) {
        try {
            HttpRequest head = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(6))
                .header("User-Agent", "Anibus/2.0 PassiveRecon")
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .build();
            HttpResponse<Void> response = client.send(head, HttpResponse.BodyHandlers.discarding());
            return response.statusCode() >= 200 && response.statusCode() < 400;
        } catch (IOException | InterruptedException | IllegalArgumentException ioe) {
            if (ioe instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                return false;
            }
            try {
                HttpRequest get = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "Anibus/2.0 PassiveRecon")
                    .GET()
                    .build();
                HttpResponse<Void> response = client.send(get, HttpResponse.BodyHandlers.discarding());
                return response.statusCode() >= 200 && response.statusCode() < 400;
            } catch (IOException | InterruptedException | IllegalArgumentException retryIoe) {
                if (retryIoe instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                return false;
            }
        }
    }

    private String fetchFaviconHash(URI baseUri, List<String> notes) {
        try {
            URI faviconUri = buildSiblingUri(baseUri, "/favicon.ico");
            HttpRequest request = HttpRequest.newBuilder(faviconUri)
                .timeout(Duration.ofSeconds(8))
                .header("User-Agent", "Anibus/2.0 PassiveRecon")
                .GET()
                .build();
            HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() < 200 || response.statusCode() >= 400 || response.body() == null) {
                return "n/a";
            }
            return sha256(response.body());
        } catch (IOException | InterruptedException | IllegalArgumentException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            notes.add("Favicon hash skipped: " + e.getMessage());
            return "n/a";
        }
    }

    private URI buildSiblingUri(URI baseUri, String path) {
        String scheme = baseUri.getScheme() == null ? "https" : baseUri.getScheme();
        String host = baseUri.getHost();
        int port = baseUri.getPort();
        String authority = (port > 0) ? host + ":" + port : host;
        return URI.create(scheme + "://" + authority + path);
    }

    private String extractTitle(String html) {
        if (html == null || html.isBlank()) {
            return "n/a";
        }
        Matcher matcher = TITLE_PATTERN.matcher(html);
        if (!matcher.find()) {
            return "n/a";
        }
        return matcher.group(1).replaceAll("\\s+", " ").trim();
    }

    private String sha256(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(bytes);
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format(Locale.ROOT, "%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return "n/a";
        }
    }

    public static String formatReport(PassiveReconResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("      PASSIVE RECON — ").append(result.targetUrl()).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");
        sb.append("  Final URL : ").append(result.finalUrl()).append("\n");
        sb.append("  Status    : ").append(result.statusCode()).append("\n");
        sb.append("  Title     : ").append(result.pageTitle()).append("\n");
        sb.append("  robots.txt: ").append(result.robotsFound() ? "✓ found" : "✗ not found").append("\n");
        sb.append("  sitemap   : ").append(result.sitemapFound() ? "✓ found" : "✗ not found").append("\n");
        sb.append("  favicon   : ").append(result.faviconSha256()).append("\n");

        if (!result.headers().isEmpty()) {
            sb.append("\n  Headers:\n");
            for (Map.Entry<String, String> entry : result.headers().entrySet()) {
                sb.append("    • ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
        }

        if (result.cookieFindings() != null && !result.cookieFindings().isEmpty()) {
            sb.append("\n  Cookies (").append(result.cookieFindings().size()).append("):\n");
            for (CookieFlagsAuditor.CookieFinding cf : result.cookieFindings()) {
                sb.append("    • [").append(cf.severity()).append("] ").append(cf.name())
                  .append("  Secure=").append(cf.secure())
                  .append(" HttpOnly=").append(cf.httpOnly())
                  .append(" SameSite=").append(cf.sameSite()).append("\n");
                for (String issue : cf.issues()) {
                    sb.append("        - ").append(issue).append("\n");
                }
            }
        }

        if (result.csrfToken() != null) {
            CsrfTokenExtractor.CsrfToken t = result.csrfToken();
            sb.append("\n  CSRF token detected:\n");
            sb.append("    Name   : ").append(t.tokenName()).append("\n");
            sb.append("    Source : ").append(t.source()).append("\n");
            if (t.headerName() != null) {
                sb.append("    Header : ").append(t.headerName()).append("\n");
            }
            sb.append("    Value  : ").append(maskToken(t.tokenValue())).append("\n");
        }

        if (!result.notes().isEmpty()) {
            sb.append("\n  Notes:\n");
            for (String note : result.notes()) {
                sb.append("    • ").append(note).append("\n");
            }
        }
        return sb.toString();
    }

    private static String maskToken(String value) {
        if (value == null || value.isBlank()) return "(empty)";
        if (value.length() <= 8) return "***";
        return value.substring(0, 4) + "…" + value.substring(value.length() - 4)
            + " (" + value.length() + " chars)";
    }
}
