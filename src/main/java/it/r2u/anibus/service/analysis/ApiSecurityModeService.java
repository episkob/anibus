package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * API Security Mode:
 * - discovers OpenAPI/Swagger specs
 * - extracts declared endpoints
 * - probes each declared method/path and reports HTTP status
 */
public class ApiSecurityModeService {

    private static final int TIMEOUT_MS = 7000;

    private static final List<String> SPEC_PATHS = List.of(
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/api-docs",
        "/api/swagger.json"
    );

    private static final Pattern PATH_BLOCK = Pattern.compile(
        "\\\"(/[^\\\"]*)\\\"\\s*:\\s*\\{([\\s\\S]*?)\\n\\s*\\}",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern METHOD_PATTERN = Pattern.compile(
        "\\\"(get|post|put|delete|patch|head|options)\\\"\\s*:",
        Pattern.CASE_INSENSITIVE
    );

    public record EndpointProbe(
        String method,
        String path,
        int statusCode,
        String note
    ) {}

    public record ScanResult(
        String baseUrl,
        String specUrl,
        List<EndpointProbe> probes,
        List<String> errors
    ) {}

    public ScanResult scan(String baseUrl) {
        List<String> errors = new ArrayList<>();
        String normalizedBase = normalizeBase(baseUrl);

        String specUrl = null;
        String specBody = null;
        for (String suffix : SPEC_PATHS) {
            String candidate = normalizedBase + suffix;
            String body = fetch(candidate);
            if (body != null && body.contains("\"paths\"")) {
                specUrl = candidate;
                specBody = body;
                break;
            }
        }

        if (specUrl == null || specBody == null) {
            errors.add("OpenAPI/Swagger spec not found on common paths");
            return new ScanResult(normalizedBase, null, List.of(), errors);
        }

        Map<String, Set<String>> declared = extractDeclaredEndpoints(specBody);
        if (declared.isEmpty()) {
            errors.add("Spec found, but no declared endpoints parsed");
            return new ScanResult(normalizedBase, specUrl, List.of(), errors);
        }

        List<EndpointProbe> probes = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : declared.entrySet()) {
            String path = e.getKey();
            for (String method : e.getValue()) {
                int status = probe(normalizedBase, path, method);
                String note = classify(status);
                probes.add(new EndpointProbe(method, path, status, note));
            }
        }

        return new ScanResult(normalizedBase, specUrl, probes, errors);
    }

    private Map<String, Set<String>> extractDeclaredEndpoints(String specJson) {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        Matcher m = PATH_BLOCK.matcher(specJson);
        while (m.find()) {
            String path = m.group(1).trim();
            String block = m.group(2);
            Set<String> methods = new LinkedHashSet<>();
            Matcher mm = METHOD_PATTERN.matcher(block);
            while (mm.find()) {
                methods.add(mm.group(1).toUpperCase());
            }
            if (!methods.isEmpty()) {
                result.put(path, methods);
            }
        }
        return result;
    }

    private int probe(String baseUrl, String path, String method) {
        try {
            String url = path.startsWith("http://") || path.startsWith("https://")
                ? path
                : baseUrl + (path.startsWith("/") ? path : "/" + path);

            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod(method);
            conn.setRequestProperty("User-Agent", "Anibus-API-Security-Mode/1.0");
            conn.setRequestProperty("Accept", "application/json,*/*");
            conn.setInstanceFollowRedirects(false);

            if (requiresBody(method)) {
                conn.setDoOutput(true);
                byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", String.valueOf(body.length));
                conn.getOutputStream().write(body);
            }
            return conn.getResponseCode();
        } catch (IOException | IllegalArgumentException e) {
            return 0;
        }
    }

    private boolean requiresBody(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
    }

    private String classify(int status) {
        if (status == 0) return "No response / connection failed";
        if (status == 200) return "OK";
        if (status == 401 || status == 403) return "Protected endpoint (auth enforced)";
        if (status == 404) return "Declared in spec but not reachable";
        if (status >= 500) return "Server error while probing";
        return "HTTP " + status;
    }

    private String fetch(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json,*/*");
            int code = conn.getResponseCode();
            if (code < 200 || code >= 300) {
                return null;
            }
            return new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    private String normalizeBase(String baseUrl) {
        String b = baseUrl == null ? "" : baseUrl.trim();
        if (!b.startsWith("http://") && !b.startsWith("https://")) {
            b = "http://" + b;
        }
        return b.endsWith("/") ? b.substring(0, b.length() - 1) : b;
    }

    public static String formatReport(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== API SECURITY MODE: ").append(result.baseUrl()).append(" ===\n");
        if (result.specUrl() != null) {
            sb.append("  Spec detected: ").append(result.specUrl()).append("\n");
        }
        if (!result.errors().isEmpty()) {
            for (String err : result.errors()) {
                sb.append("  Error: ").append(err).append("\n");
            }
        }
        if (result.probes().isEmpty()) {
            return sb.toString();
        }

        long exposed = result.probes().stream()
            .filter(p -> p.statusCode() == 200)
            .count();

        sb.append("  Probed endpoints: ").append(result.probes().size()).append("\n");
        sb.append("  Publicly accessible (200): ").append(exposed).append("\n\n");

        for (EndpointProbe p : result.probes()) {
            sb.append("  [").append(p.statusCode() == 0 ? "ERR" : p.statusCode()).append("] ")
                .append(p.method()).append(" ").append(p.path())
                .append("  — ").append(p.note()).append("\n");
        }
        return sb.toString();
    }
}
