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
    private static final String TEST_AUTH_HEADER = "Bearer ANIBUS_TEST_TOKEN";

    private static final List<String> SPEC_PATHS = List.of(
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/api-docs",
        "/api/swagger.json"
    );

    private static final List<String> GRPC_PROBE_PATHS = List.of(
        "/grpc.health.v1.Health/Check",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
    );

    private static final List<String> OPENRPC_PROBE_PATHS = List.of(
        "/openrpc.json",
        "/rpc",
        "/api/rpc",
        "/jsonrpc"
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

    public record GrpcResult(
        boolean detected,
        boolean reflectionEnabled,
        boolean grpcWebEnabled,
        List<String> services,
        String evidence
    ) {
        public static GrpcResult notDetected() {
            return new GrpcResult(false, false, false, List.of(), "");
        }
    }

    public record OpenRpcResult(
        boolean detected,
        String specUrl,
        List<String> methods,
        String serverVersion
    ) {
        public static OpenRpcResult notDetected() {
            return new OpenRpcResult(false, null, List.of(), null);
        }
    }

    public record ScanResult(
        String baseUrl,
        String specUrl,
        List<EndpointProbe> probes,
        List<GraphqlScanner.GraphqlEndpoint> graphql,
        GrpcResult grpc,
        OpenRpcResult openRpc,
        List<String> errors
    ) {}

    public ScanResult scan(String baseUrl) {
        List<String> errors = new ArrayList<>();
        String normalizedBase = normalizeBase(baseUrl);

        // --- Phase 1: OpenAPI / REST ---
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

        List<EndpointProbe> probes = new ArrayList<>();
        if (specUrl == null || specBody == null) {
            errors.add("OpenAPI/Swagger spec not found on common paths");
        } else {
            Map<String, Set<String>> declared = extractDeclaredEndpoints(specBody);
            if (declared.isEmpty()) {
                errors.add("Spec found, but no declared endpoints parsed");
            } else {
                for (Map.Entry<String, Set<String>> e : declared.entrySet()) {
                    String path = e.getKey();
                    for (String method : e.getValue()) {
                        int status = probe(normalizedBase, path, method, null);
                        String note = classify(status);
                        probes.add(new EndpointProbe(method, path, status, note));

                        if ("GET".equals(method)) {
                            EndpointProbe rateLimitProbe = runRateLimitProbe(normalizedBase, path, method);
                            probes.add(rateLimitProbe);
                        }

                        int authStatus = probe(normalizedBase, path, method, TEST_AUTH_HEADER);
                        probes.add(new EndpointProbe(method + "+AUTH", path, authStatus,
                                classifyAuthDiff(status, authStatus)));

                        if ("GET".equals(method) && path.contains("{")) {
                            for (String fuzzedPath : fuzzIdPathVariants(path)) {
                                int fuzzStatus = probe(normalizedBase, fuzzedPath, method, null);
                                probes.add(new EndpointProbe(method + "+FUZZ", fuzzedPath, fuzzStatus,
                                        "ID fuzz probe: " + classify(fuzzStatus)));
                            }
                            // BOLA / IDOR: compare authenticated access to neighbour id
                            EndpointProbe bola = runBolaProbe(normalizedBase, path, method);
                            if (bola != null) probes.add(bola);
                        }

                        // Enum-style query parameter fuzz (sort/order/role/status)
                        if ("GET".equals(method)) {
                            probes.addAll(runEnumQueryFuzz(normalizedBase, path, method));
                        }
                    }
                }
            }
        }

        // --- Phase 2: GraphQL ---
        GraphqlScanner graphqlScanner = new GraphqlScanner();
        List<GraphqlScanner.GraphqlEndpoint> graphqlEndpoints = graphqlScanner.scan(normalizedBase);

        // --- Phase 3: gRPC-Web ---
        GrpcResult grpcResult = detectGrpc(normalizedBase);

        // --- Phase 4: OpenRPC / JSON-RPC 2.0 ---
        OpenRpcResult openRpcResult = detectOpenRpc(normalizedBase);

        return new ScanResult(normalizedBase, specUrl, probes, graphqlEndpoints, grpcResult, openRpcResult, errors);
    }

    private EndpointProbe runRateLimitProbe(String baseUrl, String path, String method) {
        int first429At = -1;
        int lastStatus = 0;
        for (int i = 1; i <= 20; i++) {
            lastStatus = probe(baseUrl, path, method, null);
            if (lastStatus == 429) {
                first429At = i;
                break;
            }
        }

        if (first429At > 0) {
            return new EndpointProbe(method + "+RATELIMIT", path, 429,
                    "Rate-limit triggered after " + first429At + " request(s)");
        }
        return new EndpointProbe(method + "+RATELIMIT", path, lastStatus,
                "Rate-limit check: no 429 within 20 request(s)");
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

    private int probe(String baseUrl, String path, String method, String authHeader) {
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
            if (authHeader != null && !authHeader.isBlank()) {
                conn.setRequestProperty("Authorization", authHeader);
            }

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

    private String classifyAuthDiff(int anonymousStatus, int authStatus) {
        if (anonymousStatus == 0 || authStatus == 0) {
            return "Auth diff check incomplete";
        }
        if (anonymousStatus == authStatus) {
            return "Auth diff: no change";
        }
        if (anonymousStatus == 200 && (authStatus == 401 || authStatus == 403)) {
            return "Auth diff: anonymous access looks broader than authenticated";
        }
        if ((anonymousStatus == 401 || anonymousStatus == 403) && authStatus == 200) {
            return "Auth diff: token changes access (expected for protected endpoints)";
        }
        return "Auth diff: status changed " + anonymousStatus + " -> " + authStatus;
    }

    private List<String> fuzzIdPathVariants(String path) {
        String normalized = path.replaceAll("\\{[^/}]+}", "1");
        List<String> variants = new ArrayList<>();
        variants.add(normalized);
        variants.add(normalized.replace("/1", "/999999"));
        return variants.stream().distinct().toList();
    }

    /**
     * BOLA / IDOR probe: requests two neighbour IDs with the test auth header.
     * If both return 200 (or the same non-error status), the endpoint likely
     * does not enforce ownership checks on the {id} parameter.
     */
    private EndpointProbe runBolaProbe(String baseUrl, String path, String method) {
        String pathA = path.replaceAll("\\{[^/}]+}", "1");
        String pathB = path.replaceAll("\\{[^/}]+}", "2");
        if (pathA.equals(pathB)) return null;
        int sa = probe(baseUrl, pathA, method, TEST_AUTH_HEADER);
        int sb = probe(baseUrl, pathB, method, TEST_AUTH_HEADER);
        if (sa == 0 || sb == 0) return null;
        boolean both200 = sa == 200 && sb == 200;
        boolean sameOK = sa == sb && sa >= 200 && sa < 300;
        if (both200 || sameOK) {
            return new EndpointProbe(method + "+BOLA", path, sa,
                "Possible BOLA/IDOR: id=1 → " + sa + ", id=2 → " + sb
                + " (ownership not enforced)");
        }
        return new EndpointProbe(method + "+BOLA", path, sa,
            "BOLA probe: id=1 → " + sa + ", id=2 → " + sb + " (different — appears protected)");
    }

    /**
     * Enum-style query fuzzing: probes common enum-like parameters with
     * suspicious values to detect injection / privilege escalation surface.
     */
    private List<EndpointProbe> runEnumQueryFuzz(String baseUrl, String path, String method) {
        List<EndpointProbe> out = new ArrayList<>();
        String[][] cases = {
            {"role",   "admin"},
            {"role",   "superuser"},
            {"status", "all"},
            {"sort",   "id;DROP"},
            {"order",  "desc'"},
            {"filter", "*"},
            {"debug",  "true"}
        };
        for (String[] kv : cases) {
            String injected = (path.contains("?") ? path + "&" : path + "?") + kv[0] + "=" + kv[1];
            int status = probe(baseUrl, injected, method, null);
            if (status == 200 || status == 500) {
                out.add(new EndpointProbe(method + "+ENUM", injected, status,
                    "Enum-fuzz " + kv[0] + "=" + kv[1] + " → " + classify(status)));
            }
        }
        return out;
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

    /** Retry spec-discovery GETs up to 3 times on transient network errors. */
    private static final it.r2u.anibus.network.RetryPolicy FETCH_RETRY = it.r2u.anibus.network.RetryPolicy.DEFAULT;

    private String fetch(String url) {
        try {
            return FETCH_RETRY.execute(() -> {
                try {
                    HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
                    conn.setConnectTimeout(TIMEOUT_MS);
                    conn.setReadTimeout(TIMEOUT_MS);
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("Accept", "application/json,*/*");
                    int code = conn.getResponseCode();
                    if (code < 200 || code >= 300) {
                        return null; // deterministic non-2xx — not retried
                    }
                    return new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                } catch (IllegalArgumentException e) {
                    return null; // invalid URL — not retried
                }
            });
        } catch (IOException e) {
            return null;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
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

    /**
     * Probe gRPC-Web endpoints. Sends a minimal 5-byte gRPC frame (compressed=0, length=0)
     * with Content-Type: application/grpc-web+proto and inspects response headers.
     */
    private GrpcResult detectGrpc(String baseUrl) {
        boolean detected = false;
        boolean reflectionEnabled = false;
        boolean grpcWebEnabled = false;
        List<String> services = new ArrayList<>();
        StringBuilder evidence = new StringBuilder();

        // Minimal gRPC frame: 1 compression byte (0) + 4 length bytes (0) = 5 bytes
        byte[] grpcFrame = {0x00, 0x00, 0x00, 0x00, 0x00};

        for (String path : GRPC_PROBE_PATHS) {
            try {
                String url = baseUrl + path;
                HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/grpc-web+proto");
                conn.setRequestProperty("X-Grpc-Web", "1");
                conn.setRequestProperty("Accept", "application/grpc-web+proto,*/*");
                conn.setRequestProperty("User-Agent", "Anibus-API-Security-Mode/1.0");
                conn.setInstanceFollowRedirects(false);
                conn.getOutputStream().write(grpcFrame);

                int status;
                try {
                    status = conn.getResponseCode();
                } catch (IOException e) {
                    continue;
                }

                String contentType = conn.getHeaderField("Content-Type");
                String grpcStatus  = conn.getHeaderField("Grpc-Status");
                String grpcEncoding = conn.getHeaderField("Grpc-Encoding");

                boolean isGrpc = (contentType != null && contentType.contains("grpc"))
                              || grpcStatus != null
                              || grpcEncoding != null
                              || status == 415; // Unsupported Media Type but server knows grpc

                if (isGrpc) {
                    detected = true;
                    if (contentType != null && contentType.contains("grpc-web")) {
                        grpcWebEnabled = true;
                    }
                    if (path.contains("Reflection") && status == 200) {
                        reflectionEnabled = true;
                    }
                    // Extract service name (first path segment)
                    String svcName = path.length() > 1 ? path.substring(1).split("/")[0] : path;
                    if (!services.contains(svcName)) {
                        services.add(svcName);
                    }
                    if (evidence.length() > 0) evidence.append("; ");
                    evidence.append(path).append(" → HTTP ").append(status);
                    if (grpcStatus != null) evidence.append(" [Grpc-Status: ").append(grpcStatus).append("]");
                    if (contentType != null) evidence.append(" [").append(contentType).append("]");
                }
            } catch (IOException | IllegalArgumentException ignored) {}
        }

        return new GrpcResult(detected, reflectionEnabled, grpcWebEnabled,
                              List.copyOf(services), evidence.toString());
    }

    /**
     * Probe for OpenRPC / JSON-RPC 2.0 schema endpoints.
     * First checks /openrpc.json via GET, then probes other paths via rpc.discover.
     */
    private OpenRpcResult detectOpenRpc(String baseUrl) {
        // 1. Try static OpenRPC spec file
        String specFileUrl = baseUrl + "/openrpc.json";
        String specBody = fetch(specFileUrl);
        if (specBody != null && (specBody.contains("\"openrpc\"") || specBody.contains("\"methods\""))) {
            List<String> methods = extractRpcMethods(specBody);
            String version = extractJsonStringValue(specBody, "openrpc");
            return new OpenRpcResult(true, specFileUrl, methods, version);
        }

        // 2. Try JSON-RPC rpc.discover on remaining probe paths
        String discoverPayload = "{\"jsonrpc\":\"2.0\",\"method\":\"rpc.discover\",\"params\":[],\"id\":1}";
        byte[] payloadBytes = discoverPayload.getBytes(StandardCharsets.UTF_8);

        for (String path : OPENRPC_PROBE_PATHS) {
            if ("/openrpc.json".equals(path)) continue; // already tried above as GET
            String url = baseUrl + path;
            try {
                HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(TIMEOUT_MS);
                conn.setReadTimeout(TIMEOUT_MS);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Accept", "application/json,*/*");
                conn.setRequestProperty("User-Agent", "Anibus-API-Security-Mode/1.0");
                conn.setInstanceFollowRedirects(false);
                conn.getOutputStream().write(payloadBytes);

                int status;
                try {
                    status = conn.getResponseCode();
                } catch (IOException e) {
                    continue;
                }
                if (status < 200 || status >= 300) continue;

                String responseBody;
                try {
                    responseBody = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                } catch (IOException e) {
                    continue;
                }
                if (responseBody.contains("\"openrpc\"") || responseBody.contains("\"methods\"")) {
                    List<String> methods = extractRpcMethods(responseBody);
                    String version = extractJsonStringValue(responseBody, "openrpc");
                    return new OpenRpcResult(true, url, methods, version);
                }
            } catch (IOException | IllegalArgumentException ignored) {}
        }

        return OpenRpcResult.notDetected();
    }

    /** Extract "name" values from a JSON array of method descriptors (up to 30). */
    private List<String> extractRpcMethods(String json) {
        List<String> methods = new ArrayList<>();
        Pattern p = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        while (m.find() && methods.size() < 30) {
            methods.add(m.group(1));
        }
        return List.copyOf(methods);
    }

    /** Extract a simple string value for the given JSON key. */
    private String extractJsonStringValue(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    public static String formatReport(ScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== API SECURITY SCAN — UNIFIED REPORT ===\n");
        sb.append("  Target: ").append(result.baseUrl()).append("\n\n");

        // ── OpenAPI / REST ────────────────────────────────────────────────────
        sb.append("┌─ OpenAPI / REST ─────────────────────────────────────────────\n");
        if (result.specUrl() != null) {
            sb.append("│  Spec: ").append(result.specUrl()).append("\n");
            long exposed = result.probes().stream().filter(p -> p.statusCode() == 200).count();
            sb.append("│  Endpoints probed: ").append(result.probes().size())
              .append("  │  Accessible (200): ").append(exposed).append("\n");
            for (EndpointProbe p : result.probes()) {
                sb.append("│    [").append(p.statusCode() == 0 ? "ERR" : p.statusCode()).append("] ")
                  .append(p.method()).append(" ").append(p.path())
                  .append("  — ").append(p.note()).append("\n");
            }
        } else {
            sb.append("│  No OpenAPI/Swagger spec detected\n");
        }
        sb.append("└─────────────────────────────────────────────────────────────\n\n");

        // ── GraphQL ───────────────────────────────────────────────────────────
        sb.append("┌─ GraphQL ────────────────────────────────────────────────────\n");
        if (result.graphql().isEmpty()) {
            sb.append("│  No GraphQL endpoints detected\n");
        } else {
            for (GraphqlScanner.GraphqlEndpoint ep : result.graphql()) {
                sb.append("│  Endpoint: ").append(ep.url()).append("\n");
                sb.append("│    Introspection : ").append(ep.introspectionEnabled() ? "ENABLED ⚠" : "disabled").append("\n");
                sb.append("│    Batch queries  : ").append(ep.batchQueryEnabled() ? "ENABLED ⚠" : "not detected").append("\n");
                sb.append("│    Depth limit    : ").append(ep.depthLimitMissing() ? "MISSING ⚠" : "enforced").append("\n");
                if (!ep.typeNames().isEmpty()) {
                    sb.append("│    Schema types   : ").append(ep.typeNames()).append("\n");
                }
                if (!ep.queryFields().isEmpty()) {
                    List<String> names = ep.queryFields().stream()
                            .map(GraphqlScanner.GraphqlField::name).toList();
                    sb.append("│    Query fields   : ").append(names).append("\n");
                }
                if (!ep.mutationFields().isEmpty()) {
                    List<String> names = ep.mutationFields().stream()
                            .map(GraphqlScanner.GraphqlField::name).toList();
                    sb.append("│    Mutation fields: ").append(names).append("\n");
                }
                if (ep.finding() != null && !ep.finding().isBlank()) {
                    sb.append("│    Finding: ").append(ep.finding()).append("\n");
                }
            }
        }
        sb.append("└─────────────────────────────────────────────────────────────\n\n");

        // ── gRPC / gRPC-Web ───────────────────────────────────────────────────
        sb.append("┌─ gRPC / gRPC-Web ────────────────────────────────────────────\n");
        GrpcResult grpc = result.grpc();
        if (grpc.detected()) {
            sb.append("│  gRPC service detected\n");
            sb.append("│    gRPC-Web protocol : ").append(grpc.grpcWebEnabled() ? "YES" : "no").append("\n");
            sb.append("│    Server Reflection : ");
            if (grpc.reflectionEnabled()) {
                sb.append("ENABLED ⚠  (full service/method list exposed)\n");
            } else {
                sb.append("disabled / not confirmed\n");
            }
            if (!grpc.services().isEmpty()) {
                sb.append("│    Detected services : ").append(grpc.services()).append("\n");
            }
            if (!grpc.evidence().isBlank()) {
                sb.append("│    Evidence: ").append(grpc.evidence()).append("\n");
            }
        } else {
            sb.append("│  No gRPC endpoints detected\n");
        }
        sb.append("└─────────────────────────────────────────────────────────────\n\n");

        // ── OpenRPC / JSON-RPC 2.0 ────────────────────────────────────────────
        sb.append("┌─ OpenRPC / JSON-RPC 2.0 ─────────────────────────────────────\n");
        OpenRpcResult rpc = result.openRpc();
        if (rpc.detected()) {
            sb.append("│  OpenRPC schema detected: ").append(rpc.specUrl()).append("\n");
            if (rpc.serverVersion() != null) {
                sb.append("│    OpenRPC version: ").append(rpc.serverVersion()).append("\n");
            }
            if (!rpc.methods().isEmpty()) {
                sb.append("│    Exposed methods: ").append(rpc.methods()).append("\n");
            }
        } else {
            sb.append("│  No OpenRPC/JSON-RPC schema detected\n");
        }
        sb.append("└─────────────────────────────────────────────────────────────\n");

        // ── Errors ────────────────────────────────────────────────────────────
        if (!result.errors().isEmpty()) {
            sb.append("\n  Scan notes:\n");
            for (String err : result.errors()) {
                sb.append("    - ").append(err).append("\n");
            }
        }

        return sb.toString();
    }
}
