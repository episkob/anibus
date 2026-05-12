package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GraphQL introspection scanner.
 * Probes common GraphQL endpoints and fires an introspection query.
 * Parses the response to extract type names, query/mutation fields,
 * and flags if introspection is enabled in production (a common misconfiguration).
 */
public class GraphqlScanner {

    private static final int TIMEOUT = 8000;

    private static final String INTROSPECTION_QUERY = """
        {"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}"}
        """.strip();

    private static final String BATCH_PROBE_QUERY = """
        [{"query":"{__typename}"},{"query":"{__typename}"}]
        """.strip();

    private static final List<String> GRAPHQL_PATHS = List.of(
        "/graphql", "/graphql/v1", "/graphql/v2",
        "/api/graphql", "/api/v1/graphql", "/api/v2/graphql",
        "/gql", "/query", "/api/query",
        "/v1/graphql", "/v2/graphql"
    );

    public record GraphqlField(String name, String typeName) {}

    public record GraphqlEndpoint(
        String url,
        boolean introspectionEnabled,
        boolean batchQueryEnabled,
        boolean minimalQueryAccepted,
        boolean minimalMutationAccepted,
        List<String> typeNames,
        List<GraphqlField> queryFields,
        List<GraphqlField> mutationFields,
        String finding
    ) {}

    /**
     * Scans the base URL for GraphQL endpoints with introspection enabled.
     *
     * @param baseUrl Base URL (e.g. "https://example.com")
     * @return List of discovered GraphQL endpoints
     */
    public List<GraphqlEndpoint> scan(String baseUrl) {
        List<GraphqlEndpoint> results = new ArrayList<>();
        if (baseUrl == null || baseUrl.isBlank()) return results;

        String base = baseUrl.replaceAll("/$", "");
        for (String path : GRAPHQL_PATHS) {
            GraphqlEndpoint ep = probe(base + path);
            if (ep != null) results.add(ep);
        }
        return results;
    }

    private GraphqlEndpoint probe(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");

            byte[] body = INTROSPECTION_QUERY.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(body.length));
            conn.getOutputStream().write(body);

            int status = conn.getResponseCode();
            if (status < 200 || status >= 300) return null;

            String response = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            conn.disconnect();

            if (!response.contains("__schema") && !response.contains("queryType")) return null;

            boolean introspectionEnabled = response.contains("__schema") || response.contains("queryType");
            boolean batchQueryEnabled = supportsBatchQuery(url);
            List<String>        typeNames     = extractTypeNames(response);
            List<GraphqlField>  queryFields   = extractFields(response, "Query");
            List<GraphqlField>  mutationFields = extractFields(response, "Mutation");
            boolean minimalQueryAccepted = probeMinimalOperation(url, buildMinimalQuery(queryFields));
            boolean minimalMutationAccepted = probeMinimalOperation(url, buildMinimalMutation(mutationFields));

            String finding = introspectionEnabled
                ? "[HIGH] GraphQL introspection is ENABLED at " + url +
                  " — exposes full schema (" + typeNames.size() + " type(s), " +
                  queryFields.size() + " query field(s), " + mutationFields.size() + " mutation(s))"
                : "";

            if (batchQueryEnabled) {
                finding += " [MEDIUM] Batch GraphQL queries are accepted.";
            }
            if (minimalQueryAccepted) {
                finding += " [INFO] Minimal query generated from schema was accepted.";
            }
            if (minimalMutationAccepted) {
                finding += " [INFO] Minimal mutation generated from schema was accepted.";
            }

            return new GraphqlEndpoint(url, introspectionEnabled, batchQueryEnabled,
                minimalQueryAccepted, minimalMutationAccepted, typeNames,
                queryFields, mutationFields, finding);

        } catch (IOException | IllegalArgumentException ignored) {
            return null;
        }
    }

    private boolean supportsBatchQuery(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");

            byte[] body = BATCH_PROBE_QUERY.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(body.length));
            conn.getOutputStream().write(body);

            int status = conn.getResponseCode();
            if (status < 200 || status >= 300) {
                return false;
            }

            String response = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            return response.startsWith("[") && response.contains("__typename");
        } catch (IOException | IllegalArgumentException ignored) {
            return false;
        }
    }

    private boolean probeMinimalOperation(String url, String operation) {
        if (operation == null || operation.isBlank()) {
            return false;
        }
        String escapedOperation = operation.replace("\\", "\\\\").replace("\"", "\\\"");
        String payload = "{\"query\":\"" + escapedOperation + "\"}";

        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");

            byte[] body = payload.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(body.length));
            conn.getOutputStream().write(body);

            int status = conn.getResponseCode();
            if (status < 200 || status >= 300) {
                return false;
            }

            String response = new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return response.contains("\"data\"");
        } catch (IOException | IllegalArgumentException ignored) {
            return false;
        }
    }

    private String buildMinimalQuery(List<GraphqlField> queryFields) {
        if (queryFields == null || queryFields.isEmpty()) {
            return null;
        }
        return "query { " + queryFields.getFirst().name() + " }";
    }

    private String buildMinimalMutation(List<GraphqlField> mutationFields) {
        if (mutationFields == null || mutationFields.isEmpty()) {
            return null;
        }
        return "mutation { " + mutationFields.getFirst().name() + " }";
    }

    private List<String> extractTypeNames(String json) {
        List<String> names = new ArrayList<>();
        Matcher m = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        while (m.find()) {
            String name = m.group(1);
            if (!name.startsWith("__") && !names.contains(name)) names.add(name);
        }
        return names;
    }

    private List<GraphqlField> extractFields(String json, String typeName) {
        List<GraphqlField> fields = new ArrayList<>();
        // Find the block for the given type and extract field names
        int idx = json.indexOf("\"name\":\"" + typeName + "\"");
        if (idx < 0) return fields;
        int blockEnd = json.indexOf("\"kind\":\"OBJECT\"", idx + typeName.length());
        String block = (blockEnd > idx) ? json.substring(idx, blockEnd) : json.substring(idx, Math.min(idx + 2000, json.length()));

        Matcher m = Pattern.compile("\"name\"\\s*:\\s*\"([^\"_][^\"]+)\"").matcher(block);
        while (m.find() && fields.size() < 30) {
            String name = m.group(1);
            if (!name.equals(typeName)) fields.add(new GraphqlField(name, ""));
        }
        return fields;
    }

    public static String formatReport(List<GraphqlEndpoint> results, String baseUrl) {
        StringBuilder sb = new StringBuilder("=== GRAPHQL INTROSPECTION SCAN: ")
            .append(baseUrl).append(" ===\n");

        if (results == null || results.isEmpty()) {
            sb.append("  No GraphQL endpoints found.\n");
            return sb.toString();
        }

        for (GraphqlEndpoint ep : results) {
            sb.append("\n  URL: ").append(ep.url()).append("\n");
            if (!ep.introspectionEnabled()) {
                sb.append("    Introspection disabled.\n");
                continue;
            }
            sb.append("    [HIGH] Introspection ENABLED\n");
            if (ep.batchQueryEnabled()) {
                sb.append("    [MEDIUM] Batch query mode ACCEPTED\n");
            }
            if (ep.minimalQueryAccepted()) {
                sb.append("    [INFO] Minimal schema-derived query ACCEPTED\n");
            }
            if (ep.minimalMutationAccepted()) {
                sb.append("    [INFO] Minimal schema-derived mutation ACCEPTED\n");
            }
            if (!ep.typeNames().isEmpty()) {
                sb.append("    Types (").append(ep.typeNames().size()).append("): ")
                  .append(String.join(", ", ep.typeNames().subList(0, Math.min(15, ep.typeNames().size()))))
                  .append(ep.typeNames().size() > 15 ? "…" : "").append("\n");
            }
            if (!ep.queryFields().isEmpty()) {
                sb.append("    Queries: ")
                  .append(ep.queryFields().stream().map(GraphqlField::name).limit(10)
                      .reduce((a, b) -> a + ", " + b).orElse(""))
                  .append("\n");
            }
            if (!ep.mutationFields().isEmpty()) {
                sb.append("    Mutations: ")
                  .append(ep.mutationFields().stream().map(GraphqlField::name).limit(10)
                      .reduce((a, b) -> a + ", " + b).orElse(""))
                  .append("\n");
            }
        }
        return sb.toString();
    }
}
