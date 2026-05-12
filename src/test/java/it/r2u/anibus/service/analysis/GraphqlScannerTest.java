package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class GraphqlScannerTest {

    @Test
    void detectsBatchQueryModeWhenEndpointAcceptsArrayPayload() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/graphql", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (body.startsWith("[")) {
                send(exchange, 200, "[{\"data\":{\"__typename\":\"Query\"}},{\"data\":{\"__typename\":\"Query\"}}]");
                return;
            }
            if (body.contains("query { health }")) {
                send(exchange, 200, "{\"data\":{\"health\":\"ok\"}}");
                return;
            }
            if (body.contains("mutation { createUser }")) {
                send(exchange, 200, "{\"data\":{\"createUser\":\"ok\"}}");
                return;
            }
            send(exchange, 200, "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"mutationType\":{\"name\":\"Mutation\"},\"types\":[{\"name\":\"Query\",\"kind\":\"OBJECT\",\"fields\":[{\"name\":\"health\",\"type\":{\"name\":\"String\",\"kind\":\"SCALAR\",\"ofType\":null}}]},{\"name\":\"Mutation\",\"kind\":\"OBJECT\",\"fields\":[{\"name\":\"createUser\",\"type\":{\"name\":\"String\",\"kind\":\"SCALAR\",\"ofType\":null}}]}]}}}");
        });
        server.start();

        try {
            GraphqlScanner scanner = new GraphqlScanner();
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            List<GraphqlScanner.GraphqlEndpoint> results = scanner.scan(baseUrl);

            assertFalse(results.isEmpty());
            GraphqlScanner.GraphqlEndpoint endpoint = results.getFirst();
            assertTrue(endpoint.introspectionEnabled());
            assertTrue(endpoint.batchQueryEnabled());
            assertTrue(endpoint.minimalQueryAccepted());
            assertTrue(endpoint.minimalMutationAccepted());

            String report = GraphqlScanner.formatReport(results, baseUrl);
            assertTrue(report.contains("Batch query mode ACCEPTED"));
            assertTrue(report.contains("Minimal schema-derived query ACCEPTED"));
        } finally {
            server.stop(0);
        }
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
