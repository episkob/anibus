package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class ApiSecurityModeServiceTest {

    @Test
    void discoversOpenApiAndProbesDeclaredEndpoints() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/openapi.json", this::handleSpec);
        server.createContext("/pets", exchange -> send(exchange, 200, "[]"));
        server.createContext("/admin", exchange -> send(exchange, 403, "forbidden"));
        server.start();

        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            ApiSecurityModeService service = new ApiSecurityModeService();

            ApiSecurityModeService.ScanResult result = service.scan(baseUrl);

            assertTrue(result.specUrl() != null && result.specUrl().endsWith("/openapi.json"));
            assertFalse(result.probes().isEmpty());

            var petsGet = result.probes().stream()
                .filter(p -> "GET".equals(p.method()) && "/pets".equals(p.path()))
                .findFirst()
                .orElseThrow();
            assertEquals(200, petsGet.statusCode());

            var adminGet = result.probes().stream()
                .filter(p -> "GET".equals(p.method()) && "/admin".equals(p.path()))
                .findFirst()
                .orElseThrow();
            assertEquals(403, adminGet.statusCode());
        } finally {
            server.stop(0);
        }
    }

    private void handleSpec(HttpExchange exchange) throws IOException {
        String spec = """
            {
              "openapi": "3.0.0",
              "paths": {
                "/pets": {
                  "get": {"summary": "List pets"}
                },
                "/admin": {
                  "get": {"summary": "Admin"}
                }
              }
            }
            """;
        send(exchange, 200, spec);
    }

    private void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
