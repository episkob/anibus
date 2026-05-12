package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class CorsCheckerTest {

    @Test
    void detectsCriticalHighAndMediumCorsMisconfigurations() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", exchange -> {
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if ("null".equals(origin)) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "null");
            } else {
                exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
                exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
            }
            respond(exchange, 200, "ok");
        });
        server.createContext("/api", exchange -> {
            String origin = exchange.getRequestHeaders().getFirst("Origin");
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
            exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
            }
            respond(exchange, 200, "ok");
        });
        server.createContext("/api/v1", exchange -> {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "null");
            exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
            respond(exchange, 200, "ok");
        });
        server.createContext("/graphql", exchange -> {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            respond(exchange, 200, "ok");
        });
        server.createContext("/rest", exchange -> {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "https://trusted.example");
            respond(exchange, 200, "ok");
        });
        server.start();

        try {
            String targetUrl = "http://localhost:" + server.getAddress().getPort() + "/";
            CorsChecker checker = new CorsChecker();

            List<CorsChecker.CorsResult> results = checker.check(targetUrl);

            assertTrue(results.stream().anyMatch(r -> r.risk() == CorsChecker.CorsRisk.CRITICAL));
            assertTrue(results.stream().anyMatch(r -> r.risk() == CorsChecker.CorsRisk.HIGH));
            assertTrue(results.stream().anyMatch(r -> r.risk() == CorsChecker.CorsRisk.MEDIUM));

            String report = CorsChecker.formatReport(results, targetUrl);
            assertTrue(report.contains("CORS CHECK"));
            assertTrue(report.contains("misconfiguration"));
            assertTrue(report.contains(targetUrl));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void flagsPermissivePreflightInFinding() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
            }
            respond(exchange, 200, "ok");
        });
        server.start();

        try {
            String targetUrl = "http://localhost:" + server.getAddress().getPort() + "/";
            CorsChecker checker = new CorsChecker();
            List<CorsChecker.CorsResult> results = checker.check(targetUrl);

            assertTrue(results.stream().anyMatch(r ->
                    targetUrl.equals(r.url()) && r.finding().contains("Preflight allows cross-origin auth headers")));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void formatsEmptyCorsReport() {
        String report = CorsChecker.formatReport(List.of(), "http://example.test");
        assertTrue(report.contains("CORS CHECK"));
        assertTrue(report.contains("Could not reach target or no CORS headers present"));
    }

    private static void respond(HttpExchange exchange, int statusCode, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}