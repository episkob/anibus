package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import it.r2u.anibus.model.EndpointInfo;

class SQLInjectionAnalyzerTest {

    @Test
    void loadsPayloadCategoriesFromResources() {
        SQLInjectionAnalyzer analyzer = new SQLInjectionAnalyzer();

        // If resource loading fails, analyzer falls back to 4 hardcoded payloads.
        assertTrue(analyzer.getPayloadCount() > 4,
                "Expected payloads from resource files, not only fallback defaults");
    }

    @Test
    void loadsCmsProfilesFromResources() {
        SQLInjectionAnalyzer analyzer = new SQLInjectionAnalyzer();

        var cmsTypes = analyzer.getSupportedCmsTypes();
        assertTrue(cmsTypes.contains("WordPress"));
        assertTrue(cmsTypes.contains("Generic"));
        assertTrue(cmsTypes.size() >= 5);
    }

    @Test
    void generatesCmsEndpointsForWordPress() {
        SQLInjectionAnalyzer analyzer = new SQLInjectionAnalyzer();

        List<EndpointInfo> endpoints = analyzer.generateCmsEndpoints("WordPress", "https://example.com");

        assertFalse(endpoints.isEmpty());
        assertTrue(endpoints.stream().allMatch(e -> e.getUrl() != null && !e.getUrl().isBlank()));
        assertTrue(endpoints.stream().anyMatch(e -> e.getContext() != null && e.getContext().contains("WordPress")));
    }

    @Test
    void discoversNestedFormEndpointsWithoutJsInput() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", exchange -> {
            try (HttpExchange ex = exchange) {
                respond(ex, 200, "<html><body><a href='/account'>Account</a></body></html>");
            }
        });
        server.createContext("/account", exchange -> {
            try (HttpExchange ex = exchange) {
                ex.getRequestURI();
                respond(ex, 200,
                        "<html><body><form action='/account/update' method='post'>"
                                + "<input name='email'/></form></body></html>");
            }
        });
        server.createContext("/account/update", exchange -> {
            try (HttpExchange ex = exchange) {
                String method = ex.getRequestMethod();
                String body = new String(ex.getRequestBody().readAllBytes());
                if ("POST".equalsIgnoreCase(method) && body.contains("'")) {
                    respond(ex, 500, "SQL syntax error near email");
                } else {
                    respond(ex, 200, "OK");
                }
            }
        });
        server.start();

        try {
            int port = server.getAddress().getPort();
            String baseUrl = "http://localhost:" + port + "/";
            SQLInjectionAnalyzer analyzer = new SQLInjectionAnalyzer();

            List<EndpointInfo> endpoints = analyzer.discoverInjectionTargets(baseUrl, null);

            assertTrue(endpoints.stream().anyMatch(ep -> ep.getUrl().endsWith("/account/update")
                    && "POST".equalsIgnoreCase(ep.getHttpMethod())));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void detectsBooleanBasedBlindByStatusDifference() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/bool", exchange -> {
            String q = exchange.getRequestURI().getRawQuery();
            if (q != null && q.contains("1%27%3D%271")) {
                respond(exchange, 200, "ok-true");
            } else if (q != null && q.contains("1%27%3D%272")) {
                respond(exchange, 403, "blocked-false");
            } else {
                respond(exchange, 200, "normal");
            }
        });
        server.start();

        try {
            SQLInjectionAnalyzer analyzer = new SQLInjectionAnalyzer();
            String endpointUrl = "http://localhost:" + server.getAddress().getPort() + "/bool?id=";
            EndpointInfo endpoint = new EndpointInfo(
                    endpointUrl,
                    "http://localhost:" + server.getAddress().getPort(),
                    "/bool",
                    "GET",
                    List.of("id"),
                    java.util.Map.of(),
                    "test",
                    false);

            Method testPayload = SQLInjectionAnalyzer.class.getDeclaredMethod(
                    "testPayload", String.class, EndpointInfo.class, String.class);
            testPayload.setAccessible(true);

            SQLInjectionAnalyzer.InjectionResult result =
                    (SQLInjectionAnalyzer.InjectionResult) testPayload.invoke(analyzer, endpointUrl, endpoint, "' OR '1'='1");

            assertTrue(result != null && result.isVulnerable());
            assertTrue(result.getEvidence().stream().anyMatch(e -> e.contains("Boolean-based blind difference")));
        } finally {
            server.stop(0);
        }
    }

    private static void respond(HttpExchange exchange, int statusCode, String body) throws IOException {
        byte[] bytes = body.getBytes();
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}
