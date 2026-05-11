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

class JavaScriptSecurityAnalyzerAuthCrawlingTest {

    @Test
    void usesLoginAndSessionCookieForProtectedJsCrawl() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/login", this::handleLogin);
        server.createContext("/", this::handleHome);
        server.createContext("/js/app.js", this::handleProtectedJs);
        server.start();

        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            JavaScriptSecurityAnalyzer analyzer = new JavaScriptSecurityAnalyzer();

            JavaScriptSecurityAnalyzer.CrawlAuthConfig auth =
                new JavaScriptSecurityAnalyzer.CrawlAuthConfig(
                    baseUrl + "/login",
                    "admin",
                    "secret",
                    "username",
                    "password",
                    null,
                    null,
                    null
                );

            var withoutAuth = analyzer.analyzeTarget(
                baseUrl,
                JavaScriptSecurityAnalyzer.AnalysisDepth.BASIC
            );
            assertTrue(withoutAuth.getEndpoints().isEmpty(), "Expected no endpoints without auth session");

            var withAuth = analyzer.analyzeTarget(
                baseUrl,
                JavaScriptSecurityAnalyzer.AnalysisDepth.BASIC,
                auth
            );

            assertFalse(withAuth.getEndpoints().isEmpty(), "Expected protected JS to be analyzed after login");
            assertTrue(withAuth.getEndpoints().stream().anyMatch(ep -> "/api/secure".equals(ep.getUrl())));
        } finally {
            server.stop(0);
        }
    }

    private void handleLogin(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            send(exchange, 405, "Method Not Allowed");
            return;
        }

        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        if (body.contains("username=admin") && body.contains("password=secret")) {
            exchange.getResponseHeaders().add("Set-Cookie", "SESSION=ok; Path=/");
            send(exchange, 200, "OK");
            return;
        }

        send(exchange, 401, "Unauthorized");
    }

    private void handleHome(HttpExchange exchange) throws IOException {
        if ("HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
            try (exchange) {
                exchange.sendResponseHeaders(200, -1);
            }
            return;
        }

        if (!hasSession(exchange)) {
            send(exchange, 401, "Unauthorized");
            return;
        }

        String html = "<html><head><script src=\"/js/app.js\"></script></head><body>ok</body></html>";
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
        send(exchange, 200, html);
    }

    private void handleProtectedJs(HttpExchange exchange) throws IOException {
        if ("HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
            try (exchange) {
                exchange.sendResponseHeaders(200, -1);
            }
            return;
        }

        if (!hasSession(exchange)) {
            send(exchange, 401, "Unauthorized");
            return;
        }

        String js = "fetch('/api/secure')";
        exchange.getResponseHeaders().add("Content-Type", "application/javascript");
        send(exchange, 200, js);
    }

    private boolean hasSession(HttpExchange exchange) {
        List<String> cookieHeaders = exchange.getRequestHeaders().get("Cookie");
        if (cookieHeaders == null) {
            return false;
        }
        return cookieHeaders.stream().anyMatch(v -> v.contains("SESSION=ok"));
    }

    private void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
