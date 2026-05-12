package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class XssDetectorTest {

    @Test
    void findsReflectedXssWhenServerEchoesPayload() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/echo", exchange -> {
            String q = queryParam(exchange.getRequestURI().getRawQuery(), "q");
            respond(exchange, 200, "<html><body>" + q + "</body></html>");
        });
        server.start();

        try {
            String targetUrl = "http://localhost:" + server.getAddress().getPort() + "/echo";
            XssDetector detector = new XssDetector();

            List<XssDetector.XssResult> results = detector.scan(targetUrl, List.of("q"), null);

            assertEquals(7, results.size());
            assertTrue(results.stream().allMatch(XssDetector.XssResult::reflected));

            String report = XssDetector.formatReport(results, targetUrl);
            assertTrue(report.contains("XSS SCAN"));
            assertTrue(report.contains("reflected XSS finding(s)"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsNoFindingsWhenPayloadIsNotReflected() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/safe", exchange -> respond(exchange, 200, "<html><body>safe</body></html>"));
        server.start();

        try {
            String targetUrl = "http://localhost:" + server.getAddress().getPort() + "/safe";
            XssDetector detector = new XssDetector();

            List<XssDetector.XssResult> results = detector.scan(targetUrl, List.of("q"), null);

            assertTrue(results.isEmpty());
            assertTrue(XssDetector.formatReport(results, targetUrl).contains("No reflected XSS found"));
        } finally {
            server.stop(0);
        }
    }

    private static String queryParam(String rawQuery, String key) {
        if (rawQuery == null || rawQuery.isBlank()) return "";
        for (String part : rawQuery.split("&")) {
            String[] kv = part.split("=", 2);
            if (kv.length > 0 && key.equals(kv[0])) {
                return kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "";
            }
        }
        return "";
    }

    private static void respond(HttpExchange exchange, int statusCode, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}