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

class SqlMetadataExtractorTest {

    @Test
    void extractsVersionAndTablesFromDelimitedReflection() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/vuln", exchange -> {
            String q = queryParam(exchange.getRequestURI().getRawQuery(), "q");

            if (q.contains("ORDER BY 4")) {
                respond(exchange, 500, "SQL error");
            } else if (q.contains("version()")) {
                respond(exchange, 200, "prefix ANIBUS~8.0.34ANIBUS~ suffix");
            } else if (q.contains("table_name")) {
                respond(exchange, 200, "ANIBUS~usersANIBUS~ANIBUS~ordersANIBUS~");
            } else {
                respond(exchange, 200, "ok");
            }
        });
        server.start();

        try {
            String baseUrl = "http://localhost:" + server.getAddress().getPort() + "/vuln";
            SQLInjectionAnalyzer.InjectionResult vuln = new SQLInjectionAnalyzer.InjectionResult(
                    "payload",
                    baseUrl,
                    "GET",
                    200,
                    0,
                    "MySQL",
                    List.of("confirmed"),
                    "");

            SqlMetadataExtractor extractor = new SqlMetadataExtractor();
            SqlMetadataExtractor.MetadataResult result = extractor.extract(vuln);

            assertEquals("MySQL", result.dbType());
            assertEquals(3, result.columnCount());
            assertEquals("8.0.34", result.dbVersion());
            assertEquals(List.of("users", "orders"), result.tables());
            assertTrue(result.rawFindings().stream().anyMatch(s -> s.contains("Column count probe: 3")));
            assertTrue(result.rawFindings().stream().anyMatch(s -> s.contains("Version: 8.0.34")));
            assertTrue(result.rawFindings().stream().anyMatch(s -> s.contains("Tables found: users, orders")));

            String report = SqlMetadataExtractor.formatReport(result);
            assertTrue(report.contains("SQL METADATA EXTRACTION"));
            assertTrue(report.contains("Tables extracted (2)"));
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