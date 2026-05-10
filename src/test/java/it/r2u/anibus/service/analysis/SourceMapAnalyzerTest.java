package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class SourceMapAnalyzerTest {

    @Test
    void analyzesSourceMapFromJsComment() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        try {
            server.createContext("/app.js", ex -> respond(ex,
                    "console.log('x');\n//# sourceMappingURL=app.js.map",
                    200,
                    "application/javascript"));
            server.createContext("/app.js.map", ex -> respond(ex,
                    "{\"version\":3,\"file\":\"app.js\",\"sources\":[\"src/a.js\"],\"sourcesContent\":[\"const x=1;\"]}",
                    200,
                    "application/json"));
            server.start();

            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            SourceMapAnalyzer analyzer = new SourceMapAnalyzer();
            SourceMapAnalyzer.SourceMapResult result = analyzer.analyzeFromJsUrl(base + "/app.js");

            assertTrue(result.ok());
            assertEquals(3, result.version());
            assertEquals("app.js", result.file());
            assertEquals(1, result.sources().size());
            assertEquals("src/a.js", result.sources().get(0).path());
            assertTrue(result.sources().get(0).hasContent());
            assertTrue(SourceMapAnalyzer.formatReport(result).contains("Source Map Analysis"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsErrorOnMissingSourceMap() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        try {
            server.createContext("/main.js", ex -> respond(ex, "console.log('x');", 200, "application/javascript"));
            server.createContext("/main.js.map", ex -> respond(ex, "not found", 404, "text/plain"));
            server.start();

            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            SourceMapAnalyzer analyzer = new SourceMapAnalyzer();
            SourceMapAnalyzer.SourceMapResult result = analyzer.analyzeFromJsUrl(base + "/main.js");

            assertFalse(result.ok());
            assertNotNull(result.error());
            assertTrue(SourceMapAnalyzer.formatReport(result).contains("failed"));
        } finally {
            server.stop(0);
        }
    }

    private static void respond(HttpExchange ex, String body, int status, String contentType) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", contentType);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
