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

class DirectoryBruteforcerTest {

    @Test
    void probesBackupVariantsForDiscoveredPaths() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/admin", exchange -> send(exchange, 200, "admin"));
        server.createContext("/admin.bak", exchange -> send(exchange, 200, "backup"));
        server.start();

        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            DirectoryBruteforcer bruteforcer = new DirectoryBruteforcer();
            List<DirectoryBruteforcer.PathResult> results = bruteforcer.scan(baseUrl, null);

            assertTrue(results.stream().anyMatch(r -> r.url().endsWith("/admin") && r.statusCode() == 200));
            assertTrue(results.stream().anyMatch(r -> r.url().endsWith("/admin.bak") && r.statusCode() == 200));
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
