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

class PassiveReconServiceTest {

    @Test
    void collectsPageMetadataRobotsSitemapAndFaviconHash() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().set("X-Test", "ok");
            respond(exchange, 200, "<html><title>  Demo   Site </title><body>ok</body></html>", "text/html");
        });
        server.createContext("/robots.txt", exchange -> respond(exchange, 200, "User-agent: *", "text/plain"));
        server.createContext("/sitemap.xml", exchange -> respond(exchange, 200, "<xml/>", "application/xml"));
        server.createContext("/favicon.ico", exchange -> respond(exchange, 200, "ico-bytes", "application/octet-stream"));
        server.start();

        try {
            String base = "http://localhost:" + server.getAddress().getPort() + "/";
            PassiveReconService.PassiveReconResult result = new PassiveReconService().scan(base);

            assertEquals(200, result.statusCode());
            assertEquals("Demo Site", result.pageTitle());
            assertTrue(result.robotsFound());
            assertTrue(result.sitemapFound());
            assertTrue(result.headers().containsKey("x-test"));
            assertEquals(64, result.faviconSha256().length());
            assertTrue(result.notes().isEmpty());

            String report = PassiveReconService.formatReport(result);
            assertTrue(report.contains("PASSIVE RECON"));
            assertTrue(report.contains("Demo Site"));
            assertTrue(report.contains("robots.txt: ✓ found"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void recordsProbeErrorsForInvalidTarget() {
        PassiveReconService.PassiveReconResult result = new PassiveReconService().scan("not-a-valid-url");

        assertEquals(-1, result.statusCode());
        assertFalse(result.notes().isEmpty());
        assertTrue(result.notes().get(0).contains("Probe error"));
        assertTrue(PassiveReconService.formatReport(result).contains("Notes"));
    }

    private static void respond(HttpExchange exchange, int code, String body, String contentType) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
