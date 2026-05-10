package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class ParamMinerServiceTest {

    @Test
    void findsInterestingParamsWhenCanaryIsReflected() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        try {
            server.createContext("/reflect", ex -> {
                String query = ex.getRequestURI().getRawQuery();
                String body = readBody(ex);
                String response = "base" + (query == null ? "" : " " + query) + (body.isBlank() ? "" : " " + body);
                respond(ex, response, 200);
            });
            server.start();

            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/reflect";
            ParamMinerService service = new ParamMinerService();

            List<ParamMinerService.ParamFinding> findings = service.mine(url, true, null);

            assertFalse(findings.isEmpty());
            assertTrue(findings.stream().anyMatch(f -> f.paramType() == ParamMinerService.ParamType.GET));
            assertTrue(findings.stream().anyMatch(f -> f.paramType() == ParamMinerService.ParamType.POST));
            assertTrue(findings.stream().anyMatch(ParamMinerService.ParamFinding::isReflected));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void returnsNoFindingsForStableResponse() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        try {
            server.createContext("/stable", ex -> respond(ex, "constant-response", 200));
            server.start();

            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/stable";
            ParamMinerService service = new ParamMinerService();

            List<ParamMinerService.ParamFinding> findings = service.mine(url, true, null);

            assertTrue(findings.isEmpty());
            assertTrue(ParamMinerService.formatReport(findings, url).contains("no interesting parameters"));
        } finally {
            server.stop(0);
        }
    }

    private static String readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void respond(HttpExchange ex, String body, int status) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
