package it.r2u.anibus.service.iot;

class OnvifProbeServiceTest {

    @org.junit.jupiter.api.Test
    void detectsOnvifFromDeviceServicePath() throws Exception {
        com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
                new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        int port = server.getAddress().getPort();

        server.createContext("/onvif/device_service", ex -> {
            byte[] body = "<definitions>ONVIF</definitions>".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "text/xml");
            ex.sendResponseHeaders(200, body.length);
            try (java.io.OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();

        try {
            OnvifProbeService svc = new OnvifProbeService(1500);
            OnvifProbeService.OnvifProbeResult res = svc.probe("127.0.0.1", new int[]{port});
            org.junit.jupiter.api.Assertions.assertTrue(res.detected());
        } finally {
            server.stop(0);
        }
    }
}

