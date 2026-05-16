package it.r2u.anibus.service.iot;

class RtspProbeServiceTest {

    @org.junit.jupiter.api.Test
    void detectsHikvisionFromRtspOptionsResponse() throws Exception {
        int port;
        try (java.net.ServerSocket server = new java.net.ServerSocket(0)) {
            port = server.getLocalPort();

            Thread worker = new Thread(() -> {
                try (java.net.Socket s = server.accept()) {
                    s.setSoTimeout(1000);
                    // Read a bit (request headers), then respond
                    byte[] buf = new byte[2048];
                    try {
                        s.getInputStream().read(buf);
                    } catch (Exception ignored) {
                    }
                    String resp =
                            "RTSP/1.0 200 OK\r\n" +
                            "CSeq: 1\r\n" +
                            "Server: Hikvision\r\n" +
                            "Public: OPTIONS, DESCRIBE\r\n" +
                            "\r\n";
                    s.getOutputStream().write(resp.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    s.getOutputStream().flush();
                } catch (Exception ignored) {
                }
            });
            worker.setDaemon(true);
            worker.start();

            RtspProbeService svc = new RtspProbeService(1500);
            RtspProbeService.RtspProbeResult res = svc.probe("127.0.0.1", port);

            org.junit.jupiter.api.Assertions.assertTrue(res.ok());
            org.junit.jupiter.api.Assertions.assertEquals("Hikvision", res.manufacturerGuess());
            org.junit.jupiter.api.Assertions.assertTrue(res.suggestedRtspUrl().contains("/Streaming/Channels/101"));
        }
    }
}

