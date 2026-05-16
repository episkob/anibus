package it.r2u.anibus.service.iot;

class AdbProbeServiceTest {

    @org.junit.jupiter.api.Test
    void parsesHostVersionOkResponse() throws Exception {
        int port;
        try (java.net.ServerSocket server = new java.net.ServerSocket(0)) {
            port = server.getLocalPort();

            Thread worker = new Thread(() -> {
                try (java.net.Socket s = server.accept()) {
                    s.setSoTimeout(1500);
                    java.io.InputStream in = s.getInputStream();
                    java.io.OutputStream out = s.getOutputStream();

                    byte[] len = in.readNBytes(4);
                    int n = Integer.parseInt(new String(len, java.nio.charset.StandardCharsets.US_ASCII), 16);
                    byte[] payload = in.readNBytes(n);
                    String cmd = new String(payload, java.nio.charset.StandardCharsets.US_ASCII);

                    if (!"host:version".equals(cmd)) return;

                    String body = "001f";
                    String bodyLen = String.format("%04x", body.length());
                    out.write("OKAY".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    out.write(bodyLen.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    out.write(body.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    out.flush();
                } catch (Exception ignored) {
                }
            });
            worker.setDaemon(true);
            worker.start();

            AdbProbeService svc = new AdbProbeService(1500);
            AdbProbeService.AdbProbeResult res = svc.probe("127.0.0.1", port);

            org.junit.jupiter.api.Assertions.assertTrue(res.ok());
            org.junit.jupiter.api.Assertions.assertEquals("001f", res.version());
            org.junit.jupiter.api.Assertions.assertTrue(res.unauthorizedOrExposed());
        }
    }
}

