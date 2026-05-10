package it.r2u.anibus.service.core;

class UdpScannerServiceTest {

    @org.junit.jupiter.api.Test
    void marksPortOpenWhenUdpResponseIsReceived() throws Exception {
        int port;
        try (java.net.DatagramSocket server = new java.net.DatagramSocket(0)) {
            port = server.getLocalPort();

            Thread responder = new Thread(() -> {
                try {
                    byte[] inBuf = new byte[256];
                    java.net.DatagramPacket in = new java.net.DatagramPacket(inBuf, inBuf.length);
                    server.receive(in);

                    byte[] outBuf = "ok".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    java.net.DatagramPacket out = new java.net.DatagramPacket(
                            outBuf,
                            outBuf.length,
                            in.getAddress(),
                            in.getPort()
                    );
                    server.send(out);
                } catch (java.io.IOException ignored) {
                }
            });
            responder.setDaemon(true);
            responder.start();

            UdpScannerService service = new UdpScannerService(1000);
            java.util.List<it.r2u.anibus.model.PortScanResult> results =
                    service.scan("127.0.0.1", new int[]{port}, null);

            org.junit.jupiter.api.Assertions.assertEquals(1, results.size());
            it.r2u.anibus.model.PortScanResult r = results.get(0);
            org.junit.jupiter.api.Assertions.assertEquals(port, r.getPort());
            org.junit.jupiter.api.Assertions.assertEquals("UDP", r.getProtocol());
            org.junit.jupiter.api.Assertions.assertEquals("open", r.getState());
            org.junit.jupiter.api.Assertions.assertTrue(
                    r.getBanner().contains("Response")
                            || r.getBanner().contains("DNS")
                            || r.getBanner().contains("NTP")
            );
        }
    }

    @org.junit.jupiter.api.Test
    void marksPortOpenFilteredOnTimeout() {
        int unusedPort = 65500;
        UdpScannerService service = new UdpScannerService(200);

        java.util.List<it.r2u.anibus.model.PortScanResult> results =
                service.scan("127.0.0.1", new int[]{unusedPort}, null);

        org.junit.jupiter.api.Assertions.assertEquals(1, results.size());
        it.r2u.anibus.model.PortScanResult r = results.get(0);
        org.junit.jupiter.api.Assertions.assertEquals(unusedPort, r.getPort());
        org.junit.jupiter.api.Assertions.assertEquals("UDP", r.getProtocol());
        org.junit.jupiter.api.Assertions.assertEquals("open|filtered", r.getState());
    }
}
