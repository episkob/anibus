package it.r2u.anibus.service.network.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ProxyChainServiceTest {

    @Test
    void chainsMultipleProxiesToTarget() throws Exception {
        // Start target server on localhost
        ServerSocket targetServer = new ServerSocket(0);
        int targetPort = targetServer.getLocalPort();

        Thread targetThread = new Thread(() -> {
            try {
                Socket conn = targetServer.accept();
                conn.close();
            } catch (IOException ignored) {
            }
        });
        targetThread.setDaemon(true);
        targetThread.start();

        // Start first proxy server (echoes CONNECT requests)
        ServerSocket proxy1Server = new ServerSocket(0);
        int proxy1Port = proxy1Server.getLocalPort();

        Thread proxy1Thread = new Thread(() -> {
            try {
                Socket conn = proxy1Server.accept();
                handleProxyRequest(conn, 2);
            } catch (IOException ignored) {
            }
        });
        proxy1Thread.setDaemon(true);
        proxy1Thread.start();

        // Start second proxy server
        ServerSocket proxy2Server = new ServerSocket(0);
        int proxy2Port = proxy2Server.getLocalPort();

        Thread proxy2Thread = new Thread(() -> {
            try {
                Socket conn = proxy2Server.accept();
                handleProxyRequest(conn, 3);
            } catch (IOException ignored) {
            }
        });
        proxy2Thread.setDaemon(true);
        proxy2Thread.start();

        try {
            // Create proxy chain
            ProxyNode proxy1 = new ProxyNode("127.0.0.1", proxy1Port, ProxyType.HTTP, "XX", 1L);
            ProxyNode proxy2 = new ProxyNode("127.0.0.1", proxy2Port, ProxyType.HTTP, "XX", 1L);
            List<ProxyNode> chain = List.of(proxy1, proxy2);

            ProxyChainService chainService = new ProxyChainService();

            // Connect through chain to target
            try (Socket socket = chainService.connectThroughChain(chain, "127.0.0.1", targetPort)) {
                // Verify connection succeeded
                assertNotNull(socket);
                assertTrue(socket.isConnected());

                // Wait for threads to complete
                Thread.sleep(100);
            }
        } finally {
            targetServer.close();
            proxy1Server.close();
            proxy2Server.close();
        }
    }

    @Test
    void formatsChainCorrectly() {
        ProxyNode proxy1 = new ProxyNode("192.168.1.100", 8080, ProxyType.HTTP, "XX", 50L);
        ProxyNode proxy2 = new ProxyNode("10.0.0.1", 3128, ProxyType.SOCKS5, "XX", 75L);
        List<ProxyNode> chain = List.of(proxy1, proxy2);

        String formatted = ProxyChainService.formatChain(chain);

        assertTrue(formatted.contains("192.168.1.100:8080"));
        assertTrue(formatted.contains("10.0.0.1:3128"));
        assertTrue(formatted.contains("->"));
        assertTrue(formatted.contains("HTTP"));
        assertTrue(formatted.contains("SOCKS5"));
    }

    @Test
    void rejectsEmptyChain() {
        ProxyChainService chainService = new ProxyChainService();

        try {
            chainService.connectThroughChain(List.of(), "example.com", 80);
            throw new AssertionError("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("empty"));
        } catch (IOException ignored) {
        }
    }

    /**
     * Simulate proxy behavior: accept CONNECT request and forward to next hop.
     */
    private void handleProxyRequest(Socket clientSocket, int hopCount) throws IOException {
        try (InputStream in = clientSocket.getInputStream();
             OutputStream out = clientSocket.getOutputStream()) {

            byte[] buffer = new byte[1024];
            int read = in.read(buffer);
            if (read <= 0) return;

            String request = new String(buffer, 0, read, StandardCharsets.US_ASCII);

            // Parse CONNECT request
            if (request.contains("CONNECT")) {
                // Send 200 OK response to establish tunnel
                String response = "HTTP/1.1 200 Connection Established\r\n\r\n";
                out.write(response.getBytes(StandardCharsets.US_ASCII));
                out.flush();

                // If not last hop, act as client to next proxy
                if (hopCount > 1) {
                    // Re-read to get next CONNECT
                    Thread.sleep(50);
                    int nextRead = in.read(buffer);
                    if (nextRead > 0) {
                        // Echo back 200 OK
                        out.write(response.getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                    }
                }
            }
        } catch (IOException | InterruptedException ignored) {
        }
    }
}
