package it.r2u.anibus.service.network.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.logging.Logger;

/**
 * Proxy chain service using HTTP CONNECT tunneling.
 *
 * <p>Implements the "chain through SOCKS" pattern:
 * <ol>
 *   <li>Connect to the first proxy.</li>
 *   <li>Send HTTP CONNECT to the second proxy through the first.</li>
 *   <li>Send HTTP CONNECT to the target through the second proxy.</li>
 *   <li>Return a socket connected to the target through the entire chain.</li>
 * </ol>
 *
 * <p>Supports arbitrary chain depth: Proxy1 -> Proxy2 -> Proxy3 -> ... -> Target.
 */
public class ProxyChainService {

    private static final Logger LOG = Logger.getLogger(ProxyChainService.class.getName());

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS = 5_000;

    /**
     * Establish a socket connection through a proxy chain.
     *
     * @param proxyChain list of proxy nodes to traverse (in order)
     * @param targetHost the final target hostname
     * @param targetPort the final target port
     * @return a connected Socket to the target through the entire proxy chain
     * @throws IOException if any link in the chain fails
     */
    public Socket connectThroughChain(List<ProxyNode> proxyChain, String targetHost, int targetPort)
            throws IOException {
        if (proxyChain == null || proxyChain.isEmpty()) {
            throw new IllegalArgumentException("Proxy chain cannot be empty");
        }

        if (targetHost == null || targetHost.trim().isEmpty()) {
            throw new IllegalArgumentException("Target host cannot be null or empty");
        }

        // Start with the first proxy
        Socket socket = connectToFirstProxy(proxyChain.get(0));
        try {
            // Tunnel through intermediate proxies
            for (int i = 1; i < proxyChain.size(); i++) {
                ProxyNode nextProxy = proxyChain.get(i);
                tunnelToProxy(socket, nextProxy.host(), nextProxy.port());
            }

            // Final tunnel to target
            tunnelToTarget(socket, targetHost, targetPort);
            return socket;
        } catch (IOException e) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            throw e;
        }
    }

    /**
     * Establish a socket connection to the first proxy in the chain.
     */
    private Socket connectToFirstProxy(ProxyNode firstProxy) throws IOException {
        Socket socket = new Socket();
        socket.setSoTimeout(READ_TIMEOUT_MS);

        try {
            InetSocketAddress address = new InetSocketAddress(firstProxy.host(), firstProxy.port());
            socket.connect(address, CONNECT_TIMEOUT_MS);
            LOG.info(() -> "Connected to first proxy: " + firstProxy);
            return socket;
        } catch (IOException e) {
            socket.close();
            LOG.warning(() -> "Failed to connect to first proxy " + firstProxy + ": " + e.getMessage());
            throw e;
        }
    }

    /**
     * Tunnel from the current socket to the next proxy using HTTP CONNECT.
     */
    private void tunnelToProxy(Socket socket, String nextProxyHost, int nextProxyPort)
            throws IOException {
        sendHttpConnectRequest(socket, nextProxyHost, nextProxyPort);
        verifyHttpConnectResponse(socket, nextProxyHost, nextProxyPort);
        LOG.info(() -> "Tunneled to intermediate proxy: " + nextProxyHost + ":" + nextProxyPort);
    }

    /**
     * Tunnel from the current socket to the final target using HTTP CONNECT.
     */
    private void tunnelToTarget(Socket socket, String targetHost, int targetPort)
            throws IOException {
        sendHttpConnectRequest(socket, targetHost, targetPort);
        verifyHttpConnectResponse(socket, targetHost, targetPort);
        LOG.info(() -> "Tunneled to target: " + targetHost + ":" + targetPort);
    }

    /**
     * Send an HTTP CONNECT request to establish a tunnel.
     * Format: CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n
     */
    private void sendHttpConnectRequest(Socket socket, String host, int port) throws IOException {
        String connectRequest = """
                CONNECT %s:%d HTTP/1.1
                Host: %s:%d
                Proxy-Connection: keep-alive
                User-Agent: Anibus-Scanner/1.8
                """.formatted(host, port, host, port).replace("\n", "\r\n");

        try {
            OutputStream out = socket.getOutputStream();
            out.write(connectRequest.getBytes(StandardCharsets.US_ASCII));
            out.flush();
        } catch (IOException e) {
            LOG.warning(() -> "Failed to send HTTP CONNECT to " + host + ":" + port + ": " + e.getMessage());
            throw e;
        }
    }

    /**
     * Verify that the HTTP CONNECT request was successful (200 response code).
     */
    private void verifyHttpConnectResponse(Socket socket, String host, int port) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] buffer = new byte[1024];

        try {
            int bytesRead = in.read(buffer);
            if (bytesRead <= 0) {
                throw new IOException("No response from proxy for CONNECT to " + host + ":" + port);
            }

            String response = new String(buffer, 0, bytesRead, StandardCharsets.US_ASCII);
            // Check for "200" in the first line (HTTP/1.x 200 ...)
            if (!response.contains(" 200 ")) {
                throw new IOException(
                        "Proxy rejected CONNECT to " + host + ":" + port +
                                ". Response: " + response.substring(0, Math.min(100, response.length()))
                );
            }
        } catch (IOException e) {
            LOG.warning(() -> "HTTP CONNECT verification failed for " + host + ":" + port + ": " + e.getMessage());
            throw e;
        }
    }

    /**
     * Format chain as a human-readable string.
     */
    public static String formatChain(List<ProxyNode> chain) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < chain.size(); i++) {
            if (i > 0) sb.append(" -> ");
            ProxyNode proxy = chain.get(i);
            sb.append(proxy.host()).append(":").append(proxy.port())
                    .append(" (").append(proxy.type()).append(")");
        }
        return sb.toString();
    }
}
