package it.r2u.anibus.service.network.proxy;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URI;
import java.util.List;

import it.r2u.anibus.model.ScanContext;

/**
 * Central factory for all proxied network resources.
 *
 * <p>Wires {@link ScanContext} proxy state into concrete JDK objects:
 * <ul>
 *   <li>{@link Socket} — for raw TCP connections (port scanning, banner grabbing).</li>
 *   <li>{@link HttpURLConnection} — for HTTP-level analysis (JS analysis, SQL injection).</li>
 *   <li>{@link Proxy} — raw java.net.Proxy for callers that manage their own connections.</li>
 * </ul>
 *
 * <p>If the context has no active proxy ({@code proxyEnabled == false}), direct connections
 * are returned transparently — callers do not need to branch.
 */
public class ProxyConnectionFactory {

    private static final int CONNECT_TIMEOUT_MS = 5_000;

    private final ProxyChainService chainService;

    public ProxyConnectionFactory() {
        this(new ProxyChainService());
    }

    public ProxyConnectionFactory(ProxyChainService chainService) {
        this.chainService = chainService;
    }

    /**
     * Create a connected {@link Socket} to {@code targetHost:targetPort},
     * routing through the proxy in {@code context} if enabled.
     *
     * @throws IOException if connection fails (proxy or direct)
     */
    public Socket createSocket(ScanContext context, String targetHost, int targetPort)
            throws IOException {
        Socket socket;

        if (context.proxyEnabled() && context.activeProxy().isPresent()) {
            ProxyNode proxy = context.activeProxy().get();
            socket = new Socket(proxy.toJavaProxy());
        } else {
            socket = new Socket();
        }

        try {
            socket.setSoTimeout(CONNECT_TIMEOUT_MS);
            socket.connect(new InetSocketAddress(targetHost, targetPort), CONNECT_TIMEOUT_MS);
        } catch (IOException e) {
            try { socket.close(); } catch (IOException ignored) {}
            throw e;
        }

        return socket;
    }

    /**
     * Return a {@link java.net.Proxy} object from the context.
     * Returns {@link Proxy#NO_PROXY} when proxy is disabled or unavailable.
     */
    public Proxy createProxy(ScanContext context) {
        if (context.proxyEnabled() && context.activeProxy().isPresent()) {
            return context.activeProxy().get().toJavaProxy();
        }
        return Proxy.NO_PROXY;
    }

    /**
     * Open an {@link HttpURLConnection} to the given URI, routing through the
     * proxy in {@code context} if enabled.
     *
     * <p>Callers are responsible for setting timeouts, headers, and closing the
     * connection.
     *
     * @throws IOException if the URL is malformed or connection cannot be opened
     */
    public HttpURLConnection openConnection(URI uri, ScanContext context) throws IOException {
        Proxy proxy = createProxy(context);
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection(proxy);
        conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(CONNECT_TIMEOUT_MS);
        conn.setRequestProperty("User-Agent", "Anibus-Scanner/1.8");
        return conn;
    }

    /**
     * Create a connected {@link Socket} through a proxy chain.
     * The chain is traversed in order: Proxy1 -> Proxy2 -> ... -> Target.
     *
     * @param proxyChain list of proxy nodes to tunnel through (in order)
     * @param targetHost the final target hostname
     * @param targetPort the final target port
     * @return a connected Socket to the target through the entire proxy chain
     * @throws IOException if any link in the chain fails
     */
    public Socket createSocketThroughChain(List<ProxyNode> proxyChain, String targetHost, int targetPort)
            throws IOException {
        if (proxyChain == null || proxyChain.isEmpty()) {
            throw new IllegalArgumentException("Proxy chain cannot be empty");
        }
        return chainService.connectThroughChain(proxyChain, targetHost, targetPort);
    }

    /**
     * Create a socket to a specific port through a proxy chain for HTTP analysis.
     * Useful for banner grabbing, certificate extraction, and other port-specific tasks.
     *
     * @param proxyChain list of proxies to chain
     * @param targetHost target hostname
     * @param targetPort target port
     * @return connected socket through the chain
     * @throws IOException if connection fails
     */
    public Socket createSocketThroughChainForPort(List<ProxyNode> proxyChain, String targetHost, int targetPort)
            throws IOException {
        return createSocketThroughChain(proxyChain, targetHost, targetPort);
    }
}
