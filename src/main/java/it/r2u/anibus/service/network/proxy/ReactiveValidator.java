package it.r2u.anibus.service.network.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.logging.Logger;

/**
 * Triple-Handshake proxy validator using Java 21 Virtual Threads.
 *
 * <p>For each candidate proxy, performs three steps:
 * <ol>
 *   <li><b>TCP-connect</b> — plain socket connect to proxy host:port.</li>
 *   <li><b>Forwarding check</b> — HTTP CONNECT (HTTP) or SOCKS5 CONNECT (SOCKS5)
 *       to a well-known public endpoint (8.8.8.8:80).</li>
 *   <li><b>Latency measurement</b> — wall-clock time of steps 1+2 combined.</li>
 * </ol>
 *
 * <p>Proxies that pass all three steps are returned with their measured latency.
 * All others are silently discarded — proxy errors never propagate to callers.
 */
public class ReactiveValidator {

    private static final Logger LOG = Logger.getLogger(ReactiveValidator.class.getName());

    private static final int CONNECT_TIMEOUT_MS = 4_000;
    private static final int MAX_LATENCY_MS     = 8_000;

    /** Max simultaneous open sockets — prevents flooding the network channel. */
    private static final int MAX_CONCURRENT     = 200;

    // Neutral host used for CONNECT probe (only need TCP, no real HTTP traffic)
    private static final String PROBE_HOST = "8.8.8.8";
    private static final int    PROBE_PORT = 80;

    /**
     * Validates all candidates in parallel using virtual threads.
     * {@code progressCallback} receives (checked, total) after each proxy is processed.
     *
     * @param candidates raw proxy nodes (latencyMs = -1, countryCode may be "XX")
     * @param progressCallback called with (checked, total) after each probe; may be null
     * @return set of live nodes with measured latency
     */
    public Set<ProxyNode> validateAll(Set<ProxyNode> candidates,
                                      BiConsumer<Integer, Integer> progressCallback) {
        Set<ProxyNode> live = java.util.Collections.synchronizedSet(new HashSet<>());
        int total = candidates.size();
        AtomicInteger checked = new AtomicInteger(0);
        Semaphore semaphore = new Semaphore(MAX_CONCURRENT);

        try (ExecutorService vt = Executors.newVirtualThreadPerTaskExecutor()) {
            Set<CompletableFuture<Void>> futures = new HashSet<>();

            for (ProxyNode node : candidates) {
                CompletableFuture<Void> f = CompletableFuture
                        .supplyAsync(() -> {
                            try {
                                semaphore.acquire();
                                try {
                                    return validate(node);
                                } finally {
                                    semaphore.release();
                                }
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                return null;
                            }
                        }, vt)
                        .exceptionally(ex -> null)
                        .thenAccept(result -> {
                            if (result != null) live.add(result);
                            int done = checked.incrementAndGet();
                            if (progressCallback != null) progressCallback.accept(done, total);
                        });
                futures.add(f);
            }

            CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new))
                    .get(MAX_LATENCY_MS * 2L + 5_000, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | java.util.concurrent.ExecutionException
                | java.util.concurrent.TimeoutException ignored) {
            // return whatever was validated so far
        }

        LOG.info(String.format("[Validator] %d/%d proxies passed triple-handshake",
                live.size(), total));
        return live;
    }

    /** Convenience overload without progress callback. */
    public Set<ProxyNode> validateAll(Set<ProxyNode> candidates) {
        return validateAll(candidates, null);
    }

    /**
     * Validate a single proxy node. Returns a node with real latency on success,
     * or null on any failure.
     */
    private ProxyNode validate(ProxyNode node) {
        try {
            long start = System.nanoTime();
            boolean ok = switch (node.type()) {
                case HTTP    -> validateHttp(node);
                case SOCKS5  -> validateSocks5(node);
            };
            if (!ok) return null;

            long latency = (System.nanoTime() - start) / 1_000_000;
            if (latency > MAX_LATENCY_MS) return null;

            return node.withLatency(latency);
        } catch (Exception e) {
            return null;
        }
    }

    // ── HTTP: TCP connect → CONNECT probe ────────────────────────────────────

    private boolean validateHttp(ProxyNode node) {
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(CONNECT_TIMEOUT_MS);
            // Handshake 1: TCP connect to proxy
            socket.connect(new InetSocketAddress(node.host(), node.port()), CONNECT_TIMEOUT_MS);

            // Handshake 2: send HTTP CONNECT
            OutputStream out = socket.getOutputStream();
            String req = "CONNECT " + PROBE_HOST + ":" + PROBE_PORT
                    + " HTTP/1.1\r\nHost: " + PROBE_HOST + ":" + PROBE_PORT
                    + "\r\nProxy-Connection: keep-alive\r\n\r\n";
            out.write(req.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            // Handshake 3: check response (200 = tunnel established)
            InputStream in = socket.getInputStream();
            byte[] buf = new byte[64];
            int read = in.read(buf);
            if (read <= 0) return false;
            String resp = new String(buf, 0, read, StandardCharsets.US_ASCII);
            return resp.startsWith("HTTP/1.1 200") || resp.startsWith("HTTP/1.0 200");
        } catch (IOException e) {
            return false;
        }
    }

    // ── SOCKS5: use JDK SOCKS support to open a tunnelled socket ─────────────

    private boolean validateSocks5(ProxyNode node) {
        java.net.Proxy socks = new java.net.Proxy(
                java.net.Proxy.Type.SOCKS,
                new InetSocketAddress(node.host(), node.port()));

        // Handshake 1+2: JDK negotiates SOCKS5 auth + CONNECT internally
        try (Socket socket = new Socket(socks)) {
            socket.setSoTimeout(CONNECT_TIMEOUT_MS);
            socket.connect(new InetSocketAddress(PROBE_HOST, PROBE_PORT), CONNECT_TIMEOUT_MS);
            // Handshake 3: connection successful = proxy alive
            return socket.isConnected();
        } catch (IOException e) {
            return false;
        }
    }
}
