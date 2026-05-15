package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Embedded loopback HTTP callback listener for out-of-band (OOB) detection.
 *
 * <p>Opens a {@link ServerSocket} bound to 127.0.0.1 on a random ephemeral
 * port and accepts inbound HTTP connections in a background daemon thread.
 * Every accepted connection has its request-line recorded in {@link #hits()}.
 *
 * <p>Used by detectors (SSRF, XXE, SQLi, Blind XSS) to verify out-of-band
 * exfiltration without depending on external OAST services. Suitable only for
 * targets that can reach the scanner's loopback (i.e. local lab / same host),
 * which is exactly the desktop-scanner use case.
 *
 * <p>The instance is {@link AutoCloseable} — use try-with-resources.
 */
public final class LoopbackCallbackServer implements AutoCloseable {

    private final ServerSocket server;
    private final Thread acceptor;
    private final List<String> hits = new CopyOnWriteArrayList<>();
    private final ConcurrentHashMap<String, RegisteredResponse> responseRegistry = new ConcurrentHashMap<>();
    private volatile boolean running = true;

    /** A static response served at a specific path. */
    private record RegisteredResponse(String contentType, byte[] body) {}

    /**
     * Register a static response body to be served at a specific URL path.
     * Used to serve a malicious DTD at e.g. {@code /oob.dtd} so that
     * parameter-entity XXE payloads can fetch and execute it for data exfiltration.
     */
    public void registerResponse(String path, String contentType, String body) {
        responseRegistry.put(path, new RegisteredResponse(contentType,
                body.getBytes(StandardCharsets.UTF_8)));
    }

    private LoopbackCallbackServer(ServerSocket socket) {
        this.server = socket;
        this.acceptor = new Thread(this::acceptLoop, "anibus-oob-callback");
        this.acceptor.setDaemon(true);
    }

    /**
     * Opens a listener on 127.0.0.1 on a random ephemeral port and starts
     * accepting connections. The accept loop runs in a daemon thread that is
     * started by this factory (intentionally outside the constructor so that
     * partial construction never leaks a running thread).
     */
    public static LoopbackCallbackServer start() throws IOException {
        ServerSocket socket = new ServerSocket(0, 16, InetAddress.getLoopbackAddress());
        LoopbackCallbackServer s = new LoopbackCallbackServer(socket);
        s.acceptor.start();
        return s;
    }

    public int port() {
        return server.getLocalPort();
    }

    /** Base URL the listener answers on, e.g. {@code http://127.0.0.1:54321/}. */
    public String baseUrl() {
        return "http://127.0.0.1:" + port() + "/";
    }

    /** Snapshot of recorded request-lines (one per inbound hit). */
    public List<String> hits() {
        return new ArrayList<>(hits);
    }

    public boolean hasHits() {
        return !hits.isEmpty();
    }

    private void acceptLoop() {
        while (running && !server.isClosed()) {
            try (Socket s = server.accept()) {
                s.setSoTimeout(1500);
                byte[] buf = new byte[4096];
                try (InputStream in = s.getInputStream();
                     OutputStream out = s.getOutputStream()) {
                    int n = in.read(buf);
                    if (n > 0) {
                        String raw = new String(buf, 0, n, StandardCharsets.UTF_8);
                        String firstLine = raw.split("\\r?\\n", 2)[0];
                        hits.add(firstLine);

                        // Parse request path to serve registered responses (e.g. malicious DTDs)
                        String requestPath = "/";
                        String[] lineParts = firstLine.split(" ");
                        if (lineParts.length >= 2) {
                            requestPath = lineParts[1].split("\\?")[0];
                        }
                        RegisteredResponse registered = responseRegistry.get(requestPath);
                        if (registered != null) {
                            String header = "HTTP/1.1 200 OK\r\nContent-Type: " + registered.contentType()
                                    + "\r\nContent-Length: " + registered.body().length
                                    + "\r\nConnection: close\r\n\r\n";
                            out.write(header.getBytes(StandardCharsets.UTF_8));
                            out.write(registered.body());
                        } else {
                            out.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                    .getBytes(StandardCharsets.UTF_8));
                        }
                        out.flush();
                    }
                }
            } catch (IOException ignored) {
                // Socket closed by close() or peer reset — exit loop on next iteration check.
            }
        }
    }

    @Override
    public void close() {
        running = false;
        try {
            server.close();
        } catch (IOException ignored) {
            // ignore — already best-effort shutdown
        }
    }
}
