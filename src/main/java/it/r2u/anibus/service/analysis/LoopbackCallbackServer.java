package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
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
    private volatile boolean running = true;

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
                byte[] buf = new byte[2048];
                try (InputStream in = s.getInputStream();
                     OutputStream out = s.getOutputStream()) {
                    int n = in.read(buf);
                    if (n > 0) {
                        String firstLine = new String(buf, 0, n).split("\\r?\\n", 2)[0];
                        hits.add(firstLine);
                    }
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .getBytes());
                    out.flush();
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
