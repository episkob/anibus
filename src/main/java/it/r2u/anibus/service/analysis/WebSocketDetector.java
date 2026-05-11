package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * WebSocket Detector
 *
 * Sends an HTTP Upgrade: websocket request to common WS paths.
 * A 101 Switching Protocols response confirms a WebSocket endpoint.
 * Also detects partial upgrades (server supports WS but requires auth).
 */
public class WebSocketDetector {

    public record WsEndpoint(
        String url,
        boolean upgraded,
        int responseCode,
        String serverHeader,
        String note
    ) {}

    private static final String[] WS_PATHS = {
        "/ws", "/websocket", "/socket", "/socket.io/",
        "/ws/v1", "/ws/v2", "/api/ws", "/api/websocket",
        "/live", "/realtime", "/events", "/stream",
        "/chat", "/notify", "/notifications",
        "/stomp", "/sockjs/websocket", "/signalr/negotiate"
    };

    private final int timeoutMs;

    public WebSocketDetector(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public WebSocketDetector() {
        this(5000);
    }

    public List<WsEndpoint> detect(String host, int port) {
        List<WsEndpoint> results = new ArrayList<>();
        String[] schemes = (port == 443) ? new String[]{"wss"}
                         : (port == 80)  ? new String[]{"ws"}
                         : new String[]{"ws", "wss"};

        for (String scheme : schemes) {
            for (String path : WS_PATHS) {
                WsEndpoint ep = probe(host, port, scheme, path);
                if (ep != null) results.add(ep);
            }
            if (!results.isEmpty()) break;
        }
        return results;
    }

    private WsEndpoint probe(String host, int port, String scheme, String path) {
        // Build WebSocket upgrade key (RFC 6455)
        byte[] keyBytes = new byte[16];
        new SecureRandom().nextBytes(keyBytes);
        String key = Base64.getEncoder().encodeToString(keyBytes);

        boolean useSsl = "wss".equals(scheme);
        String httpScheme = useSsl ? "https" : "http";
        String urlStr = httpScheme + "://" + host
            + (isDefaultPort(scheme, port) ? "" : ":" + port) + path;

        try {
            HttpURLConnection conn = (HttpURLConnection)
                URI.create(urlStr).toURL().openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Upgrade", "websocket");
            conn.setRequestProperty("Connection", "Upgrade");
            conn.setRequestProperty("Sec-WebSocket-Key", key);
            conn.setRequestProperty("Sec-WebSocket-Version", "13");
            conn.setRequestProperty("Host", host);
            conn.setInstanceFollowRedirects(false);
            conn.connect();

            int code = conn.getResponseCode();
            String server = conn.getHeaderField("Server");

            switch (code) {
                case 101 -> { return new WsEndpoint(urlStr, true, 101, server,
                        "WebSocket upgrade accepted (101 Switching Protocols)"); }
                case 426 -> { return new WsEndpoint(urlStr, false, 426, server,
                        "Server requires WebSocket upgrade (426 Upgrade Required)"); }
                case 401, 403 -> {
                    String upgrade = conn.getHeaderField("Upgrade");
                    if ("websocket".equalsIgnoreCase(upgrade)) {
                        return new WsEndpoint(urlStr, false, code, server,
                            "WS endpoint exists but requires authentication (HTTP " + code + ")");
                    }
                }
                default -> { /* not a WS response */ }
            }
        } catch (IOException | IllegalArgumentException ignored) {
        }
        return null;
    }

    private boolean isDefaultPort(String scheme, int port) {
        return ("ws".equals(scheme) && port == 80)
            || ("wss".equals(scheme) && port == 443);
    }

    public static String formatReport(List<WsEndpoint> endpoints, String target) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("          WEBSOCKET DETECTOR — ").append(target).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (endpoints.isEmpty()) {
            sb.append("  ✓ No WebSocket endpoints detected.\n");
        } else {
            long upgraded = endpoints.stream().filter(WsEndpoint::upgraded).count();
            sb.append(String.format("  Found %d WebSocket endpoint(s) (%d fully upgraded):\n\n",
                endpoints.size(), upgraded));
            for (WsEndpoint ep : endpoints) {
                sb.append(String.format("  URL     : %s\n", ep.url()));
                sb.append(String.format("  HTTP    : %d\n", ep.responseCode()));
                if (ep.serverHeader() != null) {
                    sb.append(String.format("  Server  : %s\n", ep.serverHeader()));
                }
                sb.append(String.format("  Note    : %s\n\n", ep.note()));
            }
        }
        return sb.toString();
    }
}
