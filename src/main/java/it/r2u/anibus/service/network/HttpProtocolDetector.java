package it.r2u.anibus.service.network;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * HTTP/2 and HTTP/3 Protocol Detector
 *
 * Detects HTTP/2 via ALPN negotiation during TLS handshake.
 * Detects HTTP/3 via the Alt-Svc response header (h3, h3-29, etc.).
 * HTTP/1.1 baseline is always checked via plain HTTP GET.
 */
public class HttpProtocolDetector {

    public record ProtocolResult(
        String target,
        boolean http11,
        boolean http2,
        boolean http3Advertised,
        String http3AltSvc,
        String negotiatedAlpn,
        String serverHeader,
        List<String> notes
    ) {}

    private final int timeoutMs;

    public HttpProtocolDetector(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public HttpProtocolDetector() {
        this(6000);
    }

    public ProtocolResult detect(String host, int port) {
        List<String> notes = new ArrayList<>();
        boolean http11 = false;
        boolean http2  = false;
        boolean http3  = false;
        String altSvc  = null;
        String alpn    = null;
        String server  = null;

        // ── 1. HTTP/1.1 baseline ─────────────────────────────────────────
        try {
            String scheme = (port == 443) ? "https" : "http";
            String url = scheme + "://" + host
                + (isDefaultPort(scheme, port) ? "" : ":" + port) + "/";
            HttpURLConnection conn = (HttpURLConnection)
                URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            conn.setInstanceFollowRedirects(false);
            int code = conn.getResponseCode();
            if (code > 0) {
                http11 = true;
                server = conn.getHeaderField("Server");
                altSvc = conn.getHeaderField("Alt-Svc");
                if (altSvc != null && (altSvc.contains("h3") || altSvc.contains("h2"))) {
                    if (altSvc.contains("h3")) {
                        http3 = true;
                        notes.add("HTTP/3 advertised via Alt-Svc: " + altSvc);
                    }
                    if (altSvc.contains("h2")) {
                        notes.add("HTTP/2 also advertised in Alt-Svc");
                    }
                }
            }
        } catch (IOException | IllegalArgumentException e) {
            notes.add("HTTP/1.1 probe failed: " + e.getMessage());
        }

        // ── 2. HTTP/2 via ALPN ────────────────────────────────────────────
        if (port == 443 || port > 8000) {
            int tlsPort = (port == 80) ? 443 : port;
            String detectedAlpn = probeAlpn(host, tlsPort, notes);
            if (detectedAlpn != null) {
                alpn = detectedAlpn;
                if ("h2".equals(detectedAlpn)) {
                    http2 = true;
                    notes.add("HTTP/2 confirmed via ALPN negotiation");
                } else if ("http/1.1".equalsIgnoreCase(detectedAlpn)) {
                    notes.add("Server supports TLS but only negotiated HTTP/1.1 via ALPN");
                } else {
                    notes.add("ALPN negotiated: " + detectedAlpn);
                }
            }
        }

        // ── 3. Upgrade: h2c (plaintext HTTP/2) ───────────────────────────
        if (!http2 && port != 443) {
            try {
                String url = "http://" + host + (port == 80 ? "" : ":" + port) + "/";
                HttpURLConnection conn = (HttpURLConnection)
                    URI.create(url).toURL().openConnection();
                conn.setConnectTimeout(timeoutMs);
                conn.setReadTimeout(timeoutMs);
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Upgrade", "h2c");
                conn.setRequestProperty("Connection", "Upgrade, HTTP2-Settings");
                conn.setRequestProperty("HTTP2-Settings", "AAMAAABkAAQAAP__");
                conn.setInstanceFollowRedirects(false);
                int code = conn.getResponseCode();
                if (code == 101) {
                    http2 = true;
                    notes.add("HTTP/2 cleartext (h2c) upgrade accepted (101)");
                }
            } catch (IOException | IllegalArgumentException ignored) {
            }
        }

        return new ProtocolResult(host + ":" + port, http11, http2, http3,
            altSvc, alpn, server, notes);
    }

    private String probeAlpn(String host, int port, List<String> notes) {
        try {
            SSLContext ctx = buildTrustAllContext();
            SSLSocketFactory factory = ctx.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                SSLParameters params = socket.getSSLParameters();
                params.setApplicationProtocols(new String[]{"h2", "http/1.1"});
                socket.setSSLParameters(params);
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);
                socket.startHandshake();
                return socket.getApplicationProtocol();
            }
        } catch (IOException | GeneralSecurityException e) {
            notes.add("ALPN probe failed: " + e.getMessage());
            return null;
        }
    }

    private SSLContext buildTrustAllContext() throws GeneralSecurityException {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
                @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new java.security.SecureRandom());
        return ctx;
    }

    private boolean isDefaultPort(String scheme, int port) {
        return ("http".equals(scheme) && port == 80)
            || ("https".equals(scheme) && port == 443);
    }

    public static String formatReport(ProtocolResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("      HTTP PROTOCOL DETECTOR — ").append(r.target()).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        sb.append(String.format("  HTTP/1.1 : %s\n", r.http11() ? "✓ Supported" : "✗ Not detected"));
        sb.append(String.format("  HTTP/2   : %s\n", r.http2()  ? "✓ Supported" : "✗ Not detected"));
        sb.append(String.format("  HTTP/3   : %s\n", r.http3Advertised() ? "✓ Advertised via Alt-Svc" : "✗ Not advertised"));

        if (r.negotiatedAlpn() != null && !r.negotiatedAlpn().isEmpty()) {
            sb.append(String.format("  ALPN     : %s\n", r.negotiatedAlpn()));
        }
        if (r.serverHeader() != null) {
            sb.append(String.format("  Server   : %s\n", r.serverHeader()));
        }
        if (r.http3AltSvc() != null) {
            sb.append(String.format("  Alt-Svc  : %s\n", r.http3AltSvc()));
        }

        if (!r.notes().isEmpty()) {
            sb.append("\n  Notes:\n");
            for (String note : r.notes()) {
                sb.append("    • ").append(note).append("\n");
            }
        }
        return sb.toString();
    }
}
