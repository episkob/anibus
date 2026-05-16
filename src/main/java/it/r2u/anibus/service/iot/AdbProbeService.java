package it.r2u.anibus.service.iot;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Android Debug Bridge (ADB) exposure probe.
 * Detection only — sends "host:version" and parses response.
 */
public class AdbProbeService {

    public record AdbProbeResult(boolean ok, boolean unauthorizedOrExposed, String version, String raw) {}

    private final int timeoutMs;

    public AdbProbeService(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public AdbProbeResult probe(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(timeoutMs);
            socket.connect(new InetSocketAddress(host, port), timeoutMs);

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // ADB protocol: 4 ASCII hex length + payload
            String payload = "host:version";
            String len = String.format("%04x", payload.length());
            out.write((len + payload).getBytes(StandardCharsets.US_ASCII));
            out.flush();

            byte[] status = readN(in, 4);
            if (status == null) return new AdbProbeResult(false, false, null, null);
            String statusStr = new String(status, StandardCharsets.US_ASCII);
            if (!statusStr.equals("OKAY") && !statusStr.equals("FAIL")) {
                return new AdbProbeResult(false, false, null, statusStr);
            }

            byte[] l = readN(in, 4);
            if (l == null) return new AdbProbeResult(false, false, null, statusStr);
            int n = Integer.parseInt(new String(l, StandardCharsets.US_ASCII), 16);
            byte[] body = readN(in, Math.min(n, 512));
            String bodyStr = body == null ? null : new String(body, StandardCharsets.US_ASCII);

            boolean ok = statusStr.equals("OKAY");
            // If ADB answers OKAY on network, it is usually an exposed debug interface
            boolean exposed = ok;
            return new AdbProbeResult(ok, exposed, bodyStr, statusStr + " " + (bodyStr != null ? bodyStr : ""));
        } catch (IOException | NumberFormatException e) {
            return new AdbProbeResult(false, false, null, null);
        }
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) return null;
            off += r;
        }
        return buf;
    }
}

