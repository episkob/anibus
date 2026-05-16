package it.r2u.anibus.service.iot;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight RTSP probe (OPTIONS handshake) used for IoT/camera detection.
 * Detection only — does not authenticate and does not request streams.
 */
public class RtspProbeService {

    public record RtspProbeResult(
            boolean ok,
            String statusLine,
            String serverHeader,
            String publicHeader,
            String rawResponse,
            String manufacturerGuess,
            String suggestedRtspUrl
    ) {}

    private final int timeoutMs;
    private final int maxLines;

    public RtspProbeService(int timeoutMs) {
        this(timeoutMs, 25);
    }

    public RtspProbeService(int timeoutMs, int maxLines) {
        this.timeoutMs = timeoutMs;
        this.maxLines = Math.max(5, maxLines);
    }

    public RtspProbeResult probe(String host, int port) {
        String request = "OPTIONS rtsp://" + host + ":" + port + "/ RTSP/1.0\r\n" +
                         "CSeq: 1\r\n" +
                         "User-Agent: Anibus/1.0\r\n\r\n";

        try (Socket socket = new Socket()) {
            socket.setSoTimeout(timeoutMs);
            socket.connect(new InetSocketAddress(host, port), timeoutMs);

            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.flush();

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

            List<String> lines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null && lines.size() < maxLines) {
                lines.add(line);
                if (line.isEmpty()) break;
            }

            String raw = String.join("\n", lines).trim();
            String statusLine = lines.isEmpty() ? null : lines.getFirst();
            String server = headerValue(lines, "server");
            String pub = headerValue(lines, "public");

            String lc = (raw == null ? "" : raw.toLowerCase());
            String manufacturer = guessManufacturer(lc, server);
            String suggested = suggestedRtspUrl(host, manufacturer);

            boolean ok = statusLine != null && statusLine.toUpperCase().contains("RTSP/1.0");
            return new RtspProbeResult(ok, statusLine, server, pub, raw, manufacturer, suggested);
        } catch (IOException e) {
            return new RtspProbeResult(false, null, null, null, null, null, "rtsp://" + host + ":" + port + "/");
        }
    }

    private static String headerValue(List<String> lines, String nameLower) {
        for (String l : lines) {
            if (l == null) continue;
            int idx = l.indexOf(':');
            if (idx <= 0) continue;
            String k = l.substring(0, idx).trim().toLowerCase();
            if (!k.equals(nameLower)) continue;
            return l.substring(idx + 1).trim();
        }
        return null;
    }

    private static String guessManufacturer(String rawLower, String serverHeader) {
        String s = (serverHeader == null ? "" : serverHeader.toLowerCase());
        if (rawLower.contains("hikvision") || rawLower.contains("ds-") || s.contains("hikvision")) return "Hikvision";
        if (rawLower.contains("dahua") || s.contains("dahua")) return "Dahua";
        if (rawLower.contains("axis") || s.contains("axis")) return "Axis Communications";
        if (rawLower.contains("vivotek") || s.contains("vivotek")) return "Vivotek";
        if (rawLower.contains("foscam") || s.contains("foscam")) return "Foscam";
        if (rawLower.contains("tp-link") || rawLower.contains("tapo") || s.contains("tp-link") || s.contains("tapo")) return "TP-Link";
        return null;
    }

    private static String suggestedRtspUrl(String host, String manufacturer) {
        if (manufacturer == null) return "rtsp://" + host + ":554/";
        return switch (manufacturer) {
            case "Hikvision" -> "rtsp://" + host + ":554/Streaming/Channels/101";
            case "Dahua" -> "rtsp://" + host + ":554/cam/realmonitor?channel=1&subtype=0";
            case "Axis Communications" -> "rtsp://" + host + ":554/axis-media/media.amp";
            case "Vivotek" -> "rtsp://" + host + ":554/live.sdp";
            case "Foscam" -> "rtsp://" + host + ":554/videoMain";
            case "TP-Link" -> "rtsp://" + host + ":554/stream1";
            default -> "rtsp://" + host + ":554/";
        };
    }
}

