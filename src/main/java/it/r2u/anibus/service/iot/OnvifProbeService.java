package it.r2u.anibus.service.iot;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * ONVIF presence probe (HTTP heuristics).
 * Detection only — does not attempt auth, user creation, or configuration changes.
 */
public class OnvifProbeService {

    public record OnvifProbeResult(boolean detected, List<String> attempts, String hint) {}

    private final int timeoutMs;
    private final int maxBodyBytes;

    public OnvifProbeService(int timeoutMs) {
        this(timeoutMs, 4096);
    }

    public OnvifProbeService(int timeoutMs, int maxBodyBytes) {
        this.timeoutMs = timeoutMs;
        this.maxBodyBytes = Math.max(1024, maxBodyBytes);
    }

    public OnvifProbeResult probeHost(String host) {
        return probe(host, new int[]{80, 443, 8080, 8000, 8443});
    }

    public OnvifProbeResult probe(String host, int[] ports) {
        String[] paths = {"/onvif/device_service", "/onvif/device_service?wsdl", "/onvif/device_service/", "/onvif/"};

        List<String> attempts = new ArrayList<>();
        for (int port : ports) {
            String proto = (port == 443 || port == 8443) ? "https" : "http";
            for (String path : paths) {
                String url = proto + "://" + host + ":" + port + path;
                ProbeAttempt attempt = tryUrl(url);
                attempts.add(attempt.summary);
                if (attempt.detected) {
                    return new OnvifProbeResult(true, attempts, "ONVIF likely available at " + url);
                }
            }
        }
        return new OnvifProbeResult(false, attempts, "ONVIF not detected (heuristic)");
    }

    private ProbeAttempt tryUrl(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setInstanceFollowRedirects(true);
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Anibus/1.0");

            int code = conn.getResponseCode();
            String server = conn.getHeaderField("Server");
            String www = conn.getHeaderField("WWW-Authenticate");
            String contentType = conn.getHeaderField("Content-Type");

            String body = readBody(conn, code < 400);
            String lc = (body == null ? "" : body.toLowerCase());
            boolean detected =
                    lc.contains("onvif") ||
                    (contentType != null && contentType.toLowerCase().contains("wsdl")) ||
                    (www != null && www.toLowerCase().contains("onvif")) ||
                    (server != null && server.toLowerCase().contains("onvif")) ||
                    (code == 401 && (url.toLowerCase().contains("/onvif/") || url.toLowerCase().contains("device_service")));

            String summary = url + " -> " + code +
                    (contentType != null ? (" | " + contentType) : "") +
                    (server != null ? (" | Server=" + server) : "");
            conn.disconnect();
            return new ProbeAttempt(detected, summary);
        } catch (Exception e) {
            return new ProbeAttempt(false, url + " -> error: " + e.getClass().getSimpleName());
        }
    }

    private String readBody(HttpURLConnection conn, boolean okStream) throws IOException {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                okStream ? conn.getInputStream() : conn.getErrorStream(), StandardCharsets.UTF_8))) {
            if (in == null) return null;
            StringBuilder sb = new StringBuilder();
            String line;
            int total = 0;
            while ((line = in.readLine()) != null && total < maxBodyBytes) {
                sb.append(line).append('\n');
                total += line.length();
            }
            return sb.toString();
        }
    }

    private record ProbeAttempt(boolean detected, String summary) {}
}
