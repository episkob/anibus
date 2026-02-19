package it.r2u.anibus;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Grabs service banners from open ports.
 * Uses an HTTP HEAD probe for web ports; reads the raw greeting otherwise.
 */
public class BannerGrabber {

    private final int timeout;

    public BannerGrabber(int timeout) {
        this.timeout = timeout;
    }

    public String grab(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(timeout);
            socket.connect(new InetSocketAddress(host, port), timeout);
            return isHttpPort(port) ? grabHttpHeaders(socket, host) : grabGreeting(socket);
        } catch (IOException ignored) {
            return "";
        }
    }

    private String grabGreeting(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] buffer = new byte[2048];
        int read = in.read(buffer, 0, buffer.length);
        return read > 0 ? sanitize(new String(buffer, 0, read, StandardCharsets.UTF_8)) : "";
    }

    private String grabHttpHeaders(Socket socket, String host) throws IOException {
        OutputStream out = socket.getOutputStream();
        String request = "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.UTF_8));
        out.flush();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        int lineCount = 0;
        while ((line = reader.readLine()) != null && lineCount < 20) {
            sb.append(line).append("  ");
            lineCount++;
        }
        return sanitize(sb.toString());
    }

    private boolean isHttpPort(int port) {
        return port == 80 || port == 443 || port == 8080 || port == 8443
                || port == 8000 || port == 8888 || port == 3000 || port == 9090;
    }

    private String sanitize(String s) {
        if (s == null) return "";
        return s.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "")
                .replaceAll("\\s+", " ")
                .trim();
    }
}
