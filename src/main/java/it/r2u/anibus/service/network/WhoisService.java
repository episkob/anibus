package it.r2u.anibus.service.network;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * WHOIS lookup client.
 * Queries the IANA root WHOIS server to find the authoritative WHOIS server
 * for the TLD, then queries it directly for the domain registration data.
 */
public class WhoisService {

    private static final String ROOT_WHOIS = "whois.iana.org";
    private static final int    WHOIS_PORT = 43;
    private static final int    TIMEOUT_MS = 8000;

    public record WhoisResult(
        String query,
        String server,
        String rawResponse,
        boolean success
    ) {}

    /**
     * Performs a WHOIS lookup for the given domain or IP.
     *
     * @param query Domain name or IP address
     * @return WhoisResult with raw WHOIS response
     */
    public WhoisResult lookup(String query) {
        if (query == null || query.isBlank()) {
            return new WhoisResult(query, null, "Empty query", false);
        }
        String target = query.trim().toLowerCase();

        // For domains: find authoritative server via IANA root
        String authServer = findAuthoritativeServer(target);
        if (authServer == null) authServer = ROOT_WHOIS;

        String response = queryWhoisServer(authServer, target);
        if (response == null) {
            return new WhoisResult(target, authServer, "No response from " + authServer, false);
        }
        return new WhoisResult(target, authServer, response, true);
    }

    private String findAuthoritativeServer(String query) {
        // IPs go straight to root
        if (query.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") || query.contains(":")) {
            return ROOT_WHOIS;
        }
        // Ask root for the referral
        String rootResponse = queryWhoisServer(ROOT_WHOIS, query);
        if (rootResponse == null) return null;

        for (String line : rootResponse.split("\n")) {
            String lc = line.toLowerCase().trim();
            if (lc.startsWith("whois:") || lc.startsWith("refer:")) {
                String server = line.substring(line.indexOf(':') + 1).trim();
                if (!server.isBlank()) return server;
            }
        }
        return null;
    }

    private String queryWhoisServer(String server, String query) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(server, WHOIS_PORT), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            socket.getOutputStream().write((query + "\r\n").getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();

            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line).append("\n");
                    if (sb.length() > 64 * 1024) break; // safety cap
                }
            }
            return sb.toString().isBlank() ? null : sb.toString();
        } catch (IOException e) {
            return null;
        }
    }

    public static String formatReport(WhoisResult result) {
        StringBuilder sb = new StringBuilder("=== WHOIS: ").append(result.query()).append(" ===\n");
        if (!result.success()) {
            sb.append("  Error: ").append(result.rawResponse()).append("\n");
            return sb.toString();
        }
        sb.append("  Server: ").append(result.server()).append("\n\n");
        // Print the raw response, stripping comment-only lines starting with %
        for (String line : result.rawResponse().split("\n")) {
            if (!line.startsWith("%")) {
                sb.append("  ").append(line).append("\n");
            }
        }
        return sb.toString();
    }
}
