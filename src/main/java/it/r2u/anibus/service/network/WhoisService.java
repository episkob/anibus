package it.r2u.anibus.service.network;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WHOIS lookup client with RDAP fallback and field normalisation.
 *
 * <p>Strategy:
 * <ol>
 *   <li>Query the IANA root WHOIS → find authoritative server → query it.</li>
 *   <li>If WHOIS fails or returns no meaningful data, fall back to the RDAP
 *       bootstrap service ({@code https://rdap.org/…}) and parse the JSON
 *       response manually (no external library needed).</li>
 * </ol>
 * Normalized fields extracted: registrar, registrant, abuse email,
 * name-servers, created date, expiry date.
 */
public class WhoisService {

    private static final String ROOT_WHOIS   = "whois.iana.org";
    private static final int    WHOIS_PORT   = 43;
    private static final int    TIMEOUT_MS   = 8000;
    private static final int    RDAP_TIMEOUT = 6000;

    // ── Result type ───────────────────────────────────────────────────────────

    /**
     * WHOIS/RDAP lookup result.
     *
     * @param query         original query string
     * @param server        authoritative WHOIS server that was queried (may be null for RDAP-only)
     * @param rawResponse   full raw WHOIS response
     * @param success       false if both WHOIS and RDAP failed
     * @param rdapUsed      true if the RDAP fallback was used
     * @param normalized    key → value map of extracted fields (registrar, expiry, …)
     */
    public record WhoisResult(
        String              query,
        String              server,
        String              rawResponse,
        boolean             success,
        boolean             rdapUsed,
        Map<String, String> normalized
    ) {}

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Performs a WHOIS lookup for the given domain or IP, with RDAP fallback.
     *
     * @param query Domain name or IP address
     * @return WhoisResult with raw response and normalised fields
     */
    public WhoisResult lookup(String query) {
        if (query == null || query.isBlank()) {
            return fail(query, null, "Empty query", false);
        }
        String target = query.trim().toLowerCase();

        // Step 1 – WHOIS
        String authServer = findAuthoritativeServer(target);
        if (authServer == null) authServer = ROOT_WHOIS;
        String whoisResp = queryWhoisServer(authServer, target);

        if (!isEmpty(whoisResp)) {
            Map<String, String> norm = normalizeWhois(whoisResp);
            return new WhoisResult(target, authServer, whoisResp, true, false, norm);
        }

        // Step 2 – RDAP fallback
        String rdapResp = rdapLookup(target);
        if (!isEmpty(rdapResp)) {
            Map<String, String> norm = normalizeRdap(rdapResp);
            return new WhoisResult(target, authServer, rdapResp, true, true, norm);
        }

        return fail(target, authServer, "No response from WHOIS or RDAP", false);
    }

    // ── WHOIS ─────────────────────────────────────────────────────────────────

    private String findAuthoritativeServer(String query) {
        // IPs / IPv6 go straight to root
        if (query.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") || query.contains(":")) {
            return ROOT_WHOIS;
        }
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
                    if (sb.length() > 64 * 1024) break;
                }
            }
            return sb.toString().isBlank() ? null : sb.toString();
        } catch (IOException e) {
            return null;
        }
    }

    // ── RDAP ─────────────────────────────────────────────────────────────────

    /**
     * Queries the RDAP bootstrap at rdap.org for the domain or IP.
     *
     * @param target domain or IP
     * @return raw JSON response string, or null on failure
     */
    String rdapLookup(String target) {
        String url = buildRdapUrl(target);
        if (url == null) return null;
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(RDAP_TIMEOUT);
            conn.setReadTimeout(RDAP_TIMEOUT);
            conn.setRequestProperty("Accept", "application/rdap+json, application/json");
            conn.setRequestProperty("User-Agent", "Anibus-RDAP/1.0");
            int code = conn.getResponseCode();
            if (code < 200 || code >= 300) return null;
            return new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    private String buildRdapUrl(String target) {
        try {
            if (target.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") || target.contains(":")) {
                return "https://rdap.org/ip/" + target;
            }
            return "https://rdap.org/domain/" + target;
        } catch (Exception e) {
            return null;
        }
    }

    // ── Normalisation ────────────────────────────────────────────────────────

    private static final String[][] WHOIS_FIELDS = {
        {"registrar",  "(?i)^\\s*Registrar:\\s*(.+)"},
        {"registrar",  "(?i)^\\s*registrar-name:\\s*(.+)"},
        {"registrant", "(?i)^\\s*Registrant Organization:\\s*(.+)"},
        {"registrant", "(?i)^\\s*registrant-org:\\s*(.+)"},
        {"abuse",      "(?i)^\\s*Registrar Abuse Contact Email:\\s*(.+)"},
        {"abuse",      "(?i)^\\s*abuse-mailbox:\\s*(.+)"},
        {"nameserver", "(?i)^\\s*Name Server:\\s*(.+)"},
        {"nameserver", "(?i)^\\s*nserver:\\s*(.+)"},
        {"created",    "(?i)^\\s*Creation Date:\\s*(.+)"},
        {"created",    "(?i)^\\s*created:\\s*(.+)"},
        {"expires",    "(?i)^\\s*Registry Expiry Date:\\s*(.+)"},
        {"expires",    "(?i)^\\s*expire[sd]?:\\s*(.+)"},
        {"updated",    "(?i)^\\s*Updated Date:\\s*(.+)"},
        {"updated",    "(?i)^\\s*last-modified:\\s*(.+)"},
    };

    private Map<String, String> normalizeWhois(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null) return out;
        for (String line : raw.split("\n")) {
            if (line.startsWith("%") || line.startsWith("#")) continue;
            for (String[] fp : WHOIS_FIELDS) {
                String key = fp[0];
                if ("nameserver".equals(key)) {
                    // Collect all name servers (append)
                    Matcher m = Pattern.compile(fp[1]).matcher(line);
                    if (m.find()) {
                        String v = m.group(1).trim().toLowerCase();
                        if (!v.isBlank()) {
                            String existing = out.get("nameserver");
                            out.put("nameserver",
                                existing == null ? v : existing + ", " + v);
                        }
                    }
                } else {
                    if (!out.containsKey(key)) {
                        Matcher m = Pattern.compile(fp[1]).matcher(line);
                        if (m.find()) {
                            String v = m.group(1).trim();
                            if (!v.isBlank()) out.put(key, v);
                        }
                    }
                }
            }
        }
        return out;
    }

    private Map<String, String> normalizeRdap(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        if (json == null) return out;
        putJsonString(json, "\"fn\"",             out, "registrant");
        putJsonString(json, "\"registrarName\"",  out, "registrar");
        // Abuse contact — look inside "links" or "vcardArray"
        Matcher abuse = Pattern.compile("\"abuse\".*?\"email\"\\s*:\\s*\"([^\"]+)\"")
            .matcher(json.replace("\n", " "));
        if (abuse.find()) out.put("abuse", abuse.group(1));
        // Date fields
        putJsonString(json, "\"registrationDate\"", out, "created");
        putJsonString(json, "\"expirationDate\"",   out, "expires");
        putJsonString(json, "\"lastChangedDate\"",  out, "updated");
        // Nameservers from "nameservers": [{"ldhName":"ns1.example.com"}...]
        Matcher ns = Pattern.compile("\"ldhName\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        StringBuilder servers = new StringBuilder();
        while (ns.find()) {
            if (!servers.isEmpty()) servers.append(", ");
            servers.append(ns.group(1).toLowerCase());
        }
        if (!servers.isEmpty()) out.put("nameserver", servers.toString());
        return out;
    }

    private void putJsonString(String json, String jsonKey, Map<String, String> out, String outKey) {
        if (out.containsKey(outKey)) return;
        Matcher m = Pattern.compile(Pattern.quote(jsonKey) + "\\s*:\\s*\"([^\"]+)\"")
            .matcher(json.replace("\n", " "));
        if (m.find()) out.put(outKey, m.group(1));
    }

    // ── Report ────────────────────────────────────────────────────────────────

    public static String formatReport(WhoisResult result) {
        StringBuilder sb = new StringBuilder("=== WHOIS");
        if (result.rdapUsed()) sb.append("/RDAP");
        sb.append(": ").append(result.query()).append(" ===\n");

        if (!result.success()) {
            sb.append("  Error: ").append(result.rawResponse()).append("\n");
            return sb.toString();
        }
        if (result.server() != null)
            sb.append("  Server: ").append(result.server())
              .append(result.rdapUsed() ? " [RDAP fallback]" : "").append("\n");

        // Normalized section
        Map<String, String> norm = result.normalized();
        if (!norm.isEmpty()) {
            sb.append("\n  ── Normalized fields ──────────────────────────────────────\n");
            Map<String, String> labels = new LinkedHashMap<>();
            labels.put("registrar",  "Registrar  ");
            labels.put("registrant", "Registrant ");
            labels.put("abuse",      "Abuse email");
            labels.put("nameserver", "Name server");
            labels.put("created",    "Created    ");
            labels.put("expires",    "Expires    ");
            labels.put("updated",    "Updated    ");
            labels.forEach((k, label) -> {
                if (norm.containsKey(k))
                    sb.append("  ").append(label).append(": ").append(norm.get(k)).append("\n");
            });
        }

        // Raw response
        sb.append("\n  ── Raw response ───────────────────────────────────────────\n");
        for (String line : result.rawResponse().split("\n")) {
            if (!line.startsWith("%") && !line.startsWith(">>>")) {
                sb.append("  ").append(line).append("\n");
            }
        }
        return sb.toString();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean isEmpty(String s) {
        return s == null || s.isBlank();
    }

    private WhoisResult fail(String query, String server, String msg, boolean rdap) {
        return new WhoisResult(query, server, msg, false, rdap, Map.of());
    }
}

