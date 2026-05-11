package it.r2u.anibus.service.network;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ASN Lookup Service
 *
 * Queries the IANA/RIR WHOIS chain (whois.iana.org → RIPE/ARIN/APNIC/LACNIC/AFRINIC)
 * via raw TCP/43 to resolve AS number, ASN name, network prefix and country.
 * No external APIs required.
 */
public class AsnLookupService {

    public record AsnInfo(
        String ip,
        String asn,
        String asnName,
        String netName,
        String route,
        String country,
        String rir,
        String description
    ) {}

    private static final int WHOIS_PORT    = 43;
    private static final int TIMEOUT_MS    = 7000;

    // RIR endpoints by name
    private static final Map<String, String> RIRS = new LinkedHashMap<>();
    static {
        RIRS.put("ripe",    "whois.ripe.net");
        RIRS.put("arin",    "whois.arin.net");
        RIRS.put("apnic",   "whois.apnic.net");
        RIRS.put("lacnic",  "whois.lacnic.net");
        RIRS.put("afrinic", "whois.afrinic.net");
    }

    // Fields to extract from WHOIS responses
    private static final String[][] FIELD_PATTERNS = {
        {"asn",         "(?i)^aut-num:\\s*AS?(\\d+)"},
        {"asn",         "(?i)^ASNumber:\\s*(\\d+)"},
        {"asnName",     "(?i)^as-name:\\s*(.+)"},
        {"asnName",     "(?i)^ASName:\\s*(.+)"},
        {"netName",     "(?i)^netname:\\s*(.+)"},
        {"netName",     "(?i)^NetName:\\s*(.+)"},
        {"route",       "(?i)^route:\\s*(.+)"},
        {"route",       "(?i)^inet-num:\\s*(.+)"},
        {"country",     "(?i)^country:\\s*(.+)"},
        {"description", "(?i)^descr:\\s*(.+)"},
        {"description", "(?i)^OrgName:\\s*(.+)"},
        {"rir",         "(?i)^source:\\s*(.+)"},
    };

    public AsnInfo lookup(String ip) {
        // Step 1: query IANA to find responsible RIR
        String ianaResponse = whoisQuery("whois.iana.org", ip);
        String authServer = parseReferral(ianaResponse);

        // Step 2: query the authoritative RIR (or try all if IANA referral failed)
        String rir = null;
        String whoisResponse = null;
        if (authServer != null && !authServer.isBlank()) {
            whoisResponse = whoisQuery(authServer, ip);
            rir = authServer;
        }
        if (whoisResponse == null || isEmptyResponse(whoisResponse)) {
            // Try known RIRs directly
            for (Map.Entry<String, String> entry : RIRS.entrySet()) {
                whoisResponse = whoisQuery(entry.getValue(), ip);
                if (!isEmptyResponse(whoisResponse)) {
                    rir = entry.getValue();
                    break;
                }
            }
        }
        if (whoisResponse == null) {
            return new AsnInfo(ip, null, null, null, null, null, rir, "WHOIS lookup failed");
        }

        // Step 3: if we found a route entry with AS info, do a follow-up ASN query
        Map<String, String> fields = extractFields(whoisResponse);
        String asn = fields.get("asn");
        if (asn != null && !asn.isBlank()) {
            // Query same server for the ASN details
            String asnResponse = whoisQuery(rir != null ? rir : "whois.iana.org", "AS" + asn);
            if (!isEmptyResponse(asnResponse)) {
                Map<String, String> asnFields = extractFields(asnResponse);
                fields.putIfAbsent("asnName", asnFields.get("asnName"));
                fields.putIfAbsent("description", asnFields.get("description"));
            }
        }

        return new AsnInfo(
            ip,
            asn,
            fields.get("asnName"),
            fields.get("netName"),
            fields.get("route"),
            fields.get("country"),
            rir,
            fields.get("description")
        );
    }

    private String whoisQuery(String server, String query) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(server, WHOIS_PORT), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.US_ASCII);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            out.println(query);
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                sb.append(line).append("\n");
                if (sb.length() > 65536) break; // safety cap
            }
            return sb.toString();
        } catch (IOException ignored) {
            return null;
        }
    }

    private String parseReferral(String response) {
        if (response == null) return null;
        for (String line : response.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.toLowerCase().startsWith("refer:")) {
                return trimmed.substring(6).trim();
            }
            if (trimmed.toLowerCase().startsWith("whois:")) {
                return trimmed.substring(6).trim();
            }
        }
        return null;
    }

    private Map<String, String> extractFields(String response) {
        Map<String, String> result = new LinkedHashMap<>();
        if (response == null) return result;
        for (String line : response.split("\n")) {
            if (line.startsWith("%") || line.startsWith("#")) continue;
            for (String[] fp : FIELD_PATTERNS) {
                String fieldName = fp[0];
                if (result.containsKey(fieldName)) continue;
                Matcher m = Pattern.compile(fp[1]).matcher(line);
                if (m.find()) {
                    result.put(fieldName, m.group(1).trim());
                }
            }
        }
        return result;
    }

    private boolean isEmptyResponse(String response) {
        if (response == null || response.isBlank()) return true;
        long meaningful = response.lines()
            .filter(l -> !l.isBlank() && !l.startsWith("%") && !l.startsWith("#"))
            .count();
        return meaningful == 0;
    }

    public static String formatReport(AsnInfo info) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("              ASN LOOKUP — ").append(info.ip()).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (info.asn() == null && info.netName() == null) {
            sb.append("  No ASN data found");
            if (info.description() != null) sb.append(": ").append(info.description());
            sb.append("\n");
            return sb.toString();
        }
        if (info.asn()         != null) sb.append(String.format("  ASN        : AS%s\n", info.asn()));
        if (info.asnName()     != null) sb.append(String.format("  AS Name    : %s\n", info.asnName()));
        if (info.netName()     != null) sb.append(String.format("  Network    : %s\n", info.netName()));
        if (info.route()       != null) sb.append(String.format("  Route      : %s\n", info.route()));
        if (info.country()     != null) sb.append(String.format("  Country    : %s\n", info.country()));
        if (info.description() != null) sb.append(String.format("  Org/Descr  : %s\n", info.description()));
        if (info.rir()         != null) sb.append(String.format("  RIR Server : %s\n", info.rir()));
        return sb.toString();
    }
}
