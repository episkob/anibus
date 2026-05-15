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
 * Also enriches with BGP data from Team Cymru (whois.cymru.com) for prefix,
 * allocated date, and registry info — all offline, no external APIs.
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

    /**
     * BGP-layer enrichment from Team Cymru: prefix, origin ASN, org, allocated date.
     *
     * @param prefix     CIDR prefix the IP belongs to (e.g. "203.0.113.0/24")
     * @param asn        origin ASN (numeric string)
     * @param org        organisation name from BGP registry
     * @param country    2-letter country code
     * @param registry   registry name (arin/ripe/apnic/…)
     * @param allocated  allocation date (may be empty)
     */
    public record BgpInfo(
        String prefix,
        String asn,
        String org,
        String country,
        String registry,
        String allocated
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

    /**
     * Queries Team Cymru's WHOIS service (whois.cymru.com) for BGP prefix and
     * origin ASN data. Uses the verbose origin query format:
     * {@code -v -f AS{asn}}.
     *
     * @param ip resolved IP address
     * @return BgpInfo, never null (fields may be empty on failure)
     */
    public BgpInfo bgpLookup(String ip) {
        if (ip == null || ip.isBlank()) return emptyBgp(ip);
        // Cymru bulk query: "begin\nnotruncate\nverbose\n{ip}\nend\n"
        String query = "begin\nnotruncate\nverbose\n" + ip.trim() + "\nend\n";
        String resp = whoisQuery("whois.cymru.com", query);
        if (resp == null || resp.isBlank()) return emptyBgp(ip);
        // Response header: "AS  | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
        // Then a data line like: "15169 | 8.8.8.8 | 8.8.8.0/24 | US | ARIN | 1992-12-01 | GOOGLE, US"
        for (String line : resp.split("\n")) {
            if (line.startsWith("AS") || line.startsWith("Bulk") || line.isBlank()) continue;
            String[] parts = line.split("\\|");
            if (parts.length < 5) continue;
            String asn       = parts[0].trim().replaceFirst("^AS", "");
            String prefix    = parts.length > 2 ? parts[2].trim() : "";
            String cc        = parts.length > 3 ? parts[3].trim() : "";
            String registry  = parts.length > 4 ? parts[4].trim() : "";
            String allocated = parts.length > 5 ? parts[5].trim() : "";
            String org       = parts.length > 6 ? parts[6].trim() : "";
            return new BgpInfo(prefix, asn, org, cc, registry, allocated);
        }
        return emptyBgp(ip);
    }

    private BgpInfo emptyBgp(String ip) {
        return new BgpInfo("", ip != null ? "" : "", "", "", "", "");
    }

    public static String formatReport(AsnInfo info) {
        return formatReport(info, null);
    }

    public static String formatReport(AsnInfo info, BgpInfo bgp) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("              ASN/BGP LOOKUP — ").append(info.ip()).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (info.asn() == null && info.netName() == null) {
            sb.append("  No ASN data found");
            if (info.description() != null) sb.append(": ").append(info.description());
            sb.append("\n");
        } else {
            if (info.asn()         != null) sb.append(String.format("  ASN        : AS%s\n", info.asn()));
            if (info.asnName()     != null) sb.append(String.format("  AS Name    : %s\n", info.asnName()));
            if (info.netName()     != null) sb.append(String.format("  Network    : %s\n", info.netName()));
            if (info.route()       != null) sb.append(String.format("  Route      : %s\n", info.route()));
            if (info.country()     != null) sb.append(String.format("  Country    : %s\n", info.country()));
            if (info.description() != null) sb.append(String.format("  Org/Descr  : %s\n", info.description()));
            if (info.rir()         != null) sb.append(String.format("  RIR Server : %s\n", info.rir()));
        }

        if (bgp != null && (!bgp.prefix().isBlank() || !bgp.org().isBlank())) {
            sb.append("\n  ── BGP Enrichment (Team Cymru) ─────────────────────────\n");
            if (!bgp.prefix().isBlank())    sb.append(String.format("  BGP Prefix : %s\n", bgp.prefix()));
            if (!bgp.asn().isBlank())       sb.append(String.format("  Origin ASN : AS%s\n", bgp.asn()));
            if (!bgp.org().isBlank())       sb.append(String.format("  Org (BGP)  : %s\n", bgp.org()));
            if (!bgp.country().isBlank())   sb.append(String.format("  Country    : %s\n", bgp.country()));
            if (!bgp.registry().isBlank())  sb.append(String.format("  Registry   : %s\n", bgp.registry()));
            if (!bgp.allocated().isBlank()) sb.append(String.format("  Allocated  : %s\n", bgp.allocated()));
        }
        return sb.toString();
    }
}
