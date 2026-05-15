package it.r2u.anibus.service.network;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * GeoIP Map View — resolves a list of hostnames/IPs to country + ASN using
 * the existing {@link AsnLookupService} and presents a console "map" grouped
 * by country.
 *
 * <p>No external API is required: country data comes from RIR WHOIS responses.
 * The "map" is a structured text report sorted by country with per-host details.
 */
public class GeoIpService {

    private final AsnLookupService asnLookup;

    public GeoIpService() {
        this.asnLookup = new AsnLookupService();
    }

    public GeoIpService(AsnLookupService asnLookup) {
        this.asnLookup = asnLookup;
    }

    /**
     * Result for a single host.
     *
     * @param host    original input (hostname or IP)
     * @param ip      resolved IPv4/IPv6 address (may equal host if already an IP)
     * @param country 2-letter ISO code, "??" if unknown
     * @param asn     ASN string (without "AS" prefix), empty if unknown
     * @param org     organisation/description
     * @param prefix  BGP prefix (from Team Cymru enrichment)
     */
    public record GeoEntry(
        String host,
        String ip,
        String country,
        String asn,
        String org,
        String prefix
    ) {}

    /**
     * Resolves all hosts and returns one {@link GeoEntry} per host.
     *
     * @param hosts list of hostnames or IPs to resolve
     * @return results in input order
     */
    public List<GeoEntry> resolve(List<String> hosts) {
        List<GeoEntry> out = new ArrayList<>();
        for (String host : hosts) {
            if (host == null || host.isBlank()) continue;
            String ip = resolveIp(host);
            AsnLookupService.AsnInfo info = asnLookup.lookup(ip);
            AsnLookupService.BgpInfo bgp  = asnLookup.bgpLookup(ip);
            String country = pick(info.country(), bgp.country(), "??");
            String asn     = pick(info.asn(), bgp.asn(), "");
            String org     = pick(info.description(), info.asnName(), bgp.org(), "");
            String prefix  = bgp.prefix().isBlank() ? (info.route() != null ? info.route() : "") : bgp.prefix();
            out.add(new GeoEntry(host, ip, country, asn, org, prefix));
        }
        return out;
    }

    private String resolveIp(String host) {
        try {
            return InetAddress.getByName(host).getHostAddress();
        } catch (java.net.UnknownHostException e) {
            return host;
        }
    }

    private String pick(String... candidates) {
        for (String c : candidates) {
            if (c != null && !c.isBlank()) return c;
        }
        return "";
    }

    /**
     * Formats a geo-IP console "map": entries grouped by country, sorted by
     * country code, with summary bar chart showing relative node counts.
     */
    public static String formatReport(List<GeoEntry> entries, String targetHost) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== GEO-IP MAP VIEW");
        if (targetHost != null && !targetHost.isBlank()) sb.append(": ").append(targetHost);
        sb.append(" ===\n\n");

        if (entries.isEmpty()) {
            sb.append("  No hosts to display.\n");
            return sb.toString();
        }

        // Group by country
        Map<String, List<GeoEntry>> byCountry = new LinkedHashMap<>();
        entries.stream()
            .sorted(Comparator.comparing(GeoEntry::country))
            .forEach(e -> byCountry.computeIfAbsent(e.country(), k -> new ArrayList<>()).add(e));

        int max = byCountry.values().stream().mapToInt(List::size).max().orElse(1);

        sb.append(String.format("  %-6s  %-4s  %-30s  %s%n", "COUNT", "CC", "ORG (ASN)", "HOSTS"));
        sb.append("  ").append("─".repeat(72)).append("\n");

        for (Map.Entry<String, List<GeoEntry>> entry : byCountry.entrySet()) {
            String cc = entry.getKey();
            List<GeoEntry> group = entry.getValue();
            int count = group.size();
            // Simple ASCII bar proportional to max
            int barLen = Math.max(1, (count * 12) / max);
            String bar = "█".repeat(barLen);

            // Take first non-empty org for the group summary
            String repOrg = group.stream()
                .map(GeoEntry::org).filter(s -> !s.isBlank()).findFirst().orElse("");
            String repAsn = group.stream()
                .map(GeoEntry::asn).filter(s -> !s.isBlank()).findFirst().orElse("");
            String orgLabel = repOrg.isBlank() ? "" : repOrg;
            if (!repAsn.isBlank()) orgLabel += " (AS" + repAsn + ")";
            if (orgLabel.length() > 30) orgLabel = orgLabel.substring(0, 27) + "...";

            sb.append(String.format("  %-6d  %-4s  %-30s  %s%n",
                count, cc, orgLabel, bar));

            for (GeoEntry e : group) {
                String display = e.host().equals(e.ip()) ? e.ip() : e.host() + " → " + e.ip();
                String pfx = e.prefix().isBlank() ? "" : "  [" + e.prefix() + "]";
                sb.append(String.format("          %-40s%s%n", display, pfx));
            }
        }

        sb.append("\n  Total: ").append(entries.size()).append(" host(s) across ")
          .append(byCountry.size()).append(" country/countries.\n");
        return sb.toString();
    }
}
