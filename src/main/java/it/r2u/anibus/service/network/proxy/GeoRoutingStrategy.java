package it.r2u.anibus.service.network.proxy;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Selects the optimal proxy for a given target IP based on geographic proximity.
 *
 * <p>Selection order:
 * <ol>
 *   <li>Same-country proxy with lowest latency.</li>
 *   <li>Proxy from a regional neighbour country (lowest latency among neighbours).</li>
 *   <li>Any live proxy from the pool (global fallback).</li>
 * </ol>
 */
class GeoRoutingStrategy {

    private final ProxyPool pool;

    // Regional adjacency map (ISO 3166-1 alpha-2 codes)
    private static final Map<String, List<String>> NEIGHBORS = Map.ofEntries(
            Map.entry("IT", List.of("AT", "CH", "FR", "SI", "HR", "DE", "MT")),
            Map.entry("DE", List.of("AT", "CH", "FR", "NL", "BE", "PL", "DK", "CZ", "LU")),
            Map.entry("FR", List.of("ES", "BE", "CH", "IT", "DE", "LU", "AD", "MC")),
            Map.entry("ES", List.of("FR", "PT", "AD")),
            Map.entry("GB", List.of("IE", "FR", "DE", "NL", "BE")),
            Map.entry("NL", List.of("DE", "BE", "GB", "FR")),
            Map.entry("PL", List.of("DE", "CZ", "SK", "UA", "BY", "LT", "RU")),
            Map.entry("RU", List.of("UA", "BY", "FI", "PL", "EE", "LV", "LT", "KZ")),
            Map.entry("UA", List.of("RU", "PL", "BY", "RO", "MD", "SK", "HU")),
            Map.entry("US", List.of("CA", "MX")),
            Map.entry("CA", List.of("US")),
            Map.entry("BR", List.of("AR", "CL", "PE", "CO", "UY", "PY", "BO")),
            Map.entry("JP", List.of("KR", "CN", "TW")),
            Map.entry("KR", List.of("JP", "CN")),
            Map.entry("CN", List.of("JP", "KR", "HK", "TW", "SG", "RU")),
            Map.entry("SG", List.of("MY", "TH", "ID", "PH", "VN")),
            Map.entry("AU", List.of("NZ", "SG", "JP"))
    );

    GeoRoutingStrategy(ProxyPool pool) {
        this.pool = pool;
    }

    /**
     * Select the best proxy for a given target IP.
     *
     * @param targetIp IP address of the scan target
     * @return optimal ProxyNode, or empty if pool has no live proxies
     */
    Optional<ProxyNode> selectBest(String targetIp) {
        String targetCountry = resolveCountryCode(targetIp);
        return selectBestForCountry(targetCountry);
    }

    /**
     * Select best proxy for an explicit country code.
     * Exposed for unit testing and manual override.
     */
    Optional<ProxyNode> selectBestForCountry(String countryCode) {
        // 1. Same country
        Optional<ProxyNode> same = pool.bestByCountry(countryCode);
        if (same.isPresent()) return same;

        // 2. Neighbouring country — pick the fastest across all neighbours
        List<String> neighbors = NEIGHBORS.getOrDefault(countryCode, List.of());
        Optional<ProxyNode> neighbor = neighbors.stream()
                .map(pool::bestByCountry)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .min(java.util.Comparator.comparingLong(ProxyNode::latencyMs));
        if (neighbor.isPresent()) return neighbor;

        // 3. Global fallback — fastest from "XX" (unknown) or any country
        Optional<ProxyNode> unknown = pool.bestByCountry("XX");
        if (unknown.isPresent()) return unknown;

        return pool.bestOverall();
    }

    /**
     * Resolve the 2-letter ISO country code for a given IP via ip-api.com.
     * Returns "XX" on any error (no external dependency required for compilation).
     */
    private String resolveCountryCode(String ip) {
        try {
            java.net.URI uri = new java.net.URI(
                    "http://ip-api.com/json/" + ip + "?fields=countryCode");
            java.net.HttpURLConnection conn =
                    (java.net.HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(4_000);
            conn.setReadTimeout(4_000);
            conn.setRequestProperty("User-Agent", "Anibus-Scanner/1.8");

            if (conn.getResponseCode() == 200) {
                try (java.io.BufferedReader br = new java.io.BufferedReader(
                        new java.io.InputStreamReader(conn.getInputStream()))) {
                    String body = br.lines().reduce("", String::concat);
                    // Parse {"countryCode":"IT"} — regex is sufficient
                    java.util.regex.Matcher m = java.util.regex.Pattern
                            .compile("\"countryCode\"\\s*:\\s*\"([A-Z]{2})\"")
                            .matcher(body);
                    if (m.find()) return m.group(1);
                }
            }
            conn.disconnect();
        } catch (java.io.IOException | java.net.URISyntaxException ignored) {}
        return "XX";
    }

}
