package it.r2u.anibus.service.network.proxy;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

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

            /**
             * Regions where direct same-country proxy usage is often unstable.
             * For these targets, prefer transit countries first.
             */
            private static final Set<String> RESTRICTED_TARGETS = Set.of("RU");

            /** Preferred transit countries for restricted targets (ordered). */
            private static final Map<String, List<String>> TRANSIT_ROUTES = Map.of(
                "RU", List.of("FI", "EE", "LV", "LT", "PL", "DE", "NL", "SE", "NO", "TR", "GE", "KZ")
            );

    GeoRoutingStrategy(ProxyPool pool) {
        this.pool = pool;
    }

    Optional<ProxyNode> selectBest(String targetIp,
                                   Set<String> excludedCountries,
                                   ProxySelectionPolicy policy) {
        String targetCountry = resolveCountryCode(targetIp);
        return selectBestForCountry(targetCountry, excludedCountries, policy);
    }

    /**
     * Select best proxy for an explicit country code.
     * Exposed for unit testing and manual override.
     */
    Optional<ProxyNode> selectBestForCountry(String countryCode, Set<String> excludedCountries) {
        return selectBestForCountry(countryCode, excludedCountries, ProxySelectionPolicy.defaultPolicy());
        }

        Optional<ProxyNode> selectBestForCountry(String countryCode,
                             Set<String> excludedCountries,
                             ProxySelectionPolicy policy) {
        ProxySelectionPolicy effectivePolicy =
            policy != null ? policy : ProxySelectionPolicy.defaultPolicy();
        Set<String> excluded = excludedCountries != null ? excludedCountries : Set.of();
        Set<String> blocked = effectivePolicy.blockedCountries();
        Predicate<ProxyNode> allowed = node -> isAllowed(node, excluded, blocked, effectivePolicy);

        Optional<ProxyNode> preferred = bestFromCountries(
            effectivePolicy.preferredCountries(),
            allowed);
        if (preferred.isPresent()) return preferred;

        // 0. Transit preference for restricted regions
        if (RESTRICTED_TARGETS.contains(countryCode) && !effectivePolicy.allowRestrictedSameCountry()) {
            Optional<ProxyNode> transit = bestFromCountries(
                    TRANSIT_ROUTES.getOrDefault(countryCode, List.of()),
                allowed);
            if (transit.isPresent()) return transit;
        }

        // 1. Same country
        if ((!RESTRICTED_TARGETS.contains(countryCode) || effectivePolicy.allowRestrictedSameCountry())
            && !excluded.contains(countryCode)
            && !blocked.contains(countryCode)) {
            Optional<ProxyNode> same = pool.getByCountry(countryCode).stream()
                .filter(allowed)
                .min(java.util.Comparator.comparingLong(ProxyNode::latencyMs));
            if (same.isPresent()) return same;
        }

        // 2. Neighbouring country — pick the fastest across all neighbours
        List<String> neighbors = NEIGHBORS.getOrDefault(countryCode, List.of());
        Optional<ProxyNode> neighbor = bestFromCountries(neighbors, allowed);
        if (neighbor.isPresent()) return neighbor;

        // 3. Global fallback — fastest from "XX" (unknown) or any country
        Optional<ProxyNode> unknown = (!effectivePolicy.preferUnknownCountryFallback()
                || excluded.contains("XX")
                || blocked.contains("XX"))
                ? Optional.empty()
                : pool.getByCountry("XX").stream()
                .filter(allowed)
                .min(java.util.Comparator.comparingLong(ProxyNode::latencyMs));
        if (unknown.isPresent()) return unknown;

        return bestOverallExcluding(allowed);
    }

    private Optional<ProxyNode> bestFromCountries(List<String> countries, Predicate<ProxyNode> allowed) {
        return countries.stream()
                .map(pool::getByCountry)
                .flatMap(Set::stream)
                .filter(allowed)
                .min(java.util.Comparator.comparingLong(ProxyNode::latencyMs));
    }

    private Optional<ProxyNode> bestOverallExcluding(Predicate<ProxyNode> allowed) {
        return pool.availableCountries().stream()
                .map(pool::getByCountry)
                .flatMap(Set::stream)
                .filter(allowed)
                .min(java.util.Comparator.comparingLong(ProxyNode::latencyMs));
    }

    private boolean isAllowed(ProxyNode node,
                              Set<String> excluded,
                              Set<String> blocked,
                              ProxySelectionPolicy policy) {
        if (!node.isAlive()) return false;
        if (excluded.contains(node.countryCode())) return false;
        if (blocked.contains(node.countryCode())) return false;
        if (!policy.allowedTypes().contains(node.type())) return false;
        return node.latencyMs() <= policy.maxLatencyMs();
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
