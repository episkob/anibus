package it.r2u.anibus.service.network.proxy;

import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * User-tunable policy controlling proxy selection behavior.
 */
public record ProxySelectionPolicy(
        Set<ProxyType> allowedTypes,
        Set<String> blockedCountries,
        List<String> preferredCountries,
        long maxLatencyMs,
        boolean preferUnknownCountryFallback,
        boolean allowRestrictedSameCountry,
        int stableProbeAttempts
) {

    public ProxySelectionPolicy {
        Set<ProxyType> normalizedTypes =
                (allowedTypes == null || allowedTypes.isEmpty())
                        ? EnumSet.allOf(ProxyType.class)
                        : EnumSet.copyOf(allowedTypes);
        Set<String> normalizedBlocked = normalizeCountries(blockedCountries);
        List<String> normalizedPreferred = List.copyOf(normalizeCountries(preferredCountries));
        long normalizedLatency = maxLatencyMs <= 0 ? Long.MAX_VALUE : maxLatencyMs;
        int normalizedAttempts = stableProbeAttempts <= 0 ? 5 : Math.min(stableProbeAttempts, 20);

        allowedTypes = Set.copyOf(normalizedTypes);
        blockedCountries = Set.copyOf(normalizedBlocked);
        preferredCountries = normalizedPreferred;
        maxLatencyMs = normalizedLatency;
        stableProbeAttempts = normalizedAttempts;
    }

    public static ProxySelectionPolicy defaultPolicy() {
        return new ProxySelectionPolicy(
                EnumSet.allOf(ProxyType.class),
                Set.of(),
                List.of(),
                Long.MAX_VALUE,
                true,
                false,
                5
        );
    }

    private static Set<String> normalizeCountries(Iterable<String> countries) {
        Set<String> normalized = new LinkedHashSet<>();
        if (countries == null) {
            return normalized;
        }
        for (String country : countries) {
            if (country == null) continue;
            String value = country.trim().toUpperCase(Locale.ROOT);
            if (value.length() == 2) {
                normalized.add(value);
            }
        }
        return normalized;
    }
}
