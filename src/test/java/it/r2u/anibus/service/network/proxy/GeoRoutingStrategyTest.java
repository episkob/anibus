package it.r2u.anibus.service.network.proxy;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class GeoRoutingStrategyTest {

    @Test
    void prefersTransitCountriesForRestrictedTargets() {
        ProxyPool pool = new ProxyPool();
        ProxyNode ru = new ProxyNode("10.0.0.1", 8080, ProxyType.HTTP, "RU", 10);
        ProxyNode fi = new ProxyNode("10.0.0.2", 8080, ProxyType.HTTP, "FI", 40);
        pool.add(ru);
        pool.add(fi);

        GeoRoutingStrategy strategy = new GeoRoutingStrategy(pool);
        ProxyNode selected = strategy.selectBestForCountry("RU", Set.of()).orElseThrow();

        assertEquals("FI", selected.countryCode());
    }

    @Test
    void fallsBackToFastestNeighborWhenNoSameCountry() {
        ProxyPool pool = new ProxyPool();
        pool.add(new ProxyNode("10.1.0.1", 8080, ProxyType.HTTP, "AT", 25));
        pool.add(new ProxyNode("10.1.0.2", 8080, ProxyType.HTTP, "FR", 50));

        GeoRoutingStrategy strategy = new GeoRoutingStrategy(pool);
        ProxyNode selected = strategy.selectBestForCountry("DE", Set.of()).orElseThrow();

        assertEquals("AT", selected.countryCode());
        assertEquals(25, selected.latencyMs());
    }

    @Test
    void usesUnknownThenOverallFallbackRespectingExclusions() {
        ProxyPool pool = new ProxyPool();
        pool.add(new ProxyNode("10.2.0.1", 8080, ProxyType.HTTP, "XX", 70));
        pool.add(new ProxyNode("10.2.0.2", 8080, ProxyType.HTTP, "BR", 15));

        GeoRoutingStrategy strategy = new GeoRoutingStrategy(pool);

        ProxyNode unknownPreferred = strategy.selectBestForCountry("ZZ", Set.of()).orElseThrow();
        assertEquals("XX", unknownPreferred.countryCode());

        ProxyNode overallFallback = strategy.selectBestForCountry("ZZ", Set.of("XX")).orElseThrow();
        assertEquals("BR", overallFallback.countryCode());
        assertEquals(15, overallFallback.latencyMs());

        assertTrue(strategy.selectBestForCountry("ZZ", Set.of("XX", "BR")).isEmpty());
    }

    @Test
    void policyCanPreferSpecificCountriesAndFilterByTypeAndLatency() {
        ProxyPool pool = new ProxyPool();
        pool.add(new ProxyNode("10.3.0.1", 8080, ProxyType.HTTP, "DE", 30));
        pool.add(new ProxyNode("10.3.0.2", 1080, ProxyType.SOCKS5, "FR", 35));
        pool.add(new ProxyNode("10.3.0.3", 8080, ProxyType.HTTP, "FR", 120));

        GeoRoutingStrategy strategy = new GeoRoutingStrategy(pool);
        ProxySelectionPolicy policy = new ProxySelectionPolicy(
                Set.of(ProxyType.SOCKS5),
                Set.of("DE"),
                List.of("FR"),
                80,
                true,
                false,
                5);

        ProxyNode selected = strategy.selectBestForCountry("DE", Set.of(), policy).orElseThrow();
        assertEquals("FR", selected.countryCode());
        assertEquals(ProxyType.SOCKS5, selected.type());
        assertEquals(35, selected.latencyMs());
    }
}
