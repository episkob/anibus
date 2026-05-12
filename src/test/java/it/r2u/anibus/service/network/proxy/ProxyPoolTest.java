package it.r2u.anibus.service.network.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ProxyPoolTest {

    @Test
    void keepsFastestAlivePerCountryAndRemovesEmptyBuckets() {
        ProxyPool pool = new ProxyPool();
        ProxyNode dead = new ProxyNode("1.1.1.1", 8080, ProxyType.HTTP, "DE", -1);
        ProxyNode slow = new ProxyNode("1.1.1.2", 8080, ProxyType.HTTP, "DE", 120);
        ProxyNode fast = new ProxyNode("1.1.1.3", 8080, ProxyType.HTTP, "DE", 30);

        pool.add(dead);
        pool.add(slow);
        pool.add(fast);

        assertEquals(3, pool.totalSize());
        assertTrue(pool.bestByCountry("DE").isPresent());
        assertEquals(fast, pool.bestByCountry("DE").orElseThrow());

        pool.remove(dead);
        pool.remove(slow);
        pool.remove(fast);

        assertEquals(0, pool.totalSize());
        assertFalse(pool.availableCountries().contains("DE"));
    }

    @Test
    void exposesReadOnlyViewsForCountryAndAllProxies() {
        ProxyPool pool = new ProxyPool();
        ProxyNode node = new ProxyNode("2.2.2.2", 3128, ProxyType.SOCKS5, "XX", 40);
        pool.add(node);

        UnsupportedOperationException countryViewReadOnly =
                assertThrows(UnsupportedOperationException.class, () -> pool.getByCountry("XX").add(node));
        assertTrue(countryViewReadOnly.getClass().getSimpleName().contains("Unsupported"));

        UnsupportedOperationException allViewReadOnly =
                assertThrows(UnsupportedOperationException.class, () -> pool.allProxies().clear());
        assertTrue(allViewReadOnly.getClass().getSimpleName().contains("Unsupported"));
    }
}
