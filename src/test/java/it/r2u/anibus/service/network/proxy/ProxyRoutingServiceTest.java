package it.r2u.anibus.service.network.proxy;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ProxyRoutingServiceTest {

    @Test
    void publicGuardsReturnSafeDefaultsWhenNotInitialized() {
        ProxyRoutingService service = new ProxyRoutingService();

        assertTrue(service.selectProxy("8.8.8.8").isEmpty());
        assertTrue(service.selectStableProxy("8.8.8.8").isEmpty());
        assertEquals(0, service.enableOnionFallback());
        assertEquals(0, service.enableOnionFallback(false, false));
        assertFalse(service.isReady());
        assertEquals(0, service.poolSize());
    }

    @Test
    void failureAndSuccessFlowManageQuarantineState() throws Exception {
        ProxyRoutingService service = new ProxyRoutingService();
        ProxyNode node = new ProxyNode("127.0.0.1", 8080, ProxyType.HTTP, "DE", 10);

        Method registerFailure = method(ProxyRoutingService.class, "registerFailure", ProxyNode.class);
        Method registerSuccess = method(ProxyRoutingService.class, "registerSuccess", ProxyNode.class);

        registerFailure.invoke(service, node);
        registerFailure.invoke(service, node);

        Map<String, Integer> countryStreak = mapField(service, "countryFailureStreak");
        Map<String, Integer> endpointStreak = mapField(service, "endpointFailureStreak");
        Set<String> quarantined = setField(service, "quarantinedCountries");

        assertEquals(2, countryStreak.get("DE"));
        assertEquals(2, endpointStreak.get("127.0.0.1:8080:HTTP"));
        assertFalse(quarantined.contains("DE"));

        registerFailure.invoke(service, node);
        assertEquals(3, countryStreak.get("DE"));
        assertTrue(quarantined.contains("DE"));

        registerSuccess.invoke(service, node);
        registerSuccess.invoke(service, node);
        registerSuccess.invoke(service, node);

        assertFalse(countryStreak.containsKey("DE"));
        assertFalse(endpointStreak.containsKey("127.0.0.1:8080:HTTP"));
        assertFalse(quarantined.contains("DE"));
    }

    @Test
    void resetCountryQuarantineClearsInternalCounters() throws Exception {
        ProxyRoutingService service = new ProxyRoutingService();
        ProxyNode node = new ProxyNode("127.0.0.1", 9000, ProxyType.SOCKS5, "FR", 15);

        Method registerFailure = method(ProxyRoutingService.class, "registerFailure", ProxyNode.class);
        registerFailure.invoke(service, node);
        registerFailure.invoke(service, node);
        registerFailure.invoke(service, node);

        Map<String, Integer> countryStreak = mapField(service, "countryFailureStreak");
        Map<String, Integer> endpointStreak = mapField(service, "endpointFailureStreak");
        Set<String> quarantined = setField(service, "quarantinedCountries");

        assertFalse(countryStreak.isEmpty());
        assertFalse(endpointStreak.isEmpty());
        assertFalse(quarantined.isEmpty());

        service.resetCountryQuarantine();

        assertTrue(countryStreak.isEmpty());
        assertTrue(endpointStreak.isEmpty());
        assertTrue(quarantined.isEmpty());
    }

    @Test
    void readinessDependsOnInitializedFlagAndPoolSize() throws Exception {
        ProxyRoutingService service = new ProxyRoutingService();
        setField(service, "initialized", true);

        assertFalse(service.isReady());

        ProxyPool pool = (ProxyPool) field(ProxyRoutingService.class, "pool").get(service);
        pool.add(new ProxyNode("10.0.0.1", 8080, ProxyType.HTTP, "XX", 5));

        assertEquals(1, service.poolSize());
        assertTrue(service.isReady());
        assertEquals(1, service.allProxies().size());
    }

    @Test
    void customizationApiUpdatesSelectionPolicyAndMode() {
        ProxyRoutingService service = new ProxyRoutingService();

        service.setAllowedTypes(Set.of(ProxyType.SOCKS5));
        service.setBlockedCountries(Set.of("ru", "de"));
        service.setPreferredCountries(List.of("FR", "NL"));
        service.setMaxLatencyMs(250);
        service.setPreferUnknownCountryFallback(false);
        service.setAllowRestrictedSameCountry(true);
        service.setRotationMode(ProxyRotationMode.BALANCED);

        ProxySelectionPolicy policy = service.getSelectionPolicy();
        assertEquals(Set.of(ProxyType.SOCKS5), policy.allowedTypes());
        assertEquals(Set.of("RU", "DE"), policy.blockedCountries());
        assertEquals(List.of("FR", "NL"), policy.preferredCountries());
        assertEquals(250, policy.maxLatencyMs());
        assertFalse(policy.preferUnknownCountryFallback());
        assertTrue(policy.allowRestrictedSameCountry());
        assertEquals(ProxyRotationMode.BALANCED, service.getRotationMode());
    }

    @Test
    void healthReportReturnsMetricsForEachProxy() throws Exception {
        ProxyRoutingService service = new ProxyRoutingService();
        setField(service, "initialized", true);

        ProxyPool pool = (ProxyPool) field(ProxyRoutingService.class, "pool").get(service);
        ProxyNode de = new ProxyNode("10.0.0.1", 8080, ProxyType.HTTP, "DE", 20);
        ProxyNode fr = new ProxyNode("10.0.0.2", 8080, ProxyType.HTTP, "FR", 40);
        pool.add(de);
        pool.add(fr);

        Method registerFailure = method(ProxyRoutingService.class, "registerFailure", ProxyNode.class);
        registerFailure.invoke(service, de);
        registerFailure.invoke(service, de);

        List<ProxyRoutingService.ProxyHealth> report = service.healthReport();
        assertEquals(2, report.size());
        assertNotNull(report.getFirst().node());
        assertTrue(report.stream().anyMatch(item -> item.node().host().equals("10.0.0.1")
                && item.endpointFailures() >= 1));
    }

    private static Method method(Class<?> type, String name, Class<?>... params) throws Exception {
        Method m = type.getDeclaredMethod(name, params);
        m.setAccessible(true);
        return m;
    }

    private static Field field(Class<?> type, String name) throws Exception {
        Field f = type.getDeclaredField(name);
        f.setAccessible(true);
        return f;
    }

    private static void setField(Object instance, String name, Object value) throws Exception {
        field(instance.getClass(), name).set(instance, value);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Integer> mapField(Object instance, String name) throws Exception {
        return (Map<String, Integer>) field(instance.getClass(), name).get(instance);
    }

    @SuppressWarnings("unchecked")
    private static Set<String> setField(Object instance, String name) throws Exception {
        return (Set<String>) field(instance.getClass(), name).get(instance);
    }
}
