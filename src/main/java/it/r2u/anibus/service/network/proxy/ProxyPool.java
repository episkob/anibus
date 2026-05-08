package it.r2u.anibus.service.network.proxy;

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe proxy pool.
 * Internally organised as ConcurrentHashMap&lt;countryCode, Set&lt;ProxyNode&gt;&gt;.
 * Package-private — external code interacts only via ProxyRoutingService.
 */
class ProxyPool {

    private final ConcurrentHashMap<String, Set<ProxyNode>> pool = new ConcurrentHashMap<>();

    void add(ProxyNode node) {
        pool.computeIfAbsent(node.countryCode(),
                k -> ConcurrentHashMap.newKeySet()).add(node);
    }

    Set<ProxyNode> getByCountry(String countryCode) {
        return Collections.unmodifiableSet(
                pool.getOrDefault(countryCode, ConcurrentHashMap.newKeySet()));
    }

    Set<String> availableCountries() {
        return Collections.unmodifiableSet(pool.keySet());
    }

    /** Fastest live node for a given country, or empty. */
    Optional<ProxyNode> bestByCountry(String countryCode) {
        return getByCountry(countryCode).stream()
                .filter(ProxyNode::isAlive)
                .min(Comparator.comparingLong(ProxyNode::latencyMs));
    }

    /** Fastest live node across all countries. */
    Optional<ProxyNode> bestOverall() {
        return pool.values().stream()
                .flatMap(Collection::stream)
                .filter(ProxyNode::isAlive)
                .min(Comparator.comparingLong(ProxyNode::latencyMs));
    }

    void remove(ProxyNode node) {
        Set<ProxyNode> set = pool.get(node.countryCode());
        if (set != null) {
            set.remove(node);
            if (set.isEmpty()) pool.remove(node.countryCode());
        }
    }

    int totalSize() {
        return pool.values().stream().mapToInt(Set::size).sum();
    }

    /** Returns all proxies across all countries as a flat set. */
    Set<ProxyNode> allProxies() {
        Set<ProxyNode> all = ConcurrentHashMap.newKeySet();
        pool.values().forEach(all::addAll);
        return Collections.unmodifiableSet(all);
    }
}
