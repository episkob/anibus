package it.r2u.anibus.service.network.proxy;

import java.util.Set;

/**
 * Strategy interface for proxy source providers.
 * Implement to add new proxy sources (commercial, Tor, VPN, etc.).
 */
public interface ProxyProvider {
    /**
     * Fetch a raw set of proxy candidates.
     * Country codes may be "XX" (unknown) — they will be resolved after validation.
     */
    Set<ProxyNode> harvest();
}
