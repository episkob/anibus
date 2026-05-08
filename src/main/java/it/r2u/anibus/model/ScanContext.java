package it.r2u.anibus.model;

import java.util.Optional;

import it.r2u.anibus.service.network.proxy.ProxyNode;

/**
 * Immutable scan context carrying all parameters for a single scan session.
 *
 * <p>Proxy state is embedded directly: if {@code proxyEnabled} is {@code false},
 * all network factories will fall back to direct connections transparently.
 *
 * <p>Usage:
 * <pre>
 *   // Direct scan
 *   ScanContext ctx = ScanContext.direct("192.168.1.1", new int[]{1, 1024}, 50);
 *
 *   // Proxy scan
 *   ScanContext ctx = ScanContext.withProxy("1.2.3.4", new int[]{1, 1024}, 50, proxyNode);
 *
 *   // Failover — swap proxy, keep everything else
 *   ScanContext next = ctx.withNewProxy(newProxy);
 * </pre>
 */
public record ScanContext(
        String           targetHost,
        int[]            portRange,
        int              threads,
        boolean          proxyEnabled,
        Optional<ProxyNode> activeProxy
) {
    // ── Factory methods ───────────────────────────────────────────────────────

    /** Create a direct (no proxy) scan context. */
    public static ScanContext direct(String targetHost, int[] portRange, int threads) {
        return new ScanContext(targetHost, portRange, threads, false, Optional.empty());
    }

    /** Create a proxy-enabled scan context. */
    public static ScanContext withProxy(
            String targetHost, int[] portRange, int threads, ProxyNode proxy) {
        return new ScanContext(targetHost, portRange, threads, true, Optional.of(proxy));
    }

    // ── Transition helpers ────────────────────────────────────────────────────

    /** Return a copy using a new proxy node (used for transparent failover). */
    public ScanContext withNewProxy(ProxyNode proxy) {
        return new ScanContext(targetHost, portRange, threads, true, Optional.of(proxy));
    }

    /** Return a copy with proxy disabled (fallback to direct). */
    public ScanContext withoutProxy() {
        return new ScanContext(targetHost, portRange, threads, false, Optional.empty());
    }

    // ── Convenience ───────────────────────────────────────────────────────────

    public int startPort() { return portRange != null && portRange.length >= 1 ? portRange[0] : 1; }
    public int endPort()   { return portRange != null && portRange.length >= 2 ? portRange[1] : 1024; }

    @Override
    public String toString() {
        String proxyStr = (proxyEnabled && activeProxy.isPresent())
                ? activeProxy.get().toString()
                : "direct";
        return String.format("ScanContext{target=%s, ports=%d-%d, threads=%d, proxy=%s}",
                targetHost, startPort(), endPort(), threads, proxyStr);
    }
}
