package it.r2u.anibus.service.network;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Reverse DNS & /24 neighbor expansion.
 *
 * Given a target IP (e.g. 10.0.1.42) this service:
 *   1. Derives the /24 base prefix (10.0.1.)
 *   2. Probes all 254 host addresses concurrently via virtual threads (ICMP reachability)
 *   3. For each live host performs a reverse DNS PTR lookup via {@link InetAddress#getCanonicalHostName()}
 *
 * Results are streamed back in real-time via a {@link Consumer} callback so the UI
 * can start displaying neighbors before the full subnet scan completes.
 */
public class ReverseDnsExpander {

    /** Milliseconds allowed for ICMP reachability check per host. */
    private static final int ICMP_TIMEOUT_MS = 800;

    // ─── Public result type ────────────────────────────────────────────────────

    public record NeighborInfo(String ip, String hostname, boolean isTarget) {

        /** True when the PTR record differs from the bare IP (i.e. a hostname was resolved). */
        public boolean hasHostname() {
            return hostname != null && !hostname.equals(ip);
        }

        /** Last octet as int, used for sorting. */
        int lastOctet() {
            try { return Integer.parseInt(ip.substring(ip.lastIndexOf('.') + 1)); }
            catch (NumberFormatException e) { return 0; }
        }

        @Override
        public String toString() {
            return hasHostname() ? ip + " → " + hostname : ip;
        }
    }

    // ─── Entry point ───────────────────────────────────────────────────────────

    /**
     * Expand the /24 subnet around {@code targetIp}.
     *
     * @param targetIp        resolved IPv4 address of the scan target
     * @param onNeighborFound called (from a virtual thread) each time a live neighbor
     *                        is discovered; may be {@code null}
     * @return sorted list of all discovered neighbors (includes the target itself)
     */
    public static List<NeighborInfo> expandSubnet(String targetIp,
                                                   Consumer<NeighborInfo> onNeighborFound) {
        String base = extractBase(targetIp);
        if (base == null) return List.of();

        CopyOnWriteArrayList<NeighborInfo> results = new CopyOnWriteArrayList<>();
        List<CompletableFuture<Void>> futures = new ArrayList<>(254);

        try (ExecutorService vtp = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 1; i <= 254; i++) {
                final String ip       = base + i;
                final boolean isTarget = ip.equals(targetIp);

                futures.add(CompletableFuture.runAsync(() -> {
                    try {
                        InetAddress addr = InetAddress.getByName(ip);
                        if (addr.isReachable(ICMP_TIMEOUT_MS)) {
                            // getCanonicalHostName() performs a PTR lookup when security manager
                            // allows it; falls back to the IP string on failure
                            String hostname = addr.getCanonicalHostName();
                            NeighborInfo info = new NeighborInfo(ip, hostname, isTarget);
                            results.add(info);
                            if (onNeighborFound != null) onNeighborFound.accept(info);
                        }
                    } catch (IOException | SecurityException ignored) {
                        // Host unreachable or DNS failure — silently skip
                    }
                }, vtp));
            }
            CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
        }

        List<NeighborInfo> sorted = new ArrayList<>(results);
        sorted.sort(Comparator.comparingInt(NeighborInfo::lastOctet));
        return sorted;
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Extracts the /24 base prefix from an IPv4 string.
     * <pre>"192.168.1.42" → "192.168.1."</pre>
     */
    static String extractBase(String ip) {
        if (ip == null) return null;
        int last = ip.lastIndexOf('.');
        if (last <= 0 || last >= ip.length() - 1) return null;
        return ip.substring(0, last + 1);
    }
}
