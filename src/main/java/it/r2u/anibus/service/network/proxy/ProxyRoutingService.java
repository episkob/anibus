package it.r2u.anibus.service.network.proxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Main facade for the geo-aware proxy routing subsystem.
 *
 * <p>Lifecycle:
 * <pre>
 *   ProxyRoutingService svc = new ProxyRoutingService();
 *   svc.initializeAsync().thenRun(() -> svc.selectProxy(targetIp));
 * </pre>
 *
 * <p>All heavy I/O (harvesting + validation) runs on a background thread.
 * The caller is notified via the returned {@link CompletableFuture}.
 *
 * <p>Automatic failover: if a proxy dies mid-scan, call {@link #failover(ProxyNode, String)}
 * to remove the dead node and get the next best candidate from the same geo-zone.
 */
public class ProxyRoutingService {

    private static final Logger LOG = Logger.getLogger(ProxyRoutingService.class.getName());

    private final ProxyPool           pool      = new ProxyPool();
    private final ProxyHarvester      harvester = new ProxyHarvester();
    private final ReactiveValidator   validator = new ReactiveValidator();
    private final GeoRoutingStrategy  routing   = new GeoRoutingStrategy(pool);
    private final ProxyStore          store     = new ProxyStore();
    private final ConcurrentHashMap<String, Integer> countryFailureStreak = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> endpointFailureStreak = new ConcurrentHashMap<>();
    private final Set<String> quarantinedCountries = ConcurrentHashMap.newKeySet();

    private static final int COUNTRY_FAILURE_THRESHOLD = 3;
    private static final int ENDPOINT_FAILURE_THRESHOLD = 2;
    private static final double BALANCED_HEALTH_FLOOR = 55.0;

    private volatile boolean initialized = false;
    private volatile boolean cancelled   = false;
    private volatile ProxySelectionPolicy selectionPolicy = ProxySelectionPolicy.defaultPolicy();
    private volatile ProxyRotationMode rotationMode = ProxyRotationMode.STABLE;
    private Consumer<String>  logCallback      = null;
    private Consumer<int[]>   statsCallback    = null;
    private Consumer<Double>  progressCallback = null;

    /** Request cancellation of an in-progress initialization. */
    public void cancel() { cancelled = true; }

    public void setLogCallback(Consumer<String> callback)      { this.logCallback      = callback; }
    public void setStatsCallback(Consumer<int[]> callback)    { this.statsCallback    = callback; }
    public void setProgressCallback(Consumer<Double> callback) { this.progressCallback = callback; }

        public ProxySelectionPolicy getSelectionPolicy() { return selectionPolicy; }

        public void configureSelectionPolicy(ProxySelectionPolicy policy) {
        selectionPolicy = policy != null ? policy : ProxySelectionPolicy.defaultPolicy();
        emit("Proxy selection policy updated: types=" + selectionPolicy.allowedTypes()
            + ", blocked=" + selectionPolicy.blockedCountries().size()
            + ", preferred=" + selectionPolicy.preferredCountries().size()
            + ", maxLatency="
            + (selectionPolicy.maxLatencyMs() == Long.MAX_VALUE
                ? "INF" : selectionPolicy.maxLatencyMs() + "ms")
            + ", attempts=" + selectionPolicy.stableProbeAttempts());
        }

        public void setAllowedTypes(Set<ProxyType> types) {
        Set<ProxyType> safeTypes = (types == null || types.isEmpty())
            ? EnumSet.allOf(ProxyType.class)
            : EnumSet.copyOf(types);
        configureSelectionPolicy(new ProxySelectionPolicy(
            safeTypes,
            selectionPolicy.blockedCountries(),
            selectionPolicy.preferredCountries(),
            selectionPolicy.maxLatencyMs(),
            selectionPolicy.preferUnknownCountryFallback(),
            selectionPolicy.allowRestrictedSameCountry(),
            selectionPolicy.stableProbeAttempts()));
        }

        public void setBlockedCountries(Set<String> blockedCountries) {
        configureSelectionPolicy(new ProxySelectionPolicy(
            selectionPolicy.allowedTypes(),
            blockedCountries,
            selectionPolicy.preferredCountries(),
            selectionPolicy.maxLatencyMs(),
            selectionPolicy.preferUnknownCountryFallback(),
            selectionPolicy.allowRestrictedSameCountry(),
            selectionPolicy.stableProbeAttempts()));
        }

        public void setPreferredCountries(List<String> preferredCountries) {
        configureSelectionPolicy(new ProxySelectionPolicy(
            selectionPolicy.allowedTypes(),
            selectionPolicy.blockedCountries(),
            preferredCountries,
            selectionPolicy.maxLatencyMs(),
            selectionPolicy.preferUnknownCountryFallback(),
            selectionPolicy.allowRestrictedSameCountry(),
            selectionPolicy.stableProbeAttempts()));
        }

        public void setMaxLatencyMs(long maxLatencyMs) {
        configureSelectionPolicy(new ProxySelectionPolicy(
            selectionPolicy.allowedTypes(),
            selectionPolicy.blockedCountries(),
            selectionPolicy.preferredCountries(),
            maxLatencyMs,
            selectionPolicy.preferUnknownCountryFallback(),
            selectionPolicy.allowRestrictedSameCountry(),
            selectionPolicy.stableProbeAttempts()));
        }

        public void setPreferUnknownCountryFallback(boolean enabled) {
        configureSelectionPolicy(new ProxySelectionPolicy(
            selectionPolicy.allowedTypes(),
            selectionPolicy.blockedCountries(),
            selectionPolicy.preferredCountries(),
            selectionPolicy.maxLatencyMs(),
            enabled,
            selectionPolicy.allowRestrictedSameCountry(),
            selectionPolicy.stableProbeAttempts()));
        }

        public void setAllowRestrictedSameCountry(boolean enabled) {
        configureSelectionPolicy(new ProxySelectionPolicy(
            selectionPolicy.allowedTypes(),
            selectionPolicy.blockedCountries(),
            selectionPolicy.preferredCountries(),
            selectionPolicy.maxLatencyMs(),
            selectionPolicy.preferUnknownCountryFallback(),
            enabled,
            selectionPolicy.stableProbeAttempts()));
        }

        public ProxyRotationMode getRotationMode() { return rotationMode; }

        public void setRotationMode(ProxyRotationMode mode) {
        rotationMode = mode != null ? mode : ProxyRotationMode.STABLE;
        emit("Proxy rotation mode set to: " + rotationMode);
        }

    private void emit(String msg) {
        LOG.info(msg);
        if (logCallback != null) logCallback.accept(msg + "\n");
    }

    private void emitStats(int candidates, int live, int countries) {
        if (statsCallback != null) statsCallback.accept(new int[]{candidates, live, countries});
    }

    private void emitProgress(double value) {
        if (progressCallback != null) progressCallback.accept(value);
    }

    // ── Initialization ────────────────────────────────────────────────────────

    /**
     * Asynchronously harvest → validate → geo-resolve → populate pool.
     *
     * @return future that completes when the pool is ready (or empty on failure)
     */
    public CompletableFuture<Void> initializeAsync() {
        return CompletableFuture.runAsync(this::doInitialize);
    }

    /** Synchronous version for callers that block deliberately (e.g. CLI tools). */
    public void initializeSync() {
        doInitialize();
    }

    private void doInitialize() {
        cancelled = false;
        countryFailureStreak.clear();
        endpointFailureStreak.clear();
        quarantinedCountries.clear();
        try {
            emitProgress(0.05);
            emit("Phase 1: harvesting proxy candidates...");
            Set<ProxyNode> raw = harvester.harvest();
            if (cancelled) { emit("Stopped."); emitProgress(0.0); return; }
            emit("Harvested " + raw.size() + " candidates.");
            emitStats(raw.size(), 0, 0);
            emitProgress(0.35);

            emit("Phase 2: triple-handshake validation (virtual threads)...");
            Set<ProxyNode> validated = validator.validateAll(raw, (done, tot) -> {
                if (cancelled) return;
                // emit progress every 500 checks
                if (done % 500 == 0 || done.equals(tot)) {
                    emit("  Checked " + done + " / " + tot + " — live so far: checking...");
                    emitProgress(0.35 + 0.35 * done / (double) tot);
                }
            });
            if (cancelled) { emit("Stopped."); emitProgress(0.0); return; }
            emit("Validated " + validated.size() + " live proxies.");
            emitStats(raw.size(), validated.size(), 0);
            emitProgress(0.70);

            // Save immediately after Phase 2 — geo data added in Phase 3
            if (!validated.isEmpty()) {
                store.save(validated);
                emit("Checkpoint saved: " + validated.size() + " proxies → " + store.getStorePath());
            }

            emit("Phase 3: geo-resolution...");
            for (ProxyNode node : validated) {
                if (cancelled) { emit("Stopped."); emitProgress(0.0); return; }
                if ("XX".equals(node.countryCode())) {
                    String cc = resolveCountryCode(node.host());
                    pool.add(node.withCountry(cc));
                } else {
                    pool.add(node);
                }
            }

            initialized = true;
            emitStats(raw.size(), pool.totalSize(), pool.availableCountries().size());
            emitProgress(1.0);
            emit("Pool ready — " + pool.totalSize() + " proxies in "
                    + pool.availableCountries().size() + " countries.");
            // Overwrite checkpoint with geo-enriched data (only if non-empty)
            if (pool.totalSize() > 0) {
                store.save(pool.allProxies());
                emit("Proxy list saved → " + store.getStorePath());
            }
        } catch (Exception e) {
            LOG.log(java.util.logging.Level.SEVERE, "[ProxyRouting] Initialization failed: {0}", e.getMessage());
            emitProgress(0.0);
            emit("ERROR: " + e.getMessage());
        }
    }

    // ── Proxy selection ───────────────────────────────────────────────────────

    /**
     * Select the best proxy for the given target IP.
     * Returns empty if the pool is not ready or has no live proxies.
     */
    public Optional<ProxyNode> selectProxy(String targetIp) {
        if (!initialized || pool.totalSize() == 0) return Optional.empty();
        return routing.selectBest(targetIp, quarantinedCountries, selectionPolicy);
    }

    /** Select by explicit target country code (manual override mode). */
    public Optional<ProxyNode> selectProxyForCountry(String countryCode) {
        if (!initialized || pool.totalSize() == 0) return Optional.empty();
        String normalized = normalizeCountry(countryCode);
        if (normalized.isBlank()) return Optional.empty();
        return routing.selectBestForCountry(normalized, quarantinedCountries, selectionPolicy);
    }

    /**
     * Select a proxy that can actually establish a tunnel to a probe endpoint.
     * This reduces runtime failures caused by stale/blocked proxy nodes.
     */
    public Optional<ProxyNode> selectStableProxy(String targetIp) {
        if (!initialized || pool.totalSize() == 0) return Optional.empty();

        Set<String> temporaryCountryExclusions = new HashSet<>();
        for (int attempt = 1; attempt <= selectionPolicy.stableProbeAttempts(); attempt++) {
            Set<String> excludedCountries = new HashSet<>(quarantinedCountries);
            excludedCountries.addAll(temporaryCountryExclusions);

            Optional<ProxyNode> candidateOpt = routing.selectBest(targetIp, excludedCountries, selectionPolicy);
            if (candidateOpt.isEmpty()) return Optional.empty();

            ProxyNode candidate = candidateOpt.get();
            if (probeProxy(candidate, targetIp)) {
                registerSuccess(candidate);
                return Optional.of(candidate);
            }

            registerFailure(candidate);
            pool.remove(candidate);
            temporaryCountryExclusions.add(candidate.countryCode());
            emit("Stable selector rejected " + endpointId(candidate) + " (attempt "
                    + attempt + "/" + selectionPolicy.stableProbeAttempts() + ")");
        }

        return Optional.empty();
    }

    /** Stable selection with explicit country override. */
    public Optional<ProxyNode> selectStableProxyForCountry(String countryCode) {
        String normalized = normalizeCountry(countryCode);
        if (normalized.isBlank() || !initialized || pool.totalSize() == 0) return Optional.empty();

        Set<String> temporaryCountryExclusions = new HashSet<>();
        for (int attempt = 1; attempt <= selectionPolicy.stableProbeAttempts(); attempt++) {
            Set<String> excludedCountries = new HashSet<>(quarantinedCountries);
            excludedCountries.addAll(temporaryCountryExclusions);

            Optional<ProxyNode> candidateOpt = routing.selectBestForCountry(normalized,
                    excludedCountries, selectionPolicy);
            if (candidateOpt.isEmpty()) return Optional.empty();

            ProxyNode candidate = candidateOpt.get();
            if (probeProxy(candidate, "1.1.1.1")) {
                registerSuccess(candidate);
                return Optional.of(candidate);
            }

            registerFailure(candidate);
            pool.remove(candidate);
            temporaryCountryExclusions.add(candidate.countryCode());
        }
        return Optional.empty();
    }

    /** Selection entrypoint honoring current rotation mode. */
    public Optional<ProxyNode> selectWithCurrentMode(String targetIp) {
        return switch (rotationMode) {
            case FASTEST -> selectProxy(targetIp);
            case STABLE -> selectStableProxy(targetIp);
            case BALANCED -> {
                Optional<ProxyNode> fast = selectProxy(targetIp);
                if (fast.isEmpty()) {
                    yield selectStableProxy(targetIp);
                }
                ProxyNode fastNode = fast.get();
                if (healthScore(fastNode) < BALANCED_HEALTH_FLOOR) {
                    yield selectStableProxy(targetIp).or(() -> fast);
                }
                yield fast;
            }
        };
    }

    // ── Failover ──────────────────────────────────────────────────────────────

    /**
     * Remove a dead proxy and return the next best candidate from the same geo-zone.
     *
     * <p>This implements the transparent failover requirement: if a proxy dies
     * during a scan, the caller invokes this method and retries with the new node.
     *
     * @param dead     the proxy that failed
     * @param targetIp the target being scanned (used for geo routing)
     * @return next live proxy, or empty if no more proxies available for that zone
     */
    public Optional<ProxyNode> failover(ProxyNode dead, String targetIp) {
        pool.remove(dead);
        registerFailure(dead);
        LOG.log(java.util.logging.Level.WARNING, "[ProxyRouting] Proxy failed, removed: {0} | Searching replacement for {1}",
                new Object[]{dead, targetIp});
        return selectStableProxy(targetIp);
    }

    private void registerFailure(ProxyNode dead) {
        String cc = dead.countryCode();
        registerEndpointFailure(dead);
        if (cc == null || cc.isBlank() || "XX".equals(cc)) return;

        int streak = countryFailureStreak.merge(cc, 1, Integer::sum);
        if (streak >= COUNTRY_FAILURE_THRESHOLD) {
            if (quarantinedCountries.add(cc)) {
                emit("Country quarantine activated for " + cc
                        + " after " + streak + " proxy failure(s).");
            }
        }
    }

    private void registerEndpointFailure(ProxyNode node) {
        String endpoint = endpointId(node);
        int streak = endpointFailureStreak.merge(endpoint, 1, Integer::sum);
        if (streak >= ENDPOINT_FAILURE_THRESHOLD) {
            emit("Endpoint quarantine signal for " + endpoint
                    + " after " + streak + " failure(s)");
        }
    }

    private void registerSuccess(ProxyNode node) {
        endpointFailureStreak.remove(endpointId(node));
        String cc = node.countryCode();
        if (cc == null || cc.isBlank()) return;

        countryFailureStreak.computeIfPresent(cc, (k, v) -> v > 1 ? v - 1 : null);
        if (countryFailureStreak.getOrDefault(cc, 0) == 0 && quarantinedCountries.remove(cc)) {
            emit("Country quarantine lifted for " + cc + " after stable proxy selection.");
        }
    }

    // ── Status ────────────────────────────────────────────────────────────────

    public boolean isReady()  { return initialized && pool.totalSize() > 0; }
    public int     poolSize() { return pool.totalSize(); }    public boolean hasSavedPool() { return store.exists(); }
    public java.nio.file.Path savedPoolPath() { return store.getStorePath(); }

    /**
     * Snapshot of all currently known proxies (may include not-alive entries from cache).
     */
    public List<ProxyNode> allProxies() {
        return List.copyOf(pool.allProxies());
    }

    public List<ProxyNode> proxiesByCountry(String countryCode) {
        String normalized = normalizeCountry(countryCode);
        if (normalized.isBlank()) return List.of();
        return pool.getByCountry(normalized).stream()
                .sorted(Comparator.comparingLong(ProxyNode::latencyMs))
                .toList();
    }

    public record ProxyHealth(
            ProxyNode node,
            double score,
            int endpointFailures,
            int countryFailures,
            boolean countryQuarantined
    ) {}

    public List<ProxyHealth> healthReport() {
        List<ProxyHealth> items = new ArrayList<>();
        for (ProxyNode node : pool.allProxies()) {
            int endpointFailures = endpointFailureStreak.getOrDefault(endpointId(node), 0);
            int countryFailures = countryFailureStreak.getOrDefault(node.countryCode(), 0);
            items.add(new ProxyHealth(
                    node,
                    healthScore(node),
                    endpointFailures,
                    countryFailures,
                    quarantinedCountries.contains(node.countryCode())));
        }
        return items.stream()
                .sorted(Comparator.comparingDouble(ProxyHealth::score).reversed())
                .toList();
    }

    /**
     * Load a previously saved proxy pool from disk (skips harvesting/validation).
     * Returns number of proxies loaded, or 0 on failure.
     */
    public int loadFromFile() {
        Set<ProxyNode> loaded = store.load();
        if (loaded.isEmpty()) return 0;
        countryFailureStreak.clear();
        endpointFailureStreak.clear();
        quarantinedCountries.clear();
        loaded.forEach(pool::add);
        initialized = true;
        emitStats(0, pool.totalSize(), pool.availableCountries().size());
        emit("Loaded " + pool.totalSize() + " proxies from cache ("
                + pool.availableCountries().size() + " countries).");
        return pool.totalSize();
    }

    /**
     * Add locally running onion-style SOCKS transports into the pool.
     *
     * Endpoints attempted:
     * - Tor Browser / tor daemon: 127.0.0.1:9150, 127.0.0.1:9050
     * - Onion-compatible local socks endpoint: 127.0.0.1:4447
     *
     * @return number of endpoints successfully added
     */
    public int enableOnionFallback() {
        return enableOnionFallback(true, true);
    }

    public int enableOnionFallback(boolean includeTor, boolean includeOtherOnion) {
        if (!initialized) {
            emit("Onion fallback skipped: pool is not initialized yet.");
            return 0;
        }

        List<Integer> localPorts = new java.util.ArrayList<>();
        if (includeTor) {
            localPorts.add(9150);
            localPorts.add(9050);
        }
        if (includeOtherOnion) {
            localPorts.add(4447);
        }
        if (localPorts.isEmpty()) {
            emit("Onion fallback skipped: no endpoint group selected.");
            return 0;
        }

        int added = 0;

        for (int port : localPorts) {
            Optional<ProxyNode> node = probeLocalSocksEndpoint("127.0.0.1", port);
            if (node.isPresent()) {
                pool.add(node.get());
                added++;
                emit("Onion transport ready via 127.0.0.1:" + port
                        + " [SOCKS5, latency=" + node.get().latencyMs() + "ms]");
            }
        }

        if (added > 0) {
            emitStats(0, pool.totalSize(), pool.availableCountries().size());
        }
        return added;
    }

    /** Explicitly clear temporary country quarantine state. */
    public void resetCountryQuarantine() {
        countryFailureStreak.clear();
        endpointFailureStreak.clear();
        quarantinedCountries.clear();
        emit("Country quarantine reset.");
    }
    // ── Internal helpers ──────────────────────────────────────────────────────

    /**
     * Resolve 2-letter ISO country code for an IP via ip-api.com.
     * Returns "XX" on any error.
     */
    private String resolveCountryCode(String ip) {
        try {
            URI uri = new URI("http://ip-api.com/json/" + ip + "?fields=countryCode");
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(4_000);
            conn.setReadTimeout(4_000);
            conn.setRequestProperty("User-Agent", "Anibus-Scanner/1.8");

            if (conn.getResponseCode() == 200) {
                StringBuilder sb = new StringBuilder();
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line);
                }
                Matcher m = Pattern.compile("\"countryCode\"\\s*:\\s*\"([A-Z]{2})\"")
                        .matcher(sb.toString());
                if (m.find()) return m.group(1);
            }
            conn.disconnect();
        } catch (IOException | java.net.URISyntaxException ignored) {}
        return "XX";
    }

    private Optional<ProxyNode> probeLocalSocksEndpoint(String host, int port) {
        long started = System.nanoTime();
        Proxy socksProxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(host, port));
        try (Socket socket = new Socket(socksProxy)) {
            socket.connect(new InetSocketAddress("1.1.1.1", 80), 3_000);
            long latencyMs = (System.nanoTime() - started) / 1_000_000;
            return Optional.of(new ProxyNode(host, port, ProxyType.SOCKS5, "XX", latencyMs));
        } catch (IOException ignored) {
            return Optional.empty();
        }
    }

    private boolean probeProxy(ProxyNode node, String targetIp) {
        String probeHost = (targetIp == null || targetIp.isBlank()) ? "1.1.1.1" : targetIp;
        try (Socket socket = new Socket(node.toJavaProxy())) {
            socket.connect(new InetSocketAddress(probeHost, 443), 3_000);
            return socket.isConnected();
        } catch (IOException ignored) {
            return false;
        }
    }

    private double healthScore(ProxyNode node) {
        int endpointFailures = endpointFailureStreak.getOrDefault(endpointId(node), 0);
        int countryFailures = countryFailureStreak.getOrDefault(node.countryCode(), 0);

        double score = 100.0;
        score -= Math.min(50.0, endpointFailures * 25.0);
        score -= Math.min(30.0, countryFailures * 10.0);
        score -= Math.min(20.0, node.latencyMs() / 25.0);
        if (quarantinedCountries.contains(node.countryCode())) {
            score -= 20.0;
        }
        return Math.max(0.0, Math.min(100.0, score));
    }

    private String normalizeCountry(String countryCode) {
        if (countryCode == null) return "";
        String normalized = countryCode.trim().toUpperCase(Locale.ROOT);
        return normalized.length() == 2 ? normalized : "";
    }

    private String endpointId(ProxyNode node) {
        return node.host() + ":" + node.port() + ":" + node.type();
    }
}
