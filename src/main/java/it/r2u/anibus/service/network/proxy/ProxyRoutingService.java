package it.r2u.anibus.service.network.proxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
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

    private volatile boolean initialized = false;
    private volatile boolean cancelled   = false;
    private Consumer<String>  logCallback      = null;
    private Consumer<int[]>   statsCallback    = null;
    private Consumer<Double>  progressCallback = null;

    /** Request cancellation of an in-progress initialization. */
    public void cancel() { cancelled = true; }

    public void setLogCallback(Consumer<String> callback)      { this.logCallback      = callback; }
    public void setStatsCallback(Consumer<int[]> callback)    { this.statsCallback    = callback; }
    public void setProgressCallback(Consumer<Double> callback) { this.progressCallback = callback; }

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
        return routing.selectBest(targetIp);
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
        LOG.log(java.util.logging.Level.WARNING, "[ProxyRouting] Proxy failed, removed: {0} | Searching replacement for {1}",
                new Object[]{dead, targetIp});
        return selectProxy(targetIp);
    }

    // ── Status ────────────────────────────────────────────────────────────────

    public boolean isReady()  { return initialized && pool.totalSize() > 0; }
    public int     poolSize() { return pool.totalSize(); }    public boolean hasSavedPool() { return store.exists(); }
    public java.nio.file.Path savedPoolPath() { return store.getStorePath(); }

    /**
     * Load a previously saved proxy pool from disk (skips harvesting/validation).
     * Returns number of proxies loaded, or 0 on failure.
     */
    public int loadFromFile() {
        Set<ProxyNode> loaded = store.load();
        if (loaded.isEmpty()) return 0;
        loaded.forEach(pool::add);
        initialized = true;
        emitStats(0, pool.totalSize(), pool.availableCountries().size());
        emit("Loaded " + pool.totalSize() + " proxies from cache ("
                + pool.availableCountries().size() + " countries).");
        return pool.totalSize();
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
}
