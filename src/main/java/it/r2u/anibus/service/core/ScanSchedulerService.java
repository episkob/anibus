package it.r2u.anibus.service.core;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.util.NamedThreadFactory;

/**
 * Scan Scheduler — runs a recurring scan task at a fixed interval.
 *
 * Usage:
 * <pre>
 *   ScanSchedulerService scheduler = new ScanSchedulerService();
 *   scheduler.schedule(Duration.ofHours(2), scanTask, onResults, onError);
 *   ...
 *   scheduler.cancel();
 *   scheduler.shutdown();
 * </pre>
 *
 * Thread safety: all callbacks are executed on the scheduler daemon thread.
 * The caller is responsible for dispatching UI updates to the JavaFX thread
 * via {@code Platform.runLater()} inside the callbacks.
 */
public class ScanSchedulerService {

    private final ScheduledExecutorService executor =
            Executors.newSingleThreadScheduledExecutor(
                    NamedThreadFactory.of("scan-scheduler"));

    private ScheduledFuture<?> future;
    private volatile LocalDateTime lastRun;
    private volatile LocalDateTime nextRun;
    private volatile boolean running;
    private volatile SchedulerOptions activeOptions;
    private volatile int runCount;

    public interface ScanTask {
        /** Perform a scan and return results. May block. */
        List<PortScanResult> execute() throws Exception;
    }

    public record SchedulerOptions(
            Duration interval,
            Duration initialDelay,
            boolean fixedDelay,
            int maxRuns
    ) {
        public SchedulerOptions {
            interval = (interval == null || interval.isNegative() || interval.isZero())
                    ? Duration.ofMinutes(30) : interval;
            initialDelay = (initialDelay == null || initialDelay.isNegative())
                    ? Duration.ZERO : initialDelay;
            maxRuns = Math.max(0, maxRuns);
        }

        public static SchedulerOptions defaults(Duration interval) {
            return new SchedulerOptions(interval, Duration.ZERO, false, 0);
        }
    }

    /**
     * Schedule a recurring scan.
     *
     * @param interval        time between scan starts
     * @param task            the scan to run
     * @param onResults       called with results after each successful scan
     * @param onError         called if the task throws; receives the exception message
     */
    public synchronized void schedule(Duration interval,
                                       ScanTask task,
                                       Consumer<ScanResults> onResults,
                                       Consumer<String> onError) {
        schedule(SchedulerOptions.defaults(interval), task, onResults, onError);
    }

    public synchronized void schedule(SchedulerOptions options,
                                      ScanTask task,
                                      Consumer<ScanResults> onResults,
                                      Consumer<String> onError) {
        cancel();

        SchedulerOptions effective = options == null
                ? SchedulerOptions.defaults(Duration.ofMinutes(30))
                : options;
        activeOptions = effective;
        runCount = 0;

        long delayMs = effective.initialDelay().toMillis();
        long periodMs = effective.interval().toMillis();
        nextRun = LocalDateTime.now().plus(effective.initialDelay());
        running = true;

        Runnable runner = () -> {
            lastRun = LocalDateTime.now();
            runCount++;
            nextRun = effective.fixedDelay()
                    ? null
                    : lastRun.plus(effective.interval());
            try {
                List<PortScanResult> results = task.execute();
                onResults.accept(new ScanResults(results, lastRun));
            } catch (Exception e) {
                onError.accept(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
            }

            if (effective.maxRuns() > 0 && runCount >= effective.maxRuns()) {
                cancel();
            }
        };

        if (effective.fixedDelay()) {
            future = executor.scheduleWithFixedDelay(runner, delayMs, periodMs, TimeUnit.MILLISECONDS);
        } else {
            future = executor.scheduleAtFixedRate(runner, delayMs, periodMs, TimeUnit.MILLISECONDS);
        }
    }

    /** Cancel the currently scheduled task without shutting down the executor. */
    public synchronized void cancel() {
        if (future != null && !future.isCancelled()) {
            future.cancel(false);
        }
        running = false;
        future  = null;
        activeOptions = null;
        runCount = 0;
    }

    /** Shut down the executor. Call when the application exits. */
    public void shutdown() {
        cancel();
        executor.shutdownNow();
    }

    public boolean isRunning()           { return running && future != null && !future.isCancelled(); }
    public LocalDateTime getLastRun()    { return lastRun; }
    public LocalDateTime getNextRun()    { return nextRun; }

    /** Returns a human-readable status string. */
    public String statusString() {
        if (!isRunning()) return "Scheduler: inactive";
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("HH:mm:ss");
        String last = lastRun != null ? lastRun.format(fmt) : "—";
        String next = nextRun != null ? nextRun.format(fmt) : "—";
        String mode = activeOptions != null && activeOptions.fixedDelay() ? "fixed-delay" : "fixed-rate";
        String runs = activeOptions != null && activeOptions.maxRuns() > 0
            ? (runCount + "/" + activeOptions.maxRuns())
            : (runCount + "/∞");
        return "Scheduler: active  |  mode: " + mode + "  |  runs: " + runs +
            "  |  last: " + last + "  |  next: " + next;
    }

    // ── Result carrier ────────────────────────────────────────────────────

    public record ScanResults(
            List<PortScanResult> results,
            LocalDateTime        timestamp,
            List<DriftAlert>     driftAlerts
    ) {
        /** Backward-compatible constructor without drift alerts. */
        public ScanResults(List<PortScanResult> results, LocalDateTime timestamp) {
            this(results, timestamp, List.of());
        }
        /** Format timestamp for display. */
        public String formattedTimestamp() {
            return timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        }
    }

    // ── Baseline & Drift (defined after ScanResults to allow cross-referencing) ──

    /** Alert severity for a drift event. */
    public enum DriftSeverity { CRITICAL, HIGH, MEDIUM, INFO }

    /** Describes a single change detected against the baseline. */
    public record DriftAlert(
        int           port,
        String        service,
        String        alertType,   // NEW / REMOVED / SERVICE_CHANGED
        DriftSeverity severity,
        String        description
    ) {}

    /**
     * Baseline profile for drift comparison.
     */
    public record BaselineProfile(
        String              name,
        Map<Integer, String> expectedPorts,
        Set<Integer>        suppressedPorts,
        DriftSeverity       minSeverity
    ) {
        public static BaselineProfile of(String name, Map<Integer, String> ports) {
            return new BaselineProfile(name, Map.copyOf(ports), Set.of(), DriftSeverity.INFO);
        }

        public static BaselineProfile snapshot(String name, List<PortScanResult> results) {
            Map<Integer, String> ports = new HashMap<>();
            for (PortScanResult r : results) {
                if (r == null) continue;
                String state = r.getState();
                if (state != null && state.toLowerCase().contains("open")) {
                    ports.put(r.getPort(), r.getService() != null ? r.getService() : "");
                }
            }
            return new BaselineProfile(name, Map.copyOf(ports), Set.of(), DriftSeverity.INFO);
        }
    }

    public static List<DriftAlert> compareWithBaseline(List<PortScanResult> results,
                                                        BaselineProfile baseline) {
        if (results == null || baseline == null) return List.of();

        Set<Integer> currentOpen = new HashSet<>();
        Map<Integer, String> currentService = new HashMap<>();
        for (PortScanResult r : results) {
            if (r == null) continue;
            String state = r.getState();
            if (state != null && state.toLowerCase().contains("open")) {
                currentOpen.add(r.getPort());
                currentService.put(r.getPort(), r.getService() != null ? r.getService() : "");
            }
        }

        List<DriftAlert> alerts = new ArrayList<>();

        for (int port : currentOpen) {
            if (baseline.suppressedPorts().contains(port)) continue;
            if (!baseline.expectedPorts().containsKey(port)) {
                String svc = currentService.getOrDefault(port, "");
                DriftSeverity sev = wellKnownSeverity(port, svc);
                if (sev.ordinal() >= baseline.minSeverity().ordinal()) {
                    alerts.add(new DriftAlert(port, svc, "NEW", sev,
                        "New open port detected: " + port + "/" + svc));
                }
            }
        }

        for (int port : baseline.expectedPorts().keySet()) {
            if (baseline.suppressedPorts().contains(port)) continue;
            if (!currentOpen.contains(port)) {
                String svc = baseline.expectedPorts().get(port);
                if (DriftSeverity.MEDIUM.ordinal() >= baseline.minSeverity().ordinal()) {
                    alerts.add(new DriftAlert(port, svc, "REMOVED", DriftSeverity.MEDIUM,
                        "Previously open port no longer responding: " + port + "/" + svc));
                }
            }
        }

        for (int port : currentOpen) {
            if (baseline.suppressedPorts().contains(port)) continue;
            String expected = baseline.expectedPorts().get(port);
            String actual   = currentService.getOrDefault(port, "");
            if (expected != null && !expected.isBlank() && !actual.isBlank()
                    && !expected.equalsIgnoreCase(actual)) {
                if (DriftSeverity.HIGH.ordinal() >= baseline.minSeverity().ordinal()) {
                    alerts.add(new DriftAlert(port, actual, "SERVICE_CHANGED", DriftSeverity.HIGH,
                        "Service changed on port " + port + ": was '" + expected + "', now '" + actual + "'"));
                }
            }
        }

        return List.copyOf(alerts);
    }

    private static DriftSeverity wellKnownSeverity(int port, String service) {
        String svc = service.toLowerCase();
        if (port == 3306 || port == 5432 || port == 27017 || port == 6379
                || svc.contains("mysql") || svc.contains("postgres")
                || svc.contains("mongo") || svc.contains("redis")) {
            return DriftSeverity.CRITICAL;
        }
        if (port == 3389 || port == 23 || port == 445 || port == 8080
                || port == 8443 || port == 9200 || port == 2375) {
            return DriftSeverity.HIGH;
        }
        if (port == 22 || port == 21 || port == 25 || port == 53 || port == 9092) {
            return DriftSeverity.MEDIUM;
        }
        return DriftSeverity.INFO;
    }

    public static String formatDriftReport(List<DriftAlert> alerts, String host, BaselineProfile baseline) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== SECURITY DRIFT REPORT: ").append(host).append(" ===\n");
        sb.append("  Baseline: ").append(baseline.name())
          .append(" (").append(baseline.expectedPorts().size()).append(" expected port(s))\n\n");
        if (alerts.isEmpty()) {
            sb.append("  \u2713 No drift detected \u2014 scan matches baseline.\n");
            return sb.toString();
        }
        sb.append("  ").append(alerts.size()).append(" drift event(s):\n\n");
        for (DriftAlert a : alerts) {
            sb.append(String.format("  [%-8s] [%-16s] port %-5d  %s%n",
                a.severity(), a.alertType(), a.port(), a.description()));
        }
        return sb.toString();
    }
}
