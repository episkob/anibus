package it.r2u.anibus.service.core;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
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
            LocalDateTime        timestamp
    ) {
        /** Format timestamp for display. */
        public String formattedTimestamp() {
            return timestamp.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        }
    }
}
