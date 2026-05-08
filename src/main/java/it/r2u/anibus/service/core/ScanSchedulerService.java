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
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "anibus-scheduler");
                t.setDaemon(true);
                return t;
            });

    private ScheduledFuture<?> future;
    private volatile LocalDateTime lastRun;
    private volatile LocalDateTime nextRun;
    private volatile boolean running;

    public interface ScanTask {
        /** Perform a scan and return results. May block. */
        List<PortScanResult> execute() throws Exception;
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
        cancel(); // cancel any existing schedule

        long periodMs = interval.toMillis();
        nextRun = LocalDateTime.now();
        running = true;

        future = executor.scheduleAtFixedRate(() -> {
            lastRun = LocalDateTime.now();
            nextRun = lastRun.plus(interval);
            try {
                List<PortScanResult> results = task.execute();
                onResults.accept(new ScanResults(results, lastRun));
            } catch (Exception e) {
                onError.accept(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
            }
        }, 0, periodMs, TimeUnit.MILLISECONDS);
    }

    /** Cancel the currently scheduled task without shutting down the executor. */
    public synchronized void cancel() {
        if (future != null && !future.isCancelled()) {
            future.cancel(false);
        }
        running = false;
        future  = null;
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
        return "Scheduler: active  |  last: " + last + "  |  next: " + next;
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
