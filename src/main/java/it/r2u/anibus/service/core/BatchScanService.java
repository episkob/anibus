package it.r2u.anibus.service.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import it.r2u.anibus.model.PortScanResult;

/**
 * Multi-target Batch Scan — accepts a list of hostnames/IPs (or a path to a
 * newline-delimited file) and runs the supplied scan task for each target in
 * sequence, collecting aggregated results for the final report.
 *
 * <p>Progress is reported after each target via the {@code onProgress} callback.
 * The implementation is intentionally scan-engine-agnostic: the caller supplies
 * any {@link TargetScanTask} implementation (e.g. wrapping PortScannerService).
 */
public class BatchScanService {

    // ── API types ─────────────────────────────────────────────────────────────

    /**
     * Caller-supplied scan action for a single target.
     */
    @FunctionalInterface
    public interface TargetScanTask {
        /** Run a scan against {@code target} and return the port results. */
        List<PortScanResult> scan(String target) throws Exception;
    }

    /**
     * Per-target scan outcome.
     *
     * @param target      host/IP that was scanned
     * @param results     list of open port findings (may be empty)
     * @param error       non-null if the scan threw an exception
     * @param durationMs  wall-clock time spent on this target
     */
    public record TargetResult(
        String               target,
        List<PortScanResult> results,
        String               error,
        long                 durationMs
    ) {
        public TargetResult {
            results = List.copyOf(results);
        }
        public boolean failed()    { return error != null; }
        public int     openPorts() { return (int) results.stream().filter(r -> isOpen(r)).count(); }
    }

    /**
     * Aggregate outcome of a full batch run.
     *
     * @param targets      ordered list of all targets that were queued
     * @param byTarget     per-target results in input order
     * @param totalMs      total elapsed milliseconds for the entire batch
     */
    public record BatchReport(
        List<String>       targets,
        List<TargetResult> byTarget,
        long               totalMs
    ) {
        public BatchReport {
            targets  = List.copyOf(targets);
            byTarget = List.copyOf(byTarget);
        }
        public long successCount() { return byTarget.stream().filter(r -> !r.failed()).count(); }
        public long failureCount() { return byTarget.stream().filter(TargetResult::failed).count(); }
        public long totalOpen()    { return byTarget.stream().mapToLong(TargetResult::openPorts).sum(); }
    }

    // ── Batch execution ───────────────────────────────────────────────────────

    /**
     * Loads targets from a newline-delimited file (UTF-8), strips blank lines
     * and lines starting with {@code #}.
     *
     * @param filePath path to the target list file
     * @return list of cleaned target strings
     * @throws IOException if the file cannot be read
     */
    public List<String> loadTargetsFromFile(Path filePath) throws IOException {
        List<String> lines = Files.readAllLines(filePath, StandardCharsets.UTF_8);
        List<String> targets = new ArrayList<>();
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                targets.add(trimmed);
            }
        }
        return targets;
    }

    /**
     * Runs the supplied task against every target in sequence.
     *
     * @param targets    list of hosts/IPs to scan
     * @param task       scan implementation
     * @param onProgress called after each target with (index+1, total) for UI progress
     * @param onTarget   called with the TargetResult immediately after each target
     *                   completes (for incremental console output); may be null
     * @return full {@link BatchReport}
     */
    public BatchReport runBatch(List<String> targets,
                                TargetScanTask task,
                                BiConsumer<Integer, Integer> onProgress,
                                Consumer<TargetResult> onTarget) {
        long batchStart = System.currentTimeMillis();
        int total = targets.size();
        List<TargetResult> results = new ArrayList<>(total);

        for (int i = 0; i < total; i++) {
            String target = targets.get(i);
            long start = System.currentTimeMillis();
            List<PortScanResult> portResults;
            String error = null;
            try {
                List<PortScanResult> r = task.scan(target);
                portResults = (r != null) ? new ArrayList<>(r) : new ArrayList<>();
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                portResults = new ArrayList<>();
                error = "Interrupted";
            } catch (Exception e) {
                portResults = new ArrayList<>();
                error = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            }
            long durationMs = System.currentTimeMillis() - start;
            TargetResult tr = new TargetResult(target, List.copyOf(portResults), error, durationMs);
            results.add(tr);
            if (onTarget != null) onTarget.accept(tr);
            if (onProgress != null) onProgress.accept(i + 1, total);
        }

        return new BatchReport(List.copyOf(targets), List.copyOf(results),
            System.currentTimeMillis() - batchStart);
    }

    // ── Report ────────────────────────────────────────────────────────────────

    public static String formatReport(BatchReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== MULTI-TARGET BATCH SCAN REPORT ===\n\n");
        sb.append(String.format("  Targets scanned : %d%n", report.targets().size()));
        sb.append(String.format("  Successful      : %d%n", report.successCount()));
        sb.append(String.format("  Failed          : %d%n", report.failureCount()));
        sb.append(String.format("  Total open ports: %d%n", report.totalOpen()));
        sb.append(String.format("  Total time      : %.1f s%n%n", report.totalMs() / 1000.0));

        // Group by risk: hosts with open ports first
        Map<String, List<PortScanResult>> withPorts = new LinkedHashMap<>();
        List<String> clean = new ArrayList<>();
        List<String> failed = new ArrayList<>();

        for (TargetResult tr : report.byTarget()) {
            if (tr.failed()) {
                failed.add(tr.target() + "  [ERROR: " + tr.error() + "]");
            } else if (tr.openPorts() > 0) {
                withPorts.put(tr.target(), tr.results());
            } else {
                clean.add(tr.target());
            }
        }

        if (!withPorts.isEmpty()) {
            sb.append("  ── Hosts with open ports ──────────────────────────────────\n");
            for (Map.Entry<String, List<PortScanResult>> e : withPorts.entrySet()) {
                sb.append("\n  ").append(e.getKey()).append(":\n");
                for (PortScanResult r : e.getValue()) {
                    if (!isOpen(r)) continue;
                    sb.append(String.format("    %-6d  %-12s  %-15s  %s%n",
                        r.getPort(),
                        safe(r.getState()),
                        safe(r.getService()),
                        safe(r.getBanner())));
                }
            }
            sb.append("\n");
        }

        if (!clean.isEmpty()) {
            sb.append("  ── No open ports ──────────────────────────────────────────\n");
            clean.forEach(h -> sb.append("    ").append(h).append("\n"));
            sb.append("\n");
        }

        if (!failed.isEmpty()) {
            sb.append("  ── Scan errors ────────────────────────────────────────────\n");
            failed.forEach(h -> sb.append("    ").append(h).append("\n"));
        }

        return sb.toString();
    }

    private static boolean isOpen(PortScanResult r) {
        if (r == null) return false;
        String state = r.getState();
        return state != null && state.toLowerCase().contains("open");
    }

    private static String safe(String s) { return s != null ? s : ""; }
}
