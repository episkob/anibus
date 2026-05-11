package it.r2u.anibus.service.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import it.r2u.anibus.model.PortScanResult;

/**
 * Persists scan results to ~/.anibus/history/ as CSV files.
 * Each file name encodes the timestamp and target host so it can be
 * listed, loaded and compared without a database dependency.
 *
 * File format: same CSV structure as ExportService.writeCsv()
 *   Port,State,Service,Version,Protocol,Latency(ms),Banner
 */
public class ScanHistoryService {

    private static final Logger LOG = Logger.getLogger(ScanHistoryService.class.getName());
    private static final DateTimeFormatter STAMP_FMT =
        DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final int MAX_ENTRIES = 50;

    public record HistoryEntry(String id, LocalDateTime timestamp, String host, int openPorts) {}

    private final Path historyDir;

    public ScanHistoryService() {
        historyDir = Path.of(System.getProperty("user.home"), ".anibus", "history");
    }

    /** Persists a completed scan. Returns the file name used. */
    public String save(String host, List<PortScanResult> results) {
        try {
            Files.createDirectories(historyDir);
            String stamp = LocalDateTime.now().format(STAMP_FMT);
            String safeName = host.replaceAll("[^a-zA-Z0-9._-]", "_");
            String fileName = stamp + "_" + safeName + ".csv";
            File file = historyDir.resolve(fileName).toFile();
            try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
                pw.println("Port,State,Service,Version,Protocol,Latency(ms),Banner");
                for (PortScanResult r : results) {
                    pw.printf("%d,\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\"%n",
                        r.getPort(), esc(r.getState()), esc(r.getService()),
                        esc(r.getVersion()), esc(r.getProtocol()),
                        r.getLatency(), esc(r.getBanner()));
                }
            }
            pruneOldEntries();
            return fileName;
        } catch (IOException e) {
            LOG.warning(() -> "Failed to save scan history: " + e.getMessage());
            return null;
        }
    }

    /** Lists all saved scans, most recent first. */
    public List<HistoryEntry> list() {
        File dir = historyDir.toFile();
        if (!dir.exists()) return Collections.emptyList();
        File[] files = dir.listFiles((d, n) -> n.endsWith(".csv"));
        if (files == null || files.length == 0) return Collections.emptyList();
        Arrays.sort(files, (a, b) -> Long.compare(b.lastModified(), a.lastModified()));
        List<HistoryEntry> entries = new ArrayList<>();
        for (File f : files) {
            HistoryEntry e = parseEntry(f);
            if (e != null) entries.add(e);
        }
        return entries;
    }

    /** Loads results from a history entry by its id (file name). */
    public List<PortScanResult> load(String id) {
        File file = historyDir.resolve(id).toFile();
        if (!file.exists()) return Collections.emptyList();
        List<PortScanResult> results = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            br.readLine(); // skip header
            String line;
            while ((line = br.readLine()) != null) {
                PortScanResult r = parseLine(line);
                if (r != null) results.add(r);
            }
        } catch (IOException e) {
            LOG.warning(() -> "Failed to load history entry " + id + ": " + e.getMessage());
        }
        return results;
    }

    public static String formatListReport(List<HistoryEntry> entries) {
        if (entries.isEmpty()) return "  (No scan history saved yet)\n";
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("                    SCAN HISTORY\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");
        DateTimeFormatter display = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        for (int i = 0; i < entries.size(); i++) {
            HistoryEntry e = entries.get(i);
            sb.append(String.format("  [%2d] %s  %-30s  %d open port(s)\n",
                i + 1,
                e.timestamp().format(display),
                e.host(),
                e.openPorts()));
        }
        sb.append("\n  (Use right-click → 'Load Scan History entry...' to restore)\n");
        return sb.toString();
    }

    public static String formatCompareReport(
            HistoryEntry entryA, List<PortScanResult> a,
            HistoryEntry entryB, List<PortScanResult> b) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("  SCAN COMPARISON\n");
        sb.append(String.format("  A: %s — %s%n", entryA.timestamp(), entryA.host()));
        sb.append(String.format("  B: %s — %s%n", entryB.timestamp(), entryB.host()));
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        java.util.Set<Integer> portsA = new java.util.LinkedHashSet<>();
        java.util.Map<Integer, PortScanResult> mapA = new java.util.LinkedHashMap<>();
        for (PortScanResult r : a) { portsA.add(r.getPort()); mapA.put(r.getPort(), r); }
        java.util.Set<Integer> portsB = new java.util.LinkedHashSet<>();
        java.util.Map<Integer, PortScanResult> mapB = new java.util.LinkedHashMap<>();
        for (PortScanResult r : b) { portsB.add(r.getPort()); mapB.put(r.getPort(), r); }

        java.util.Set<Integer> allPorts = new java.util.TreeSet<>();
        allPorts.addAll(portsA);
        allPorts.addAll(portsB);

        for (int port : allPorts) {
            boolean inA = portsA.contains(port);
            boolean inB = portsB.contains(port);
            if (inA && !inB) {
                sb.append(String.format("  - CLOSED  port %5d (%s) — disappeared in B%n",
                    port, mapA.get(port).getService()));
            } else if (!inA && inB) {
                sb.append(String.format("  + OPENED  port %5d (%s) — appeared in B%n",
                    port, mapB.get(port).getService()));
            } else {
                // Both present — check if service/version changed
                PortScanResult ra = mapA.get(port), rb = mapB.get(port);
                if (!eq(ra.getService(), rb.getService()) || !eq(ra.getVersion(), rb.getVersion())) {
                    sb.append(String.format("  ~ CHANGED port %5d: %s %s → %s %s%n",
                        port,
                        ra.getService(), nvl(ra.getVersion()),
                        rb.getService(), nvl(rb.getVersion())));
                }
            }
        }
        if (sb.indexOf("CLOSED") < 0 && sb.indexOf("OPENED") < 0 && sb.indexOf("CHANGED") < 0) {
            sb.append("  ✓ No differences detected between the two scans.\n");
        }
        return sb.toString();
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    private HistoryEntry parseEntry(File f) {
        // File name: yyyyMMdd-HHmmss_host.csv
        String name = f.getName();
        if (!name.endsWith(".csv") || name.length() < 17) return null;
        try {
            String stampStr = name.substring(0, 15); // yyyyMMdd-HHmmss
            LocalDateTime ts = LocalDateTime.parse(stampStr, STAMP_FMT);
            String host = name.substring(16, name.length() - 4).replace('_', '.');
            long openCount = 0;
            try (BufferedReader br = new BufferedReader(new FileReader(f))) {
                br.readLine(); // header
                String line;
                while ((line = br.readLine()) != null) {
                    if (line.toLowerCase().contains("open")) openCount++;
                }
            }
            return new HistoryEntry(name, ts, host, (int) openCount);
        } catch (NumberFormatException | IOException ignored) {
            return null;
        }
    }

    private PortScanResult parseLine(String line) {
        // CSV: Port,State,Service,Version,Protocol,Latency(ms),Banner
        // Values may be quoted
        try {
            String[] parts = splitCsv(line);
            if (parts.length < 7) return null;
            int port = Integer.parseInt(parts[0].trim());
            String state    = unquote(parts[1]);
            String service  = unquote(parts[2]);
            String version  = unquote(parts[3]);
            String protocol = unquote(parts[4]);
            long latency    = Long.parseLong(parts[5].trim());
            String banner   = unquote(parts[6]);
            return new PortScanResult(port, service, banner, protocol, latency, version, state, "History");
        } catch (NumberFormatException | DateTimeException ignored) {
            return null;
        }
    }

    private String[] splitCsv(String line) {
        List<String> result = new ArrayList<>();
        boolean inQuote = false;
        StringBuilder cur = new StringBuilder();
        for (char c : line.toCharArray()) {
            if (c == '"') { inQuote = !inQuote; }
            else if (c == ',' && !inQuote) { result.add(cur.toString()); cur.setLength(0); }
            else { cur.append(c); }
        }
        result.add(cur.toString());
        return result.toArray(String[]::new);
    }

    private void pruneOldEntries() {
        File dir = historyDir.toFile();
        File[] files = dir.listFiles((d, n) -> n.endsWith(".csv"));
        if (files == null || files.length <= MAX_ENTRIES) return;
        Arrays.sort(files, (a, b) -> Long.compare(a.lastModified(), b.lastModified()));
        for (int i = 0; i < files.length - MAX_ENTRIES; i++) {
            files[i].delete();
        }
    }

    private String esc(String s)     { return s == null ? "" : s.replace("\"", "\"\""); }
    private String unquote(String s) { return s == null ? "" : s.replaceAll("^\"|\"$", "").replace("\"\"", "\""); }
    private static boolean eq(String a, String b) { return a == null ? b == null : a.equals(b); }
    private static String nvl(String s) { return s == null ? "" : s; }
}
