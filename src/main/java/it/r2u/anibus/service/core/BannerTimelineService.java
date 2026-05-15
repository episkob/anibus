package it.r2u.anibus.service.core;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import it.r2u.anibus.model.PortScanResult;

/**
 * Port Banner Timeline — persists banner/version snapshots per host and
 * produces inter-scan diffs to highlight service version changes.
 *
 * <p>Snapshots are stored in {@code ~/.anibus/banners/<host>.tsv} as simple
 * tab-separated lines: {@code <timestamp>\t<port>\t<service>\t<banner>\t<version>}.
 * No external libraries are required.
 */
public class BannerTimelineService {

    private static final DateTimeFormatter TS_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    private static final Path STORAGE_DIR;

    static {
        STORAGE_DIR = Paths.get(System.getProperty("user.home"), ".anibus", "banners");
    }

    // ── Data types ────────────────────────────────────────────────────────────

    /**
     * One row in the persisted timeline: a banner/version snapshot for one port.
     *
     * @param timestamp when the snapshot was taken
     * @param port      TCP port
     * @param service   service name (may be empty)
     * @param banner    raw banner text (may be empty)
     * @param version   version string extracted from banner (may be empty)
     */
    public record BannerSnapshot(
        LocalDateTime timestamp,
        int           port,
        String        service,
        String        banner,
        String        version
    ) {}

    /**
     * Describes a change between two snapshots for the same port.
     *
     * @param port        TCP port
     * @param service     current service name
     * @param changeType  NEW / REMOVED / BANNER_CHANGED / VERSION_CHANGED
     * @param previous    previous banner/version (null for NEW)
     * @param current     current banner/version (null for REMOVED)
     * @param timestamp   when the latest snapshot was taken
     */
    public record BannerChange(
        int           port,
        String        service,
        ChangeType    changeType,
        String        previous,
        String        current,
        LocalDateTime timestamp
    ) {}

    public enum ChangeType { NEW, REMOVED, BANNER_CHANGED, VERSION_CHANGED }

    // ── API ───────────────────────────────────────────────────────────────────

    /**
     * Saves a new banner snapshot for {@code host} from current scan results.
     *
     * @param host    hostname or IP (used as storage key)
     * @param results current port scan results
     */
    public void snapshot(String host, List<PortScanResult> results) {
        if (host == null || host.isBlank() || results == null) return;
        Path file = fileFor(host);
        try {
            Files.createDirectories(STORAGE_DIR);
            String ts = LocalDateTime.now().format(TS_FMT);
            try (BufferedWriter w = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND)) {
                for (PortScanResult r : results) {
                    if (r == null) continue;
                    String service = safe(r.getService());
                    String banner  = safe(r.getBanner()).replace("\t", " ").replace("\n", " ");
                    String version = safe(r.getVersion());
                    w.write(ts + "\t" + r.getPort() + "\t" + service + "\t" + banner + "\t" + version + "\n");
                }
            }
        } catch (IOException ignored) { }
    }

    /**
     * Returns all recorded snapshots for {@code host}, oldest first.
     */
    public List<BannerSnapshot> history(String host) {
        Path file = fileFor(host);
        if (!Files.exists(file)) return List.of();
        List<BannerSnapshot> rows = new ArrayList<>();
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                String[] p = line.split("\t", 5);
                if (p.length < 5) continue;
                try {
                    LocalDateTime ts = LocalDateTime.parse(p[0], TS_FMT);
                    int port = Integer.parseInt(p[1]);
                    rows.add(new BannerSnapshot(ts, port, p[2], p[3], p[4]));
                } catch (DateTimeParseException | NumberFormatException ignored) { }
            }
        } catch (IOException ignored) { }
        return rows;
    }

    /**
     * Computes the diff between the two most recent scan timestamps for {@code host}.
     *
     * @return list of changes; empty if fewer than two snapshots exist
     */
    public List<BannerChange> diff(String host) {
        List<BannerSnapshot> rows = history(host);
        if (rows.isEmpty()) return List.of();

        // Group by timestamp (most recent two)
        List<LocalDateTime> times = rows.stream()
            .map(BannerSnapshot::timestamp).distinct()
            .sorted()
            .toList();
        if (times.size() < 2) return List.of();

        LocalDateTime prevTs = times.get(times.size() - 2);
        LocalDateTime currTs = times.get(times.size() - 1);

        Map<Integer, BannerSnapshot> prev = new LinkedHashMap<>();
        Map<Integer, BannerSnapshot> curr = new LinkedHashMap<>();
        for (BannerSnapshot s : rows) {
            if (s.timestamp().equals(prevTs)) prev.put(s.port(), s);
            else if (s.timestamp().equals(currTs)) curr.put(s.port(), s);
        }
        return computeDiff(prev, curr, currTs);
    }

    /**
     * Computes diff between arbitrary two snapshots (keyed by port).
     */
    public List<BannerChange> diff(Map<Integer, BannerSnapshot> previous,
                                   Map<Integer, BannerSnapshot> current,
                                   LocalDateTime timestamp) {
        return computeDiff(previous, current, timestamp);
    }

    private List<BannerChange> computeDiff(Map<Integer, BannerSnapshot> prev,
                                            Map<Integer, BannerSnapshot> curr,
                                            LocalDateTime ts) {
        List<BannerChange> changes = new ArrayList<>();

        // NEW ports
        for (Map.Entry<Integer, BannerSnapshot> e : curr.entrySet()) {
            if (!prev.containsKey(e.getKey())) {
                BannerSnapshot s = e.getValue();
                changes.add(new BannerChange(s.port(), s.service(), ChangeType.NEW,
                    null, bannerSummary(s), ts));
            }
        }
        // REMOVED ports
        for (Map.Entry<Integer, BannerSnapshot> e : prev.entrySet()) {
            if (!curr.containsKey(e.getKey())) {
                BannerSnapshot s = e.getValue();
                changes.add(new BannerChange(s.port(), s.service(), ChangeType.REMOVED,
                    bannerSummary(s), null, ts));
            }
        }
        // CHANGED ports
        for (Map.Entry<Integer, BannerSnapshot> e : curr.entrySet()) {
            BannerSnapshot pSnap = prev.get(e.getKey());
            if (pSnap == null) continue;
            BannerSnapshot cSnap = e.getValue();
            if (!cSnap.version().equals(pSnap.version()) && !cSnap.version().isBlank()) {
                changes.add(new BannerChange(cSnap.port(), cSnap.service(), ChangeType.VERSION_CHANGED,
                    pSnap.version(), cSnap.version(), ts));
            } else if (!cSnap.banner().equals(pSnap.banner()) && !cSnap.banner().isBlank()) {
                changes.add(new BannerChange(cSnap.port(), cSnap.service(), ChangeType.BANNER_CHANGED,
                    truncate(pSnap.banner(), 80), truncate(cSnap.banner(), 80), ts));
            }
        }
        return changes;
    }

    // ── Report ────────────────────────────────────────────────────────────────

    public static String formatReport(List<BannerChange> changes, String host) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== PORT BANNER TIMELINE: ").append(host).append(" ===\n\n");
        if (changes.isEmpty()) {
            sb.append("  No banner changes detected since last scan.\n");
            return sb.toString();
        }
        sb.append("  ").append(changes.size()).append(" change(s) detected:\n\n");
        for (BannerChange c : changes) {
            String tag = switch (c.changeType()) {
                case NEW             -> "[NEW]";
                case REMOVED         -> "[REMOVED]";
                case VERSION_CHANGED -> "[VERSION]";
                case BANNER_CHANGED  -> "[BANNER]";
            };
            sb.append(String.format("  %s port %d / %s%n", tag, c.port(), c.service()));
            if (c.previous() != null) sb.append("    was: ").append(c.previous()).append("\n");
            if (c.current()  != null) sb.append("    now: ").append(c.current()).append("\n");
            sb.append("\n");
        }
        return sb.toString();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Path fileFor(String host) {
        String safe = host.replaceAll("[^a-zA-Z0-9._\\-]", "_");
        return STORAGE_DIR.resolve(safe + ".tsv");
    }

    private String safe(String s) { return s == null ? "" : s.trim(); }

    private String bannerSummary(BannerSnapshot s) {
        if (!s.version().isBlank()) return s.service() + " " + s.version();
        if (!s.banner().isBlank()) return truncate(s.banner(), 60);
        return s.service();
    }

    private static String truncate(String s, int max) {
        return s != null && s.length() > max ? s.substring(0, max) + "…" : s;
    }

    /** List all hosts that have at least one stored snapshot. */
    public List<String> knownHosts() {
        try {
            if (!Files.exists(STORAGE_DIR)) return List.of();
            return Files.list(STORAGE_DIR)
                .filter(p -> p.toString().endsWith(".tsv"))
                .map(p -> p.getFileName().toString().replace(".tsv", ""))
                .sorted()
                .toList();
        } catch (IOException e) {
            return List.of();
        }
    }

    /** Returns a summary of snapshot timestamps for a host (newest first). */
    public List<LocalDateTime> snapshotTimestamps(String host) {
        return history(host).stream()
            .map(BannerSnapshot::timestamp).distinct()
            .sorted(Comparator.reverseOrder())
            .toList();
    }
}
