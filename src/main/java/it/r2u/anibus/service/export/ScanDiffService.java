package it.r2u.anibus.service.export;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.r2u.anibus.model.PortScanResult;

/**
 * Scan Diff Mode — compares two Anibus XML export files and highlights changes.
 *
 * Detects:
 * - Newly opened ports (present in new, absent in old)
 * - Closed ports     (present in old, absent in new)
 * - Changed service / version / banner on the same port
 *
 * Uses the XML format produced by {@link ExportService#writeXml}.
 */
public class ScanDiffService {

    public enum ChangeType {
        ADDED,    // port appeared in new scan
        REMOVED,  // port disappeared
        CHANGED   // port present in both but service/version/banner changed
    }

    public record PortChange(
            int        port,
            ChangeType type,
            String     oldService,  String newService,
            String     oldVersion,  String newVersion,
            String     oldBanner,   String newBanner,
            String     oldState,    String newState,
            String     protocol
    ) {
        /** One-line summary of this change. */
        public String summary() {
            return switch (type) {
                case ADDED   -> String.format("[ADDED]   port %d/%s  %s %s",
                        port, protocol, newService, newVersion).stripTrailing();
                case REMOVED -> String.format("[REMOVED] port %d/%s  %s %s",
                        port, protocol, oldService, oldVersion).stripTrailing();
                case CHANGED -> {
                    List<String> diffs = new ArrayList<>();
                    if (!eq(oldService, newService))
                        diffs.add("service: " + oldService + " → " + newService);
                    if (!eq(oldVersion, newVersion))
                        diffs.add("version: " + oldVersion + " → " + newVersion);
                    if (!eq(oldState, newState))
                        diffs.add("state: " + oldState + " → " + newState);
                    if (!eq(oldBanner, newBanner))
                        diffs.add("banner changed");
                    yield String.format("[CHANGED] port %d/%s  %s",
                            port, protocol, String.join(", ", diffs));
                }
            };
        }
        private static boolean eq(String a, String b) {
            return (a == null ? "" : a).equals(b == null ? "" : b);
        }
    }

    public record DiffResult(
            String           oldTimestamp,
            String           newTimestamp,
            @SuppressWarnings("MismatchedQueryAndUpdateOfCollection") List<PortChange> changes,
            int              addedCount,
            int              removedCount,
            int              changedCount
    ) {
        public DiffResult {
            changes = List.copyOf(changes); // defensive immutable copy
        }
        public boolean hasChanges() { return !changes.isEmpty(); }
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Compare two XML export files.
     *
     * @param oldFile previous scan XML
     * @param newFile current  scan XML
     * @return diff result
     */
    public DiffResult diff(File oldFile, File newFile) throws IOException {
        ParsedScan old = parse(oldFile);
        ParsedScan neu = parse(newFile);
        return computeDiff(old, neu);
    }

    /**
     * Compare an in-memory list of results against an XML export file.
     *
     * @param oldFile        previous scan XML
     * @param currentResults current scan results (live list)
     * @return diff result
     */
    public DiffResult diffWithCurrent(File oldFile, List<PortScanResult> currentResults)
            throws IOException {
        ParsedScan old = parse(oldFile);
        ParsedScan neu = fromResults(currentResults);
        return computeDiff(old, neu);
    }

    // ── Core diff logic ───────────────────────────────────────────────────

    private DiffResult computeDiff(ParsedScan old, ParsedScan neu) {
        List<PortChange> changes = new ArrayList<>();

        // Ports in NEW but not in OLD → ADDED
        for (Map.Entry<Integer, PortEntry> e : neu.ports.entrySet()) {
            if (!old.ports.containsKey(e.getKey())) {
                PortEntry p = e.getValue();
                changes.add(new PortChange(p.port, ChangeType.ADDED,
                        "", p.service, "", p.version, "", p.banner,
                        "", p.state, p.protocol));
            }
        }

        // Ports in OLD but not in NEW → REMOVED
        for (Map.Entry<Integer, PortEntry> e : old.ports.entrySet()) {
            if (!neu.ports.containsKey(e.getKey())) {
                PortEntry p = e.getValue();
                changes.add(new PortChange(p.port, ChangeType.REMOVED,
                        p.service, "", p.version, "", p.banner, "",
                        p.state, "", p.protocol));
            }
        }

        // Ports in BOTH → check for changes
        for (Map.Entry<Integer, PortEntry> e : old.ports.entrySet()) {
            PortEntry o = e.getValue();
            PortEntry n = neu.ports.get(e.getKey());
            if (n == null) continue;
            if (!eq(o.service, n.service)
                    || !eq(o.version, n.version)
                    || !eq(o.state, n.state)
                    || !eq(o.banner, n.banner)) {
                changes.add(new PortChange(o.port, ChangeType.CHANGED,
                        o.service, n.service,
                        o.version, n.version,
                        o.banner,  n.banner,
                        o.state,   n.state,
                        o.protocol));
            }
        }

        changes.sort((a, b) -> {
            int t = a.type().compareTo(b.type());
            return t != 0 ? t : Integer.compare(a.port(), b.port());
        });

        long added   = changes.stream().filter(c -> c.type() == ChangeType.ADDED).count();
        long removed = changes.stream().filter(c -> c.type() == ChangeType.REMOVED).count();
        long changed = changes.stream().filter(c -> c.type() == ChangeType.CHANGED).count();

        return new DiffResult(old.timestamp, neu.timestamp, changes,
                (int) added, (int) removed, (int) changed);
    }

    // ── XML Parser ────────────────────────────────────────────────────────

    private ParsedScan parse(File file) throws IOException {
        String xml = Files.readString(file.toPath(), StandardCharsets.UTF_8);
        ParsedScan scan = new ParsedScan();
        scan.timestamp = extractTag(xml, "meta", "timestamp");

        Pattern portBlock = Pattern.compile("<port>(.*?)</port>",
                Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        Matcher m = portBlock.matcher(xml);
        while (m.find()) {
            String block = m.group(1);
            PortEntry e = new PortEntry();
            e.port     = parseInt(tag(block, "number"), 0);
            e.state    = tag(block, "state");
            e.service  = tag(block, "service");
            e.version  = tag(block, "version");
            e.protocol = tag(block, "protocol");
            e.banner   = tag(block, "banner");
            if (e.port > 0) scan.ports.put(e.port, e);
        }
        return scan;
    }

    private ParsedScan fromResults(List<PortScanResult> results) {
        ParsedScan scan = new ParsedScan();
        scan.timestamp = java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));
        for (PortScanResult r : results) {
            PortEntry e = new PortEntry();
            e.port     = r.getPort();
            e.state    = r.getState();
            e.service  = r.getService();
            e.version  = r.getVersion();
            e.protocol = r.getProtocol();
            e.banner   = r.getBanner();
            scan.ports.put(e.port, e);
        }
        return scan;
    }

    // ── Report formatter ──────────────────────────────────────────────────

    public static String formatReport(DiffResult diff) {
        if (!diff.hasChanges())
            return "Diff: no changes detected between scans.";

        StringBuilder sb = new StringBuilder();
        sb.append("=== Scan Diff Report ===\n");
        sb.append("Old scan : ").append(diff.oldTimestamp()).append("\n");
        sb.append("New scan : ").append(diff.newTimestamp()).append("\n");
        sb.append(String.format("Changes  : +%d added, -%d removed, ~%d changed%n%n",
                diff.addedCount(), diff.removedCount(), diff.changedCount()));

        if (diff.addedCount() > 0) {
            sb.append("── NEW OPEN PORTS ──────────────────────\n");
            diff.changes().stream()
                    .filter(c -> c.type() == ChangeType.ADDED)
                    .forEach(c -> sb.append("  ").append(c.summary()).append("\n"));
            sb.append("\n");
        }
        if (diff.removedCount() > 0) {
            sb.append("── CLOSED PORTS ────────────────────────\n");
            diff.changes().stream()
                    .filter(c -> c.type() == ChangeType.REMOVED)
                    .forEach(c -> sb.append("  ").append(c.summary()).append("\n"));
            sb.append("\n");
        }
        if (diff.changedCount() > 0) {
            sb.append("── CHANGED SERVICES / VERSIONS ─────────\n");
            diff.changes().stream()
                    .filter(c -> c.type() == ChangeType.CHANGED)
                    .forEach(c -> sb.append("  ").append(c.summary()).append("\n"));
        }
        return sb.toString();
    }

    // ── Micro-helpers ─────────────────────────────────────────────────────

    private String tag(String block, String tagName) {
        Matcher m = Pattern.compile("<" + tagName + ">([^<]*)</" + tagName + ">")
                .matcher(block);
        return m.find() ? unescapeXml(m.group(1)) : "";
    }

    private String extractTag(String xml, String tag, String attr) {
        Matcher m = Pattern.compile("<" + tag + "[^>]*" + attr + "=\"([^\"]+)\"")
                .matcher(xml);
        return m.find() ? m.group(1) : "";
    }

    private int parseInt(String s, int def) {
        try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return def; }
    }

    private String unescapeXml(String s) {
        return s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", "\"").replace("&apos;", "'");
    }

    private static boolean eq(String a, String b) {
        return (a == null ? "" : a).equals(b == null ? "" : b);
    }

    // ── Inner data classes ────────────────────────────────────────────────

    private static class ParsedScan {
        String timestamp = "";
        Map<Integer, PortEntry> ports = new LinkedHashMap<>();
    }

    private static class PortEntry {
        int    port;
        String state    = "";
        String service  = "";
        String version  = "";
        String protocol = "";
        String banner   = "";
    }
}
