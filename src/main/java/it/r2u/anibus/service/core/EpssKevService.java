package it.r2u.anibus.service.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EPSS + KEV Prioritization Service.
 *
 * <ul>
 *   <li><b>EPSS</b> — Exploit Prediction Scoring System (api.first.org).  Returns a probability
 *       score [0.0 – 1.0] and a percentile indicating how likely a CVE is to be exploited within
 *       30 days.</li>
 *   <li><b>KEV</b> — CISA Known Exploited Vulnerabilities catalogue.  The catalogue is downloaded
 *       once and cached locally; individual lookups are O(1) set membership tests.</li>
 * </ul>
 *
 * <p>All network activity is best-effort: failures return empty / false rather than throwing.
 */
public class EpssKevService {

    public record EpssEntry(
            String cveId,
            double epssScore,
            double epssPercentile,
            String date
    ) {
        /** Returns a human-readable risk label based on the EPSS score. */
        public String riskLabel() {
            if (epssScore >= 0.7) return "CRITICAL-LIKELY";
            if (epssScore >= 0.4) return "HIGH-LIKELY";
            if (epssScore >= 0.1) return "MEDIUM-LIKELY";
            return "LOW-LIKELY";
        }
    }

    // ── paths ──────────────────────────────────────────────────────────────────
    private static final String CACHE_DIR  = System.getProperty("user.home") + "/.anibus/cve-cache";
    private static final String KEV_FILE   = CACHE_DIR + "/cisa-kev.ids";
    private static final String EPSS_EXT   = ".epss";

    // ── EPSS API ────────────────────────────────────────────────────────────────
    private static final String EPSS_API = "https://api.first.org/data/v1/epss?cve=";

    // ── KEV source ──────────────────────────────────────────────────────────────
    private static final String KEV_URL  =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    // In-memory KEV set (populated lazily)
    private static final Set<String> KEV_SET = Collections.synchronizedSet(new HashSet<>());
    private static volatile boolean kevLoaded = false;

    // ── public API ─────────────────────────────────────────────────────────────

    /**
     * Fetches EPSS data for {@code cveId}, using a local cache.
     * Cache is considered stale after {@code maxAgeHours}; use 0 to force refresh.
     */
    public static Optional<EpssEntry> getEpss(String cveId, int maxAgeHours) {
        if (!isCveId(cveId)) return Optional.empty();

        File cache = new File(CACHE_DIR, cveId + EPSS_EXT);
        if (cache.exists() && maxAgeHours > 0 && !isStale(cache, maxAgeHours)) {
            return parseEpss(cache);
        }

        try {
            String json = fetchEpss(cveId);
            if (json != null) {
                saveEpss(cveId, json, cache);
                return parseEpss(cache);
            }
        } catch (IOException ignored) {
            // fall through to cached data
        }

        if (cache.exists()) return parseEpss(cache);
        return Optional.empty();
    }

    /** Convenience overload with 24-hour max age. */
    public static Optional<EpssEntry> getEpss(String cveId) {
        return getEpss(cveId, 24);
    }

    /**
     * Returns {@code true} when {@code cveId} appears in the CISA KEV catalogue.
     * The KEV list is cached locally and refreshed if older than {@code maxAgeHours}.
     */
    public static boolean isKnownExploited(String cveId, int maxAgeHours) {
        if (!isCveId(cveId)) return false;
        ensureKevLoaded(maxAgeHours);
        return KEV_SET.contains(cveId);
    }

    /** Convenience overload with 168-hour (7-day) max age. */
    public static boolean isKnownExploited(String cveId) {
        return isKnownExploited(cveId, 168);
    }

    /**
     * Forces a refresh of the local KEV cache from CISA.
     *
     * @return number of CVE IDs loaded, or -1 on error
     */
    public static int refreshKev() {
        return downloadKev();
    }

    /** Formats EPSS + KEV enrichment summary for a CVE. */
    public static String formatReport(String cveId, Optional<EpssEntry> epss, boolean kev) {
        StringBuilder sb = new StringBuilder();
        sb.append("EPSS / KEV enrichment for ").append(cveId).append(System.lineSeparator());
        sb.append("─".repeat(50)).append(System.lineSeparator());

        if (epss.isPresent()) {
            EpssEntry e = epss.get();
            sb.append(String.format("  EPSS Score      : %.4f  (%s)%n", e.epssScore(), e.riskLabel()));
            sb.append(String.format("  EPSS Percentile : %.1f%%%n", e.epssPercentile() * 100));
            sb.append(String.format("  EPSS Date       : %s%n", e.date()));
        } else {
            sb.append("  EPSS Score      : N/A (not reachable or unknown CVE)").append(System.lineSeparator());
        }

        sb.append(System.lineSeparator());
        if (kev) {
            sb.append("  ⚠ CISA KEV      : YES — listed in Known Exploited Vulnerabilities catalogue!").append(System.lineSeparator());
            sb.append("  Remediation     : https://www.cisa.gov/known-exploited-vulnerabilities-catalog").append(System.lineSeparator());
        } else {
            sb.append("  CISA KEV        : not currently listed").append(System.lineSeparator());
        }
        return sb.toString().trim();
    }

    // ── EPSS internals ─────────────────────────────────────────────────────────

    private static String fetchEpss(String cveId) throws IOException {
        URI uri = URI.create(EPSS_API + cveId);
        HttpURLConnection con = (HttpURLConnection) uri.toURL().openConnection();
        con.setRequestMethod("GET");
        con.setConnectTimeout(8_000);
        con.setReadTimeout(15_000);
        con.setRequestProperty("Accept", "application/json");
        if (con.getResponseCode() != 200) return null;
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
        }
        return sb.toString();
    }

    private static void saveEpss(String cveId, String json, File dest) throws IOException {
        String score      = firstMatch(json, "\"epss\"\\s*:\\s*\"([\\d.]+)\"");
        String percentile = firstMatch(json, "\"percentile\"\\s*:\\s*\"([\\d.]+)\"");
        String date       = firstMatch(json, "\"date\"\\s*:\\s*\"([^\"]+)\"");

        if (score == null) score = "0.0";
        if (percentile == null) percentile = "0.0";
        if (date == null) date = "N/A";

        ensureParentDir(dest);
        try (FileWriter fw = new FileWriter(dest)) {
            fw.write("cveId=" + cveId + "\n");
            fw.write("epssScore=" + score + "\n");
            fw.write("epssPercentile=" + percentile + "\n");
            fw.write("date=" + date + "\n");
            fw.write("lastUpdated=" + Instant.now().getEpochSecond() + "\n");
        }
    }

    private static Optional<EpssEntry> parseEpss(File f) {
        String id = null, date = "N/A";
        double score = 0.0, pct = 0.0;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                if      (line.startsWith("cveId="))          id   = line.substring("cveId=".length());
                else if (line.startsWith("epssScore="))      score = Double.parseDouble(line.substring("epssScore=".length()));
                else if (line.startsWith("epssPercentile=")) pct  = Double.parseDouble(line.substring("epssPercentile=".length()));
                else if (line.startsWith("date="))           date = line.substring("date=".length());
            }
        } catch (IOException | NumberFormatException e) {
            return Optional.empty();
        }
        if (id == null) return Optional.empty();
        return Optional.of(new EpssEntry(id, score, pct, date));
    }

    // ── KEV internals ──────────────────────────────────────────────────────────

    private static void ensureKevLoaded(int maxAgeHours) {
        if (kevLoaded) return;
        File f = new File(KEV_FILE);
        if (f.exists() && !isStale(f, maxAgeHours)) {
            loadKevFromFile(f);
        } else {
            downloadKev();
        }
    }

    private static int downloadKev() {
        try {
            URI uri = URI.create(KEV_URL);
            HttpURLConnection con = (HttpURLConnection) uri.toURL().openConnection();
            con.setRequestMethod("GET");
            con.setConnectTimeout(10_000);
            con.setReadTimeout(30_000);
            con.setRequestProperty("Accept", "application/json");
            if (con.getResponseCode() != 200) return -1;

            StringBuilder json = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) json.append(line);
            }

            // Extract all CVE IDs from the JSON (cveID field)
            Pattern p = Pattern.compile("\"cveID\"\\s*:\\s*\"(CVE-\\d{4}-\\d{4,})\"");
            Matcher m = p.matcher(json);
            Set<String> ids = new HashSet<>();
            while (m.find()) ids.add(m.group(1));

            // Persist to file (one ID per line + timestamp on first line)
            File dest = new File(KEV_FILE);
            ensureParentDir(dest);
            try (FileWriter fw = new FileWriter(dest)) {
                fw.write("lastUpdated=" + Instant.now().getEpochSecond() + "\n");
                for (String id : ids) fw.write(id + "\n");
            }

            KEV_SET.clear();
            KEV_SET.addAll(ids);
            kevLoaded = true;
            return ids.size();

        } catch (IOException e) {
            return -1;
        }
    }

    private static void loadKevFromFile(File f) {
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            Set<String> ids = new HashSet<>();
            while ((line = br.readLine()) != null) {
                if (line.startsWith("CVE-")) ids.add(line.trim());
            }
            KEV_SET.clear();
            KEV_SET.addAll(ids);
            kevLoaded = true;
        } catch (IOException ignored) {
            // leave kevLoaded = false so it retries on next call
        }
    }

    // ── utilities ──────────────────────────────────────────────────────────────

    private static boolean isCveId(String s) {
        return s != null && s.matches("CVE-\\d{4}-\\d{4,}");
    }

    private static boolean isStale(File f, int maxAgeHours) {
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("lastUpdated=")) {
                    long epoch = Long.parseLong(line.substring("lastUpdated=".length()).trim());
                    return Instant.ofEpochSecond(epoch)
                                  .isBefore(Instant.now().minus(maxAgeHours, ChronoUnit.HOURS));
                }
            }
        } catch (IOException | NumberFormatException ignored) {
            // treat as stale
        }
        return true;
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    private static void ensureParentDir(File f) {
        if (f.getParentFile() != null) f.getParentFile().mkdirs();
    }

    private static String firstMatch(String text, String regex) {
        Matcher m = Pattern.compile(regex).matcher(text);
        return m.find() ? m.group(1) : null;
    }
}
