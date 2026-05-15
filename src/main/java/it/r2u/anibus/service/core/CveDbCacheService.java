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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CVE Offline DB Cache — local NVD 2.0 API cache with periodic refresh.
 *
 * <p>Each CVE is stored as a tiny key=value flat file inside
 * {@code ~/.anibus/cve-cache/}.  A metadata line {@code lastUpdated} records
 * the Unix-epoch seconds when the entry was fetched so that stale records
 * can be refreshed transparently.
 */
public class CveDbCacheService {

    public record CveEntry(
            String cveId,
            String description,
            double cvssV3Score,
            String cvssV3Severity,
            String publishedDate,
            String lastModifiedDate
    ) {}

    private static final String CACHE_DIR = System.getProperty("user.home") + "/.anibus/cve-cache";
    private static final String NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=";

    // ------------------------------------------------------------------ public API

    /**
     * Look up a CVE, using local cache. If the cache entry is older than
     * {@code maxAgeHours} it is refreshed from the NVD 2.0 API.
     *
     * @param cveId       standard CVE identifier, e.g. {@code CVE-2021-44790}
     * @param maxAgeHours maximum acceptable cache age; use {@code 0} to force refresh
     * @return an {@link Optional} containing the entry, or empty if not found / unreachable
     */
    public static Optional<CveEntry> lookup(String cveId, int maxAgeHours) {
        if (cveId == null || !cveId.matches("CVE-\\d{4}-\\d{4,}")) return Optional.empty();

        File cache = cacheFile(cveId);
        if (cache.exists() && maxAgeHours > 0 && !isStale(cache, maxAgeHours)) {
            return parse(cache);
        }

        // Attempt to refresh from NVD
        try {
            String json = fetchNvd(cveId);
            if (json != null) {
                save(cveId, json, cache);
                return parse(cache);
            }
        } catch (IOException ignored) {
            // Fall through to cached data if available
        }

        // Return cached data even if stale when network is unavailable
        if (cache.exists()) return parse(cache);
        return Optional.empty();
    }

    /** Convenience overload using a default max-age of 168 hours (7 days). */
    public static Optional<CveEntry> lookup(String cveId) {
        return lookup(cveId, 168);
    }

    /**
     * Refresh all cached entries that are older than {@code maxAgeHours}.
     * This is a best-effort operation; network errors are silently ignored.
     *
     * @return number of entries successfully refreshed
     */
    public static int refreshStale(int maxAgeHours) {
        File dir = new File(CACHE_DIR);
        if (!dir.isDirectory()) return 0;

        int count = 0;
        File[] files = dir.listFiles((d, n) -> n.endsWith(".cvecache"));
        if (files == null) return 0;
        for (File f : files) {
            if (isStale(f, maxAgeHours)) {
                String id = f.getName().replace(".cvecache", "");
                if (lookup(id, 0).isPresent()) count++;
            }
        }
        return count;
    }

    /** Formats a list of CveEntry records into a human-readable report. */
    public static String formatReport(List<CveEntry> entries) {
        if (entries == null || entries.isEmpty()) return "ℹ No CVE entries to display.";

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("CVE Database Report (%d entries)%n", entries.size()));
        sb.append("─".repeat(60)).append(System.lineSeparator());

        for (CveEntry e : entries) {
            String sevIcon = switch (e.cvssV3Severity()) {
                case "CRITICAL" -> "[CRITICAL]";
                case "HIGH"     -> "[HIGH]    ";
                case "MEDIUM"   -> "[MEDIUM]  ";
                case "LOW"      -> "[LOW]     ";
                default         -> "[NONE]    ";
            };
            sb.append(String.format("%s %s  CVSS %.1f%n", sevIcon, e.cveId(), e.cvssV3Score()));
            sb.append("  Desc  : ").append(truncate(e.description(), 120)).append(System.lineSeparator());
            sb.append("  Pub   : ").append(e.publishedDate()).append(System.lineSeparator());
            sb.append("  Mod   : ").append(e.lastModifiedDate()).append(System.lineSeparator());
            sb.append("  NVD   : https://nvd.nist.gov/vuln/detail/").append(e.cveId()).append(System.lineSeparator());
            sb.append("  MITRE : https://cve.mitre.org/cgi-bin/cvename.cgi?name=").append(e.cveId()).append(System.lineSeparator());
            sb.append(System.lineSeparator());
        }
        return sb.toString().trim();
    }

    // ------------------------------------------------------------------ internals

    private static File cacheFile(String cveId) {
        File dir = new File(CACHE_DIR);
        if (!dir.exists()) dir.mkdirs();
        return new File(dir, cveId + ".cvecache");
    }

    private static boolean isStale(File f, int maxAgeHours) {
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("lastUpdated=")) {
                    long epoch = Long.parseLong(line.substring("lastUpdated=".length()).trim());
                    Instant saved = Instant.ofEpochSecond(epoch);
                    return saved.isBefore(Instant.now().minus(maxAgeHours, ChronoUnit.HOURS));
                }
            }
        } catch (IOException | NumberFormatException ignored) {
            // treat as stale
        }
        return true;
    }

    /** Fetches raw JSON from NVD 2.0 API. Returns null on HTTP error. */
    private static String fetchNvd(String cveId) throws IOException {
        URI uri = URI.create(NVD_API + cveId);
        HttpURLConnection con = (HttpURLConnection) uri.toURL().openConnection();
        con.setRequestMethod("GET");
        con.setConnectTimeout(8_000);
        con.setReadTimeout(15_000);
        con.setRequestProperty("Accept", "application/json");

        int code = con.getResponseCode();
        if (code != 200) return null;

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
        }
        return sb.toString();
    }

    /** Parses the NVD JSON response and persists a flat key=value file. */
    @SuppressWarnings("ResultOfMethodCallIgnored")
    private static void save(String cveId, String json, File dest) throws IOException {
        String desc        = extractJson(json, "\"value\"\\s*:\\s*\"([^\"]+)\"", 1);
        String cvssScore   = extractJson(json, "\"baseScore\"\\s*:\\s*([\\d.]+)", 1);
        String cvssRating  = extractJson(json, "\"baseSeverity\"\\s*:\\s*\"([A-Z]+)\"", 1);
        String published   = extractJson(json, "\"published\"\\s*:\\s*\"([^\"]+)\"", 1);
        String modified    = extractJson(json, "\"lastModified\"\\s*:\\s*\"([^\"]+)\"", 1);

        if (desc == null) desc = "No description available";
        if (cvssScore == null) cvssScore = "0.0";
        if (cvssRating == null) cvssRating = "NONE";
        if (published == null) published = "N/A";
        if (modified == null) modified = "N/A";

        dest.getParentFile().mkdirs();
        try (FileWriter fw = new FileWriter(dest)) {
            fw.write("cveId=" + cveId + "\n");
            fw.write("description=" + desc.replace("\n", " ") + "\n");
            fw.write("cvssV3Score=" + cvssScore + "\n");
            fw.write("cvssV3Severity=" + cvssRating + "\n");
            fw.write("publishedDate=" + published + "\n");
            fw.write("lastModifiedDate=" + modified + "\n");
            fw.write("lastUpdated=" + Instant.now().getEpochSecond() + "\n");
        }
    }

    private static Optional<CveEntry> parse(File f) {
        String id = null, desc = null, sev = "NONE", pub = "N/A", mod = "N/A";
        double score = 0.0;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {
                if      (line.startsWith("cveId="))           id   = line.substring("cveId=".length());
                else if (line.startsWith("description="))     desc = line.substring("description=".length());
                else if (line.startsWith("cvssV3Score="))     score = Double.parseDouble(line.substring("cvssV3Score=".length()));
                else if (line.startsWith("cvssV3Severity="))  sev  = line.substring("cvssV3Severity=".length());
                else if (line.startsWith("publishedDate="))   pub  = line.substring("publishedDate=".length());
                else if (line.startsWith("lastModifiedDate="))mod  = line.substring("lastModifiedDate=".length());
            }
        } catch (IOException | NumberFormatException e) {
            return Optional.empty();
        }
        if (id == null || desc == null) return Optional.empty();
        return Optional.of(new CveEntry(id, desc, score, sev, pub, mod));
    }

    private static String extractJson(String json, String regex, int group) {
        Matcher m = Pattern.compile(regex).matcher(json);
        return m.find() ? m.group(group) : null;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    /** Collects all locally cached entries and returns them as a list. */
    public static List<CveEntry> listCached() {
        List<CveEntry> result = new ArrayList<>();
        File dir = new File(CACHE_DIR);
        if (!dir.isDirectory()) return result;
        File[] files = dir.listFiles((d, n) -> n.endsWith(".cvecache"));
        if (files == null) return result;
        for (File f : files) {
            parse(f).ifPresent(result::add);
        }
        return result;
    }
}
