package it.r2u.anibus.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes web page source code for leaked sensitive information
 * such as database connection strings, API keys, and credentials.
 */
public class WebSourceAnalyzer {
    
    private static final int TIMEOUT = 5000;
    private static final int MAX_SIZE = 5 * 1024 * 1024; // 5MB max
    
    public static class LeakInfo {
        private final String type;
        private final String value;
        private final String context;
        private final int priority;
        private final int count;
        private final String service;
        private final boolean placeholder;

        /** Full constructor. */
        public LeakInfo(String type, String value, String context,
                        int priority, String service, boolean placeholder) {
            this(type, value, context, priority, service, placeholder, 1);
        }

        /** Legacy 3-arg constructor – priority and placeholder inferred automatically. */
        public LeakInfo(String type, String value, String context) {
            this(type, value, context, inferPriority(type), null, isPlaceholderValue(value), 1);
        }

        private LeakInfo(String type, String value, String context,
                         int priority, String service, boolean placeholder, int count) {
            this.type = type;
            this.value = value;
            this.context = context;
            this.priority = priority;
            this.service = service;
            this.placeholder = placeholder;
            this.count = count;
        }

        /** Returns immutable copy with updated occurrence count (for deduplication). */
        public LeakInfo withCount(int newCount) {
            return new LeakInfo(type, value, context, priority, service, placeholder, newCount);
        }

        /** Returns immutable copy tagged with a microservice name. */
        public LeakInfo withService(String svc) {
            return new LeakInfo(type, value, context, priority, svc, placeholder, count);
        }

        public String getType()    { return type; }
        public String getValue()   { return value; }
        public String getContext() { return context; }
        public int getPriority()   { return priority; }
        public int getCount()      { return count; }
        public String getService() { return service; }
        public boolean isPlaceholder() { return placeholder; }

        @Override
        public String toString() {
            return type + ": " + value;
        }

        /** Maps a finding type label to a numeric priority 1–10. */
        public static int inferPriority(String type) {
            if (type == null) return 5;
            String t = type.toLowerCase();
            if (t.contains("private key") || t.contains("connection with credentials")) return 10;
            if (t.contains("access token") || t.contains("aws access key") || t.contains("jwt")) return 9;
            if (t.contains("database password") || t.contains("kv pair")) return 8;
            if (t.contains("api key") || t.contains("firebase") || t.contains("password")) return 7;
            if (t.contains("public key") || t.contains("certificate")
                    || t.contains("token→endpoint") || t.contains("graphql")) return 6;
            if (t.contains("database host") || t.contains("database configuration")
                    || t.contains("orm") || t.contains("sequelize")) return 5;
            if (t.contains("database name") || t.contains("connection string")
                    || t.contains("cloud database")) return 4;
            if (t.contains("environment variable") || t.contains("connection reference")) return 2;
            return 3;
        }

        /** Returns true when the value looks like a known placeholder / test value. */
        public static boolean isPlaceholderValue(String value) {
            if (value == null || value.isBlank()) return false;
            String v = value.toLowerCase().trim();
            // Strip "[Priority N] " prefix added by DB analyzer
            if (v.startsWith("[priority")) {
                int end = v.indexOf(']');
                if (end > 0) v = v.substring(end + 1).trim();
            }
            java.util.Set<String> exact = java.util.Set.of(
                "password", "123456", "12345678", "qwerty", "test", "example",
                "placeholder", "xxx", "null", "undefined", "your_password",
                "your_api_key", "changeme", "secret", "default", "sample",
                "incorrect_password", "wrong_password", "invalid_password",
                "enter_password", "type_password", "your_secret", "my_password",
                "admin", "root", "guest", "user", "pass", "pwd"
            );
            if (exact.contains(v)) return true;

            // Handle composite values like "Username: admin | Password: incorrect_password".
            java.util.regex.Matcher credentialLike = java.util.regex.Pattern.compile(
                "(?:pass(?:word)?|pwd|secret)\\s*[:=]\\s*([^|,;\\s]+)",
                java.util.regex.Pattern.CASE_INSENSITIVE
            ).matcher(v);
            while (credentialLike.find()) {
                String extracted = credentialLike.group(1);
                if (extracted != null) {
                    String normalized = extracted.toLowerCase()
                        .replaceAll("^[\\\"'`]+|[\\\"'`,;]+$", "");
                    if (exact.contains(normalized)) return true;
                    if (normalized.startsWith("incorrect_") || normalized.startsWith("wrong_")
                            || normalized.startsWith("invalid_") || normalized.startsWith("enter_")
                            || normalized.startsWith("your_") || normalized.startsWith("test_")) {
                        return true;
                    }
                }
            }

            return v.startsWith("incorrect_") || v.startsWith("wrong_")
                || v.startsWith("invalid_") || v.startsWith("enter_")
                || v.startsWith("your_") || v.startsWith("test_")
                || v.length() < 3;
        }
    }
    
    /**
     * Analyzes a web page for sensitive data leaks.
     * @param host The hostname
     * @param port The port (usually 80 or 443)
     * @param useHttps Whether to use HTTPS
     * @return List of detected leaks
     */
    public static List<LeakInfo> analyzeWebPage(String host, int port, boolean useHttps) {
        List<LeakInfo> leaks = new ArrayList<>();
        
        try {
            String protocol = useHttps ? "https" : "http";
            String urlStr = protocol + "://" + host + (port == 80 || port == 443 ? "" : ":" + port);
            
            HttpURLConnection conn = (HttpURLConnection) new URI(urlStr).toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            conn.setInstanceFollowRedirects(true);
            
            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                return leaks;
            }
            
            // Read page source
            StringBuilder source = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                int totalBytes = 0;
                while ((line = reader.readLine()) != null && totalBytes < MAX_SIZE) {
                    source.append(line).append("\n");
                    totalBytes += line.length();
                }
            }
            
            String pageSource = source.toString();
            
            // Analyze for sensitive patterns
            leaks.addAll(findDatabaseConnections(pageSource));
            leaks.addAll(findAPIKeys(pageSource));
            leaks.addAll(findInternalIPs(pageSource));
            leaks.addAll(findEmails(pageSource));
            
            // Also check common JS files
            leaks.addAll(checkCommonJSFiles(host, port, useHttps));
            
        } catch (IOException | URISyntaxException e) {
            // Silently ignore - this is a best-effort analysis
        }
        
        return leaks;
    }
    
    private static List<LeakInfo> findDatabaseConnections(String source) {
        List<LeakInfo> leaks = new ArrayList<>();

        // MongoDB
        findMatches(source,
            Pattern.compile("mongodb(?:\\+srv)?://[^\\s\"'<>]+"),
            "MongoDB Connection", leaks);

        // MySQL / MariaDB
        findMatches(source,
            Pattern.compile("(?:mysql|mariadb)://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "MySQL/MariaDB Connection", leaks);

        // PostgreSQL / CockroachDB / Neon
        findMatches(source,
            Pattern.compile("(?:postgresql|postgres|cockroachdb)://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "PostgreSQL Connection", leaks);

        // Redis / Rediss (TLS)
        findMatches(source,
            Pattern.compile("rediss?://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "Redis Connection", leaks);

        // Elasticsearch / OpenSearch
        findMatches(source,
            Pattern.compile("(?:elasticsearch|opensearch)://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "Elasticsearch/OpenSearch Connection", leaks);

        // Cassandra
        findMatches(source,
            Pattern.compile("cassandra://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "Cassandra Connection", leaks);

        // Neo4j
        findMatches(source,
            Pattern.compile("neo4j(?:\\+s)?://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "Neo4j Connection", leaks);

        // ClickHouse
        findMatches(source,
            Pattern.compile("clickhouse://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "ClickHouse Connection", leaks);

        // InfluxDB
        findMatches(source,
            Pattern.compile("influxdb://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "InfluxDB Connection", leaks);

        // CouchDB
        findMatches(source,
            Pattern.compile("couchdb://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "CouchDB Connection", leaks);

        // Couchbase
        findMatches(source,
            Pattern.compile("couchbase(?:s)?://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "Couchbase Connection", leaks);

        // RabbitMQ / AMQP
        findMatches(source,
            Pattern.compile("amqps?://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "RabbitMQ/AMQP Connection", leaks);

        // MSSQL
        findMatches(source,
            Pattern.compile("mssqls?://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "MSSQL Connection", leaks);

        // Oracle
        findMatches(source,
            Pattern.compile("oracle://[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "Oracle Connection", leaks);

        // JDBC (any)
        findMatches(source,
            Pattern.compile("jdbc:[a-z]+:(?:thin:)?//[^\\s\"'<>]+", Pattern.CASE_INSENSITIVE),
            "JDBC Connection", leaks);

        // Firebase Realtime DB
        findMatches(source,
            Pattern.compile("https://[a-zA-Z0-9-]+\\.firebaseio\\.com"),
            "Firebase Realtime Database URL", leaks);

        // Supabase
        findMatches(source,
            Pattern.compile("https://[a-zA-Z0-9-]+\\.supabase\\.co"),
            "Supabase URL", leaks);

        // PlanetScale
        findMatches(source,
            Pattern.compile("[a-zA-Z0-9-]+\\.psdb\\.cloud"),
            "PlanetScale Connection", leaks);

        // Neon serverless Postgres
        findMatches(source,
            Pattern.compile("[a-zA-Z0-9-]+\\.neon\\.tech"),
            "Neon Serverless Postgres URL", leaks);

        // Turso / libSQL
        findMatches(source,
            Pattern.compile("libsql://[^\\s\"'<>]+"),
            "Turso/libSQL Connection", leaks);

        // DynamoDB endpoint hints
        findMatches(source,
            Pattern.compile("dynamodb\\.[a-z0-9-]+\\.amazonaws\\.com"),
            "DynamoDB Endpoint", leaks);

        // ADO.NET MSSQL connection strings
        findMatches(source,
            Pattern.compile("Server=[^;\\s]+;\\s*Database=[^;\\s]+;[^\"'<>]*Password=[^;\"'<>]+", Pattern.CASE_INSENSITIVE),
            "MSSQL ADO.NET Connection String", leaks);

        return leaks;
    }
    
    private static List<LeakInfo> findAPIKeys(String source) {
        List<LeakInfo> leaks = new ArrayList<>();
        
        // Generic API keys
        findMatches(source,
            Pattern.compile("(?:api[_-]?key|apikey)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{20,})['\"]", Pattern.CASE_INSENSITIVE),
            "API Key",
            leaks);
        
        // Access tokens
        findMatches(source,
            Pattern.compile("(?:access[_-]?token|token)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-\\.]{20,})['\"]", Pattern.CASE_INSENSITIVE),
            "Access Token",
            leaks);
        
        // AWS keys
        findMatches(source,
            Pattern.compile("(AKIA[0-9A-Z]{16})"),
            "AWS Access Key",
            leaks);
        
        return leaks;
    }
    
    private static List<LeakInfo> findInternalIPs(String source) {
        List<LeakInfo> leaks = new ArrayList<>();
        
        findMatches(source,
            Pattern.compile("(?:10\\.\\d+\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+)"),
            "Internal IP Address",
            leaks);
        
        return leaks;
    }
    
    private static List<LeakInfo> findEmails(String source) {
        List<LeakInfo> leaks = new ArrayList<>();
        
        findMatches(source,
            Pattern.compile("([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})"),
            "Email Address",
            leaks);
        
        return leaks;
    }
    
    private static void findMatches(String source, Pattern pattern, String type, List<LeakInfo> leaks) {
        Matcher matcher = pattern.matcher(source);
        while (matcher.find() && leaks.size() < 50) { // Limit to 50 findings
            String match = matcher.group(matcher.groupCount() > 0 ? 1 : 0);
            
            // Get context (50 chars before and after)
            int start = Math.max(0, matcher.start() - 50);
            int end = Math.min(source.length(), matcher.end() + 50);
            String context = source.substring(start, end).replaceAll("\\s+", " ");
            
            leaks.add(new LeakInfo(type, match, context));
        }
    }
    
    private static List<LeakInfo> checkCommonJSFiles(String host, int port, boolean useHttps) {
        List<LeakInfo> leaks = new ArrayList<>();
        
        String[] commonPaths = {
            "/config.js",
            "/app.js",
            "/main.js",
            "/bundle.js",
            "/env.js"
        };
        
        String protocol = useHttps ? "https" : "http";
        String baseUrl = protocol + "://" + host + (port == 80 || port == 443 ? "" : ":" + port);
        
        for (String path : commonPaths) {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URI(baseUrl + path).toURL().openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(TIMEOUT);
                conn.setReadTimeout(TIMEOUT);
                conn.setRequestProperty("User-Agent", "Mozilla/5.0");
                
                if (conn.getResponseCode() == 200) {
                    StringBuilder js = new StringBuilder();
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                        String line;
                        int totalBytes = 0;
                        while ((line = reader.readLine()) != null && totalBytes < MAX_SIZE) {
                            js.append(line).append("\n");
                            totalBytes += line.length();
                        }
                    }
                    
                    String jsSource = js.toString();
                    leaks.addAll(findDatabaseConnections(jsSource));
                    leaks.addAll(findAPIKeys(jsSource));
                    leaks.addAll(findInternalIPs(jsSource));
                }
            } catch (IOException | URISyntaxException e) {
                // Continue checking other files
            }
        }
        
        return leaks;
    }
}
