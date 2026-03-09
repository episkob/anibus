package it.r2u.anibus.service;

import it.r2u.anibus.model.*;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Advanced JavaScript source code analyzer for security research and backend infrastructure mapping.
 * Provides comprehensive analysis including endpoint mapping, data flow analysis, 
 * database schema inference, and architectural pattern detection.
 */
public class JavaScriptSecurityAnalyzer {
    
    /**
     * Analysis depth modes for different levels of JS security analysis.
     */
    public enum AnalysisDepth {
        BASIC("Basic", "Quick analysis with basic endpoint and security checks"),
        DEEP("Deep", "Thorough analysis with advanced pattern detection and DB credentials extraction"),
        COMPREHENSIVE("Comprehensive", "Complete security audit with architectural analysis and ranked threat assessment");
        
        private final String displayName;
        private final String description;
        
        AnalysisDepth(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }
        
        public String getDisplayName() { return displayName; }
        public String getDescription() { return description; }
        
        public static AnalysisDepth fromString(String str) {
            if (str == null) return BASIC;
            switch (str.trim()) {
                case "Deep": return DEEP;
                case "Comprehensive": return COMPREHENSIVE;
                default: return BASIC;
            }
        }
    }

    private static final int TIMEOUT = 10000;
    private static final int MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    private static final int MAX_CONCURRENT_REQUESTS = 5;
    private final ExecutorService executor = Executors.newFixedThreadPool(MAX_CONCURRENT_REQUESTS);

    /**
     * Performs comprehensive analysis of JavaScript source code from a target URL.
     * 
     * @param targetUrl The base URL to analyze
     * @return Comprehensive analysis result including all discovered information
     */
    public JavaScriptAnalysisResult analyzeTarget(String targetUrl) {
        return analyzeTarget(targetUrl, AnalysisDepth.COMPREHENSIVE);
    }
    
    /**
     * Performs analysis with specified depth level.
     * 
     * @param targetUrl The base URL to analyze
     * @param depth Analysis depth level
     * @return Analysis result tailored to the specified depth
     */
    public JavaScriptAnalysisResult analyzeTarget(String targetUrl, AnalysisDepth depth) {
        long startTime = System.currentTimeMillis();
        List<String> errors = new ArrayList<>();
        
        // Clear inline cache from previous runs
        inlineScriptContents.clear();
        
        try {
            // Discover JavaScript files
            List<String> jsFiles = discoverJavaScriptFiles(targetUrl);
            
            // Download and analyze all JS files concurrently
            Map<String, String> jsContents = downloadJavaScriptFiles(jsFiles);
            
            // Combine all JavaScript content for comprehensive analysis
            String combinedJs = String.join("\n", jsContents.values());
            
            // Perform analysis based on depth level
            List<EndpointInfo> endpoints = analyzeEndpoints(combinedJs, depth);
            List<DataStructureInfo> dataStructures = (depth == AnalysisDepth.BASIC) ? 
                new ArrayList<>() : analyzeDataStructures(combinedJs);
            List<DatabaseSchemaInfo> databaseSchemas = (depth == AnalysisDepth.BASIC) ? 
                new ArrayList<>() : inferDatabaseSchemas(combinedJs, dataStructures);
            List<WebSourceAnalyzer.LeakInfo> sensitiveInfo = findSensitiveInformation(combinedJs, depth);
            ArchitectureInfo architecture = (depth == AnalysisDepth.COMPREHENSIVE) ? 
                analyzeArchitecture(combinedJs, endpoints) : null;
            
            // Sort and rank results based on depth
            sensitiveInfo = rankAndFilterSensitiveInfo(sensitiveInfo, depth);
            endpoints = rankAndFilterEndpoints(endpoints, depth);
            
            long analysisTime = System.currentTimeMillis() - startTime;
            
            return new JavaScriptAnalysisResult(
                targetUrl, analysisTime, endpoints, dataStructures, 
                databaseSchemas, sensitiveInfo, architecture, 
                new ArrayList<>(jsFiles), errors
            );
            
        } catch (Exception e) {
            errors.add("Analysis failed: " + e.getMessage());
            return new JavaScriptAnalysisResult(
                targetUrl, System.currentTimeMillis() - startTime,
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), 
                new ArrayList<>(), null, new ArrayList<>(), errors
            );
        }
    }

    /**
     * Discovers JavaScript files from the target URL including common paths and HTML references.
     * Also extracts inline script content from the HTML page.
     */
    private List<String> discoverJavaScriptFiles(String baseUrl) throws Exception {
        Set<String> jsFiles = new LinkedHashSet<>();

        // Step 1: Fetch the HTML page (with HTTPS + redirect support)
        String htmlContent = fetchPageContent(baseUrl);
        if (htmlContent != null && !htmlContent.isEmpty()) {
            // Step 2: Extract external <script src="..."> references (handles hashed filenames, query strings, CDN URLs)
            Pattern srcPattern = Pattern.compile(
                "<script[^>]+src\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>",
                Pattern.CASE_INSENSITIVE);
            Matcher srcMatcher = srcPattern.matcher(htmlContent);
            while (srcMatcher.find()) {
                String src = srcMatcher.group(1).trim();
                String fullUrl = resolveUrl(baseUrl, src);
                if (fullUrl != null) {
                    jsFiles.add(fullUrl);
                }
            }

            // Step 3: Also extract <link rel="modulepreload" href="..."> references (Vite, modern bundlers)
            Pattern modulePattern = Pattern.compile(
                "<link[^>]+rel\\s*=\\s*[\"']modulepreload[\"'][^>]+href\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>",
                Pattern.CASE_INSENSITIVE);
            Matcher moduleMatcher = modulePattern.matcher(htmlContent);
            while (moduleMatcher.find()) {
                String href = moduleMatcher.group(1).trim();
                String fullUrl = resolveUrl(baseUrl, href);
                if (fullUrl != null) {
                    jsFiles.add(fullUrl);
                }
            }

            // Step 4: Extract inline <script>...</script> content and store as virtual entries
            Pattern inlinePattern = Pattern.compile(
                "<script(?:\\s[^>]*)?>([\\s\\S]*?)</script>",
                Pattern.CASE_INSENSITIVE);
            Matcher inlineMatcher = inlinePattern.matcher(htmlContent);
            int inlineIdx = 0;
            while (inlineMatcher.find()) {
                String content = inlineMatcher.group(1).trim();
                // Skip empty scripts and scripts that are just src references (already handled above)
                if (!content.isEmpty() && content.length() > 10) {
                    String key = "inline://" + baseUrl + "#script-" + (inlineIdx++);
                    inlineScriptContents.put(key, content);
                    jsFiles.add(key);
                }
            }

            // Step 5: Store HTML itself for analysis (meta tags, data-attributes, JSON-LD, embedded configs)
            String htmlKey = "html://" + baseUrl + "#page-source";
            inlineScriptContents.put(htmlKey, htmlContent);
            jsFiles.add(htmlKey);
        }

        // Step 6: Try common paths as fallback (only if nothing found from HTML)
        if (jsFiles.isEmpty()) {
            String[] commonPaths = {
                "/js/app.js", "/js/main.js", "/js/bundle.js", "/js/vendor.js",
                "/assets/js/app.js", "/assets/js/main.js", "/assets/application.js",
                "/static/js/main.js", "/static/js/bundle.js", "/dist/main.js",
                "/build/static/js/main.js", "/public/js/app.js",
                "/app.js", "/main.js", "/bundle.js"
            };
            for (String path : commonPaths) {
                String fullUrl = normalizeUrl(baseUrl + path);
                if (isJavaScriptAccessible(fullUrl)) {
                    jsFiles.add(fullUrl);
                }
            }
        }

        return new ArrayList<>(jsFiles);
    }

    /**
     * Resolves a potentially relative URL against a base URL.
     */
    private String resolveUrl(String baseUrl, String ref) {
        if (ref == null || ref.isEmpty()) return null;
        // Already absolute
        if (ref.startsWith("http://") || ref.startsWith("https://")) return ref;
        // Protocol-relative
        if (ref.startsWith("//")) {
            String protocol = baseUrl.startsWith("https") ? "https:" : "http:";
            return protocol + ref;
        }
        // Absolute path
        if (ref.startsWith("/")) {
            try {
                URI uri = new URI(baseUrl);
                return uri.getScheme() + "://" + uri.getHost()
                       + (uri.getPort() > 0 ? ":" + uri.getPort() : "") + ref;
            } catch (Exception e) {
                return normalizeUrl(baseUrl + ref);
            }
        }
        // Relative path
        String base = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        return base + ref;
    }

    /**
     * Fetches page content with HTTPS support and redirect following.
     */
    private String fetchPageContent(String url) {
        try {
            HttpURLConnection conn = openConnection(url);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*");

            int code = conn.getResponseCode();

            // Handle manual redirect (e.g. HTTP→HTTPS)
            if (code == 301 || code == 302 || code == 307 || code == 308) {
                String location = conn.getHeaderField("Location");
                if (location != null) {
                    conn.disconnect();
                    return fetchPageContent(resolveUrl(url, location));
                }
            }

            if (code == 200) {
                StringBuilder html = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream()))) {
                    String line;
                    int totalBytes = 0;
                    while ((line = reader.readLine()) != null && totalBytes < MAX_FILE_SIZE) {
                        html.append(line).append("\n");
                        totalBytes += line.length();
                    }
                }
                return html.toString();
            }
        } catch (Exception e) {
            // Silently continue
        }
        return null;
    }

    /**
     * Opens an HTTP(S) connection with SSL trust-all for scanning purposes.
     */
    private HttpURLConnection openConnection(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URI(url).toURL().openConnection();
        if (conn instanceof HttpsURLConnection httpsConn) {
            TrustManager[] trustAll = {new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] c, String t) {}
                public void checkServerTrusted(X509Certificate[] c, String t) {}
            }};
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            httpsConn.setSSLSocketFactory(sc.getSocketFactory());
            httpsConn.setHostnameVerifier((h, s) -> true);
        }
        return conn;
    }

    // Storage for inline script content (keyed by virtual URL)
    private final Map<String, String> inlineScriptContents = new ConcurrentHashMap<>();

    /**
     * Downloads JavaScript files concurrently. Inline scripts and HTML page content
     * are resolved from the in-memory cache instead of HTTP.
     */
    private Map<String, String> downloadJavaScriptFiles(List<String> jsFiles) {
        Map<String, String> contents = new ConcurrentHashMap<>();
        
        List<CompletableFuture<Void>> futures = jsFiles.stream()
            .limit(30)
            .map(url -> CompletableFuture.runAsync(() -> {
                try {
                    // Inline scripts and HTML page source are already in memory
                    if (url.startsWith("inline://") || url.startsWith("html://")) {
                        String content = inlineScriptContents.get(url);
                        if (content != null && !content.trim().isEmpty()) {
                            contents.put(url, content);
                        }
                        return;
                    }
                    String content = downloadJavaScriptFile(url);
                    if (content != null && !content.trim().isEmpty()) {
                        contents.put(url, content);
                    }
                } catch (Exception e) {
                    // Continue with other files
                }
            }, executor))
            .collect(Collectors.toList());

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        return contents;
    }

    /**
     * Downloads a single JavaScript file with HTTPS support.
     */
    private String downloadJavaScriptFile(String url) throws Exception {
        HttpURLConnection conn = openConnection(url);
        conn.setConnectTimeout(TIMEOUT);
        conn.setReadTimeout(TIMEOUT);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestProperty("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        
        if (conn.getResponseCode() == 200) {
            StringBuilder content = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                int totalBytes = 0;
                while ((line = reader.readLine()) != null && totalBytes < MAX_FILE_SIZE) {
                    content.append(line).append("\n");
                    totalBytes += line.length();
                }
            }
            return content.toString();
        }
        return null;
    }

    /**
     * Analyzes API endpoints and routes based on analysis depth.
     */
    private List<EndpointInfo> analyzeEndpoints(String jsContent, AnalysisDepth depth) {
        List<EndpointInfo> endpoints = new ArrayList<>();
        
        // Basic patterns (always included)
        Pattern[] basicPatterns = {
            Pattern.compile("fetch\\s*\\(\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("axios\\.(get|post|put|delete)\\s*\\(\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE)
        };
        
        for (Pattern pattern : basicPatterns) {
            extractEndpointsFromPattern(jsContent, pattern, endpoints);
        }
        
        if (depth == AnalysisDepth.BASIC) {
            return deduplicateEndpoints(endpoints);
        }
        
        // Deep patterns
        Pattern[] deepPatterns = {
            Pattern.compile("\\.(get|post|put|delete|patch)\\s*\\(\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("`([^`]*\\$\\{[^}]+\\}[^`]*)`"),
            Pattern.compile("(?:route|path|url)\\s*[:=]\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE)
        };
        
        for (Pattern pattern : deepPatterns) {
            extractEndpointsFromPattern(jsContent, pattern, endpoints);
        }
        
        if (depth == AnalysisDepth.COMPREHENSIVE) {
            // Comprehensive patterns
            Pattern[] comprehensivePatterns = {
                Pattern.compile("(?:apiUrl|baseUrl|endpoint)\\s*[:=]\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
                Pattern.compile("router\\.(get|post|put|delete)\\s*\\(\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE)
            };
            
            for (Pattern pattern : comprehensivePatterns) {
                extractEndpointsFromPattern(jsContent, pattern, endpoints);
            }
        }
        
        return deduplicateEndpoints(endpoints);
    }
    
    /**
     * Extracts endpoints from a specific pattern.
     */
    private void extractEndpointsFromPattern(String jsContent, Pattern pattern, List<EndpointInfo> endpoints) {
        Matcher matcher = pattern.matcher(jsContent);
        while (matcher.find() && endpoints.size() < 100) {
            String url, method = "GET";
            
            if (matcher.groupCount() >= 2) {
                if (pattern.toString().contains("axios") || pattern.toString().contains("router")) {
                    method = matcher.group(1).toUpperCase();
                    url = matcher.group(2);
                } else {
                    url = matcher.group(1);
                    if (matcher.group(2) != null) {
                        method = matcher.group(2).toUpperCase();
                    }
                }
            } else {
                url = matcher.group(1);
            }

            if (isValidEndpoint(url)) {
                String baseUrl = extractBaseUrl(url);
                String path = extractPath(url);
                boolean isDynamic = url.contains("${") || url.contains(":" + path) || url.contains("{");
                
                String context = getMatchContext(jsContent, matcher.start(), matcher.end());
                List<String> parameters = extractParameters(context);
                Map<String, String> headers = extractHeaders(context);

                endpoints.add(new EndpointInfo(url, baseUrl, path, method, parameters, headers, context, isDynamic));
            }
        }
    }

    /**
     * Analyzes data structures including request payloads, response models, and state objects.
     */
    private List<DataStructureInfo> analyzeDataStructures(String jsContent) {
        List<DataStructureInfo> dataStructures = new ArrayList<>();
        
        // Patterns for different data structure types
        Map<DataStructureInfo.DataType, Pattern[]> patterns = new HashMap<>();
        
        patterns.put(DataStructureInfo.DataType.REQUEST_PAYLOAD, new Pattern[]{
            Pattern.compile("(?:data|payload|body)\\s*[:=]\\s*\\{([^{}]*(?:\\{[^{}]*\\}[^{}]*)*)\\}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("JSON\\.stringify\\s*\\(\\s*\\{([^{}]*(?:\\{[^{}]*\\}[^{}]*)*)\\}", Pattern.CASE_INSENSITIVE)
        });

        patterns.put(DataStructureInfo.DataType.RESPONSE_MODEL, new Pattern[]{
            Pattern.compile("(?:response|result)\\.data\\.([a-zA-Z_$][a-zA-Z0-9_$]*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\.then\\s*\\(\\s*(?:function\\s*\\(\\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*\\)|\\(?([a-zA-Z_$][a-zA-Z0-9_$]*)\\)?\\s*=>)", Pattern.CASE_INSENSITIVE)
        });

        patterns.put(DataStructureInfo.DataType.STATE_OBJECT, new Pattern[]{
            Pattern.compile("(?:state|store|reducer)\\s*[:=]\\s*\\{([^{}]*(?:\\{[^{}]*\\}[^{}]*)*)\\}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("useState\\s*\\(\\s*\\{([^{}]*(?:\\{[^{}]*\\}[^{}]*)*)\\}", Pattern.CASE_INSENSITIVE)
        });

        for (Map.Entry<DataStructureInfo.DataType, Pattern[]> entry : patterns.entrySet()) {
            DataStructureInfo.DataType type = entry.getKey();
            
            for (Pattern pattern : entry.getValue()) {
                Matcher matcher = pattern.matcher(jsContent);
                while (matcher.find() && dataStructures.size() < 50) {
                    String structureContent = matcher.group(1);
                    if (structureContent != null && !structureContent.trim().isEmpty()) {
                        String name = generateStructureName(type, dataStructures.size());
                        Map<String, String> properties = extractProperties(structureContent);
                        List<String> methods = extractMethods(structureContent);
                        String context = getMatchContext(jsContent, matcher.start(), matcher.end());
                        
                        dataStructures.add(new DataStructureInfo(name, type, properties, methods, context, false));
                    }
                }
            }
        }

        return dataStructures;
    }

    /**
     * Infers database schemas from data structures and naming patterns.
     */
    private List<DatabaseSchemaInfo> inferDatabaseSchemas(String jsContent, List<DataStructureInfo> dataStructures) {
        List<DatabaseSchemaInfo> schemas = new ArrayList<>();
        Map<String, DatabaseSchemaInfo.DatabaseType> dbTypeIndicators = new HashMap<>();
        
        // Database type detection patterns
        dbTypeIndicators.put("mongodb", DatabaseSchemaInfo.DatabaseType.MONGODB);
        dbTypeIndicators.put("mongoose", DatabaseSchemaInfo.DatabaseType.MONGODB);
        dbTypeIndicators.put("mysql", DatabaseSchemaInfo.DatabaseType.SQL);
        dbTypeIndicators.put("postgresql", DatabaseSchemaInfo.DatabaseType.SQL);
        dbTypeIndicators.put("sequelize", DatabaseSchemaInfo.DatabaseType.SQL);
        dbTypeIndicators.put("redis", DatabaseSchemaInfo.DatabaseType.REDIS);
        dbTypeIndicators.put("elasticsearch", DatabaseSchemaInfo.DatabaseType.ELASTICSEARCH);

        DatabaseSchemaInfo.DatabaseType detectedDbType = DatabaseSchemaInfo.DatabaseType.UNKNOWN;
        for (Map.Entry<String, DatabaseSchemaInfo.DatabaseType> entry : dbTypeIndicators.entrySet()) {
            if (jsContent.toLowerCase().contains(entry.getKey())) {
                detectedDbType = entry.getValue();
                break;
            }
        }

        // Infer tables from data structures
        for (DataStructureInfo structure : dataStructures) {
            if (structure.getType() == DataStructureInfo.DataType.REQUEST_PAYLOAD || 
                structure.getType() == DataStructureInfo.DataType.RESPONSE_MODEL) {
                
                String tableName = inferTableName(structure.getName(), structure.getProperties());
                if (tableName != null) {
                    Map<String, String> columns = new HashMap<>(structure.getProperties());
                    List<String> relationships = inferRelationships(structure.getProperties());
                    List<String> indexes = inferIndexes(structure.getProperties());
                    
                    double confidence = calculateSchemaConfidence(structure, jsContent);
                    
                    schemas.add(new DatabaseSchemaInfo(
                        tableName, detectedDbType, columns, relationships, 
                        indexes, structure.getContext(), confidence
                    ));
                }
            }
        }

        return schemas;
    }

    /**
     * Enhanced sensitive information finder with database credentials focus.
     */
    private List<WebSourceAnalyzer.LeakInfo> findSensitiveInformation(String jsContent, AnalysisDepth depth) {
        List<WebSourceAnalyzer.LeakInfo> leaks = new ArrayList<>();
        
        // Basic level - only critical security issues
        if (depth == AnalysisDepth.BASIC) {
            // High-priority database credentials
            findDatabaseCredentials(jsContent, leaks, true); // onlyCritical = true
            
            // Critical API keys
            findMatches(jsContent, 
                Pattern.compile("(?:api[_-]?key|apikey|secret[_-]?key)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{25,})['\"]", Pattern.CASE_INSENSITIVE),
                "Critical API Key", leaks);
                
            return leaks;
        }
        
        // Deep level - comprehensive database analysis
        findDatabaseCredentials(jsContent, leaks, false); // Get all DB info
        
        // API Keys
        findMatches(jsContent, 
            Pattern.compile("(?:api[_-]?key|apikey)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-]{20,})['\"]", Pattern.CASE_INSENSITIVE),
            "API Key", leaks);
        
        // Access tokens
        findMatches(jsContent,
            Pattern.compile("(?:access[_-]?token|token|bearer)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-\\.]{20,})['\"]", Pattern.CASE_INSENSITIVE),
            "Access Token", leaks);
        
        // Firebase keys
        findMatches(jsContent,
            Pattern.compile("(?:firebase|FIREBASE)[^{]*\\{[^}]*(?:apiKey|projectId)[^}]*\\}", Pattern.CASE_INSENSITIVE),
            "Firebase Config", leaks);
        
        if (depth == AnalysisDepth.COMPREHENSIVE) {
            // Comprehensive level - additional security patterns
            findMatches(jsContent,
                Pattern.compile("(AKIA[0-9A-Z]{16})"),
                "AWS Access Key", leaks);
                
            // JWT tokens
            findMatches(jsContent,
                Pattern.compile("(?:jwt|JWT)[^'\"]*['\"]([A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)['\"]", Pattern.CASE_INSENSITIVE),
                "JWT Token", leaks);
                
            // Private keys
            findMatches(jsContent,
                Pattern.compile("-----BEGIN [A-Z ]+PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]+PRIVATE KEY-----"),
                "Private Key", leaks);
        }
        
        return leaks;
    }
    
    /**
     * Enhanced database credentials finder using specialized analyzer.
     */
    private void findDatabaseCredentials(String jsContent, List<WebSourceAnalyzer.LeakInfo> leaks, boolean onlyCritical) {
        List<WebSourceAnalyzer.LeakInfo> dbLeaks = JavaScriptDatabaseAnalyzer.findDatabaseCredentials(jsContent, onlyCritical);
        leaks.addAll(dbLeaks);
    }
    
    /**
     * Analyzes architectural patterns and framework usage.
     */
    private ArchitectureInfo analyzeArchitecture(String jsContent, List<EndpointInfo> endpoints) {
        // Framework detection
        ArchitectureInfo.Framework framework = detectFramework(jsContent);
        
        // CMS detection
        ArchitectureInfo.CMS cms = detectCms(jsContent);
        
        // State management detection
        ArchitectureInfo.StateManagement stateManagement = detectStateManagement(jsContent);
        
        // Architecture pattern detection
        ArchitectureInfo.ArchitecturePattern pattern = detectArchitecturePattern(endpoints, jsContent);
        
        // Services detection
        List<String> services = detectServices(jsContent);
        
        // Configuration detection
        Map<String, String> configurations = extractConfigurations(jsContent);
        
        // Middleware detection
        List<String> middlewares = detectMiddlewares(jsContent);
        
        String evidence = buildArchitectureEvidence(framework, stateManagement, pattern);
        double confidence = calculateArchitectureConfidence(framework, stateManagement, pattern);
        
        return new ArchitectureInfo(pattern, stateManagement, framework, cms, services, 
                                  configurations, middlewares, evidence, confidence);
    }
    
    // Helper methods implementation continues...
    
    private boolean isJavaScriptAccessible(String url) {
        try {
            HttpURLConnection conn = openConnection(url);
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setInstanceFollowRedirects(true);
            int responseCode = conn.getResponseCode();
            return responseCode >= 200 && responseCode < 400;
        } catch (Exception e) {
            return false;
        }
    }

    private String normalizeUrl(String url) {
        return url.replaceAll("/{2,}", "/").replace(":/", "://");
    }

    private boolean isValidEndpoint(String url) {
        return url != null && 
               url.length() > 3 && 
               (url.startsWith("http") || url.startsWith("/")) &&
               !url.endsWith(".css") && 
               !url.endsWith(".png") && 
               !url.endsWith(".jpg");
    }

    private String extractBaseUrl(String url) {
        if (url.startsWith("http")) {
            int pathIndex = url.indexOf('/', 8);
            return pathIndex > 0 ? url.substring(0, pathIndex) : url;
        }
        return "";
    }

    private String extractPath(String url) {
        if (url.startsWith("http")) {
            int pathIndex = url.indexOf('/', 8);
            return pathIndex > 0 ? url.substring(pathIndex) : "/";
        }
        return url.startsWith("/") ? url : "/" + url;
    }

    private String getMatchContext(String content, int start, int end) {
        int contextStart = Math.max(0, start - 100);
        int contextEnd = Math.min(content.length(), end + 100);
        return content.substring(contextStart, contextEnd).replaceAll("\\s+", " ");
    }

    private List<String> extractParameters(String context) {
        List<String> params = new ArrayList<>();
        Pattern paramPattern = Pattern.compile("\\b([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*[:=]");
        Matcher matcher = paramPattern.matcher(context);
        while (matcher.find()) {
            params.add(matcher.group(1));
        }
        return params;
    }

    private Map<String, String> extractHeaders(String context) {
        Map<String, String> headers = new HashMap<>();
        Pattern headerPattern = Pattern.compile("headers\\s*:\\s*\\{([^}]+)\\}");
        Matcher matcher = headerPattern.matcher(context);
        if (matcher.find()) {
            String headerContent = matcher.group(1);
            Pattern keyValuePattern = Pattern.compile("(['\"]?)([a-zA-Z-]+)\\1\\s*:\\s*(['\"])([^'\"]+)\\3");
            Matcher kvMatcher = keyValuePattern.matcher(headerContent);
            while (kvMatcher.find()) {
                headers.put(kvMatcher.group(2), kvMatcher.group(4));
            }
        }
        return headers;
    }

    private List<EndpointInfo> deduplicateEndpoints(List<EndpointInfo> endpoints) {
        Map<String, EndpointInfo> unique = new LinkedHashMap<>();
        for (EndpointInfo endpoint : endpoints) {
            String key = endpoint.getHttpMethod() + ":" + endpoint.getUrl();
            unique.putIfAbsent(key, endpoint);
        }
        return new ArrayList<>(unique.values());
    }

    private String generateStructureName(DataStructureInfo.DataType type, int index) {
        return type.toString().toLowerCase() + "_" + (index + 1);
    }

    private Map<String, String> extractProperties(String objectContent) {
        Map<String, String> properties = new HashMap<>();
        Pattern propertyPattern = Pattern.compile("([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*:\\s*([^,}]+)");
        Matcher matcher = propertyPattern.matcher(objectContent);
        while (matcher.find()) {
            String name = matcher.group(1);
            String value = matcher.group(2).trim();
            String type = inferPropertyType(value);
            properties.put(name, type);
        }
        return properties;
    }

    private String inferPropertyType(String value) {
        if (value.matches("\\d+")) return "number";
        if (value.matches("true|false")) return "boolean";
        if (value.startsWith("\"") || value.startsWith("'")) return "string";
        if (value.startsWith("[")) return "array";
        if (value.startsWith("{")) return "object";
        return "unknown";
    }

    private List<String> extractMethods(String content) {
        List<String> methods = new ArrayList<>();
        Pattern methodPattern = Pattern.compile("([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*\\(");
        Matcher matcher = methodPattern.matcher(content);
        while (matcher.find()) {
            methods.add(matcher.group(1));
        }
        return methods;
    }

    private String inferTableName(String structureName, Map<String, String> properties) {
        // Simple heuristic to infer table names
        if (properties.containsKey("id") || properties.containsKey("_id")) {
            return structureName.toLowerCase().replace("_", "");
        }
        return null;
    }

    private List<String> inferRelationships(Map<String, String> properties) {
        List<String> relationships = new ArrayList<>();
        for (String prop : properties.keySet()) {
            if (prop.endsWith("Id") || prop.endsWith("_id")) {
                relationships.add(prop + " -> foreign key");
            }
        }
        return relationships;
    }

    private List<String> inferIndexes(Map<String, String> properties) {
        List<String> indexes = new ArrayList<>();
        for (String prop : properties.keySet()) {
            if (prop.equals("id") || prop.equals("_id") || prop.contains("email")) {
                indexes.add(prop + " (primary/unique)");
            }
        }
        return indexes;
    }

    private double calculateSchemaConfidence(DataStructureInfo structure, String jsContent) {
        double confidence = 0.5; // Base confidence
        if (structure.getProperties().containsKey("id")) confidence += 0.2;
        if (jsContent.toLowerCase().contains("database") || jsContent.toLowerCase().contains("model")) confidence += 0.2;
        if (structure.getProperties().size() > 3) confidence += 0.1;
        return Math.min(1.0, confidence);
    }

    private ArchitectureInfo.Framework detectFramework(String jsContent) {
        String lowerContent = jsContent.toLowerCase();
        if (lowerContent.contains("react") || lowerContent.contains("jsx")) return ArchitectureInfo.Framework.REACT;
        if (lowerContent.contains("vue") || lowerContent.contains("$vue")) return ArchitectureInfo.Framework.VUE;
        if (lowerContent.contains("angular") || lowerContent.contains("@angular")) return ArchitectureInfo.Framework.ANGULAR;
        if (lowerContent.contains("svelte")) return ArchitectureInfo.Framework.SVELTE;
        return ArchitectureInfo.Framework.VANILLA;
    }

    private ArchitectureInfo.CMS detectCms(String jsContent) {
        String lowerContent = jsContent.toLowerCase();
        
        // WordPress detection (most common)
        if (lowerContent.contains("wp-") || lowerContent.contains("wordpress") || 
            lowerContent.contains("wp_nonce") || lowerContent.contains("wp-content") ||
            lowerContent.contains("wp-admin") || lowerContent.contains("wp-includes")) {
            
            // Check for WooCommerce
            if (lowerContent.contains("woocommerce") || lowerContent.contains("wc-") || 
                lowerContent.contains("cart") && lowerContent.contains("checkout")) {
                return ArchitectureInfo.CMS.WOOCOMMERCE;
            }
            return ArchitectureInfo.CMS.WORDPRESS;
        }
        
        // Drupal detection
        if (lowerContent.contains("drupal") || lowerContent.contains("drupal.") || 
            lowerContent.contains("drupal_") || lowerContent.contains("/sites/default/files")) {
            return ArchitectureInfo.CMS.DRUPAL;
        }
        
        // Joomla detection
        if (lowerContent.contains("joomla") || lowerContent.contains("jform") || 
            lowerContent.contains("com_content") || lowerContent.contains("mod_")) {
            return ArchitectureInfo.CMS.JOOMLA;
        }
        
        // Shopify detection
        if (lowerContent.contains("shopify") || lowerContent.contains("cdn.shopify") || 
            lowerContent.contains("myshopify.com")) {
            return ArchitectureInfo.CMS.SHOPIFY;
        }
        
        // Magento detection
        if (lowerContent.contains("magento") || lowerContent.contains("mage/") || 
            lowerContent.contains("varien/")) {
            return ArchitectureInfo.CMS.MAGENTO;
        }
        
        // Next.js detection
        if (lowerContent.contains("__next") || lowerContent.contains("next/") || 
            lowerContent.contains("nextjs") || lowerContent.contains("_next/")) {
            return ArchitectureInfo.CMS.NEXTJS;
        }
        
        // Nuxt.js detection
        if (lowerContent.contains("__nuxt") || lowerContent.contains("nuxt.") || 
            lowerContent.contains("nuxtjs")) {
            return ArchitectureInfo.CMS.NUXTJS;
        }
        
        // Gatsby detection
        if (lowerContent.contains("gatsby") || lowerContent.contains("___gatsby")) {
            return ArchitectureInfo.CMS.GATSBY;
        }
        
        // Laravel detection
        if (lowerContent.contains("laravel") || lowerContent.contains("csrf-token") || 
            lowerContent.contains("laravel_") || lowerContent.contains("blade")) {
            return ArchitectureInfo.CMS.LARAVEL;
        }
        
        // Django detection
        if (lowerContent.contains("django") || lowerContent.contains("csrfmiddleware") || 
            lowerContent.contains("django.") || lowerContent.contains("/static/admin/")) {
            return ArchitectureInfo.CMS.DJANGO;
        }
        
        // Rails detection
        if (lowerContent.contains("rails") || lowerContent.contains("ruby") || 
            lowerContent.contains("authenticity_token")) {
            return ArchitectureInfo.CMS.RAILS;
        }
        
        // Strapi detection
        if (lowerContent.contains("strapi") || lowerContent.contains("/api/")) {
            return ArchitectureInfo.CMS.STRAPI;
        }
        
        // Contentful detection
        if (lowerContent.contains("contentful") || lowerContent.contains("cdn.contentful")) {
            return ArchitectureInfo.CMS.CONTENTFUL;
        }
        
        // Custom/API-first indicators
        if (lowerContent.contains("/api/v") || lowerContent.contains("rest") || 
            lowerContent.contains("graphql")) {
            return ArchitectureInfo.CMS.CUSTOM;
        }
        
        return ArchitectureInfo.CMS.UNKNOWN;
    }

    private ArchitectureInfo.StateManagement detectStateManagement(String jsContent) {
        String lowerContent = jsContent.toLowerCase();
        if (lowerContent.contains("redux") || lowerContent.contains("store.dispatch")) return ArchitectureInfo.StateManagement.REDUX;
        if (lowerContent.contains("vuex") || lowerContent.contains("$store")) return ArchitectureInfo.StateManagement.VUEX;
        if (lowerContent.contains("mobx")) return ArchitectureInfo.StateManagement.MOBX;
        if (lowerContent.contains("usecontext") || lowerContent.contains("context")) return ArchitectureInfo.StateManagement.CONTEXT_API;
        return ArchitectureInfo.StateManagement.VANILLA;
    }

    private ArchitectureInfo.ArchitecturePattern detectArchitecturePattern(List<EndpointInfo> endpoints, String jsContent) {
        if (endpoints.isEmpty()) return ArchitectureInfo.ArchitecturePattern.UNKNOWN;
        
        Set<String> basePaths = endpoints.stream()
            .map(EndpointInfo::getBaseUrl)
            .collect(Collectors.toSet());
        
        if (basePaths.size() > 3) return ArchitectureInfo.ArchitecturePattern.MICROSERVICES;
        if (jsContent.toLowerCase().contains("serverless") || jsContent.toLowerCase().contains("lambda")) return ArchitectureInfo.ArchitecturePattern.SERVERLESS;
        if (jsContent.toLowerCase().contains("proxy") || jsContent.toLowerCase().contains("gateway")) return ArchitectureInfo.ArchitecturePattern.PROXY_PATTERN;
        if (jsContent.toLowerCase().contains("bff") || endpoints.stream().anyMatch(e -> e.getPath().contains("/bff/"))) return ArchitectureInfo.ArchitecturePattern.BFF_PATTERN;
        
        return ArchitectureInfo.ArchitecturePattern.DIRECT_API;
    }

    private List<String> detectServices(String jsContent) {
        List<String> services = new ArrayList<>();
        String[] servicePatterns = {"auth", "user", "payment", "notification", "analytics", "logging"};
        
        for (String service : servicePatterns) {
            if (jsContent.toLowerCase().contains(service)) {
                services.add(service);
            }
        }
        return services;
    }

    private Map<String, String> extractConfigurations(String jsContent) {
        Map<String, String> configs = new HashMap<>();
        
        Pattern configPattern = Pattern.compile("(?:config|Config|CONFIG)\\s*[:=]\\s*\\{([^{}]*(?:\\{[^{}]*\\}[^{}]*)*)\\}");
        Matcher matcher = configPattern.matcher(jsContent);
        if (matcher.find()) {
            String configContent = matcher.group(1);
            Map<String, String> configProps = extractProperties(configContent);
            configs.putAll(configProps);
        }
        
        return configs;
    }

    private List<String> detectMiddlewares(String jsContent) {
        List<String> middlewares = new ArrayList<>();
        String[] middlewarePatterns = {"cors", "helmet", "compression", "morgan", "body-parser", "cookie-parser"};
        
        for (String middleware : middlewarePatterns) {
            if (jsContent.toLowerCase().contains(middleware)) {
                middlewares.add(middleware);
            }
        }
        return middlewares;
    }

    private String buildArchitectureEvidence(ArchitectureInfo.Framework framework, 
                                           ArchitectureInfo.StateManagement stateManagement, 
                                           ArchitectureInfo.ArchitecturePattern pattern) {
        return String.format("Framework: %s, State: %s, Pattern: %s", framework, stateManagement, pattern);
    }

    private double calculateArchitectureConfidence(ArchitectureInfo.Framework framework, 
                                                 ArchitectureInfo.StateManagement stateManagement, 
                                                 ArchitectureInfo.ArchitecturePattern pattern) {
        double confidence = 0.3; // Base confidence
        if (framework != ArchitectureInfo.Framework.UNKNOWN) confidence += 0.3;
        if (stateManagement != ArchitectureInfo.StateManagement.UNKNOWN) confidence += 0.2;
        if (pattern != ArchitectureInfo.ArchitecturePattern.UNKNOWN) confidence += 0.2;
        return confidence;
    }

    private void findMatches(String source, Pattern pattern, String type, List<WebSourceAnalyzer.LeakInfo> leaks) {
        Matcher matcher = pattern.matcher(source);
        while (matcher.find() && leaks.size() < 50) {
            String match = matcher.group(matcher.groupCount() > 0 ? 1 : 0);
            int start = Math.max(0, matcher.start() - 50);
            int end = Math.min(source.length(), matcher.end() + 50);
            String context = source.substring(start, end).replaceAll("\\s+", " ");
            leaks.add(new WebSourceAnalyzer.LeakInfo(type, match, context));
        }
    }
    
    /**
     * Ranks and filters sensitive information based on analysis depth.
     */
    private List<WebSourceAnalyzer.LeakInfo> rankAndFilterSensitiveInfo(List<WebSourceAnalyzer.LeakInfo> sensitiveInfo, AnalysisDepth depth) {
        // Sort by confidence score (highest first)
        sensitiveInfo.sort((a, b) -> Double.compare(
            calculateLeakPriority(b, depth), 
            calculateLeakPriority(a, depth)
        ));
        
        // Limit results based on depth
        int maxResults = switch (depth) {
            case BASIC -> 5;
            case DEEP -> 15;
            case COMPREHENSIVE -> -1; // No limit
        };
        
        if (maxResults > 0 && sensitiveInfo.size() > maxResults) {
            return new ArrayList<>(sensitiveInfo.subList(0, maxResults));
        }
        
        return sensitiveInfo;
    }
    
    /**
     * Ranks and filters endpoints based on analysis depth.
     */
    private List<EndpointInfo> rankAndFilterEndpoints(List<EndpointInfo> endpoints, AnalysisDepth depth) {
        // Sort by security relevance
        endpoints.sort((a, b) -> Double.compare(
            calculateEndpointPriority(b, depth),
            calculateEndpointPriority(a, depth)
        ));
        
        // Limit results based on depth
        int maxResults = switch (depth) {
            case BASIC -> 10;
            case DEEP -> 25;
            case COMPREHENSIVE -> -1; // No limit
        };
        
        if (maxResults > 0 && endpoints.size() > maxResults) {
            return new ArrayList<>(endpoints.subList(0, maxResults));
        }
        
        return endpoints;
    }
    
    /**
     * Calculates priority score for sensitive information leaks.
     */
    private double calculateLeakPriority(WebSourceAnalyzer.LeakInfo leak, AnalysisDepth depth) {
        double priority = 50.0; // Base priority
        String type = leak.getType().toLowerCase();
        String data = leak.getValue().toLowerCase();
        
        // High priority for database credentials
        if (type.contains("database") || type.contains("connection")) {
            priority += 50;
        }
        
        // High priority for credentials with actual passwords
        if (data.contains("password") || data.contains("secret")) {
            priority += 40;
        }
        
        // Priority for production-like indicators
        if (data.contains("prod") || data.contains(".com") || data.contains("amazonaws")) {
            priority += 30;
        }
        
        // API keys and tokens
        if (type.contains("api") || type.contains("token")) {
            priority += 25;
        }
        
        // Adjust for depth level
        if (depth == AnalysisDepth.COMPREHENSIVE) {
            priority *= 1.2; // Boost all scores for comprehensive analysis
        }
        
        return priority;
    }
    
    /**
     * Calculates priority score for endpoints.
     */
    private double calculateEndpointPriority(EndpointInfo endpoint, AnalysisDepth depth) {
        double priority = 0;
        String url = endpoint.getUrl().toLowerCase();
        String method = endpoint.getHttpMethod().toLowerCase();
        
        // High priority for sensitive operations
        if (method.equals("post") || method.equals("put") || method.equals("delete")) {
            priority += 30;
        }
        
        // Admin/auth endpoints
        if (url.contains("admin") || url.contains("auth") || url.contains("login")) {
            priority += 40;
        }
        
        // API endpoints
        if (url.contains("api/") || url.contains("/v1/") || url.contains("/v2/")) {
            priority += 25;
        }
        
        // Dynamic endpoints (parameters)
        if (endpoint.isDynamic()) {
            priority += 20;
        }
        
        // Database-related endpoints
        if (url.contains("user") || url.contains("data") || url.contains("query")) {
            priority += 15;
        }
        
        return priority;
    }

    public void shutdown() {
        executor.shutdown();
    }
}