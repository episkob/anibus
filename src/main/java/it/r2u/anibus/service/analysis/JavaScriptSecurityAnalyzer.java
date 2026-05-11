package it.r2u.anibus.service.analysis;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.HttpsURLConnection;

import it.r2u.anibus.model.ArchitectureInfo;
import it.r2u.anibus.model.DataStructureInfo;
import it.r2u.anibus.model.DatabaseSchemaInfo;
import it.r2u.anibus.model.EndpointInfo;
import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.LeakInfo;

/**
 * Advanced JavaScript source code analyzer for security research and backend infrastructure mapping.
 * Provides comprehensive analysis including endpoint mapping, data flow analysis, 
 * database schema inference, and architectural pattern detection.
 */
public class JavaScriptSecurityAnalyzer {

    /**
     * Optional authentication/session configuration for authenticated crawling.
     */
    public record CrawlAuthConfig(
        String loginUrl,
        String username,
        String password,
        String usernameField,
        String passwordField,
        Map<String, String> defaultHeaders,
        Map<String, String> initialCookies,
        Map<String, String> additionalLoginFormFields
    ) {
        public CrawlAuthConfig {
            defaultHeaders = defaultHeaders != null ? Map.copyOf(defaultHeaders) : Map.of();
            initialCookies = initialCookies != null ? Map.copyOf(initialCookies) : Map.of();
            additionalLoginFormFields = additionalLoginFormFields != null
                ? Map.copyOf(additionalLoginFormFields) : Map.of();
        }

        public String resolvedUsernameField() {
            return usernameField == null || usernameField.isBlank() ? "username" : usernameField;
        }

        public String resolvedPasswordField() {
            return passwordField == null || passwordField.isBlank() ? "password" : passwordField;
        }

        public boolean hasLoginCredentials() {
            return loginUrl != null && !loginUrl.isBlank()
                && username != null && !username.isBlank()
                && password != null;
        }
    }

    private static final class CrawlSession {
        private final Map<String, String> cookies = new ConcurrentHashMap<>();
        private final Map<String, String> headers = new ConcurrentHashMap<>();

        CrawlSession(CrawlAuthConfig authConfig) {
            if (authConfig != null) {
                cookies.putAll(authConfig.initialCookies());
                headers.putAll(authConfig.defaultHeaders());
            }
        }
    }
    
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
            return switch (str.trim()) {
                case "Deep" -> DEEP;
                case "Comprehensive" -> COMPREHENSIVE;
                default -> BASIC;
            };
        }
    }

    private static final int TIMEOUT = 10000;
    private static final int MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

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
        return analyzeTarget(targetUrl, depth, null);
    }

    /**
     * Performs analysis with optional authenticated session support.
     */
    public JavaScriptAnalysisResult analyzeTarget(String targetUrl, AnalysisDepth depth, CrawlAuthConfig authConfig) {
        long startTime = System.currentTimeMillis();
        List<String> errors = new ArrayList<>();
        CrawlSession session = new CrawlSession(authConfig);
        
        // Clear inline cache from previous runs
        inlineScriptContents.clear();
        
        try {
            if (authConfig != null && authConfig.hasLoginCredentials()) {
                performLogin(targetUrl, authConfig, session, errors);
            }

            // Discover JavaScript files
            List<String> jsFiles = discoverJavaScriptFiles(targetUrl, session);
            
            // Download and analyze all JS files concurrently
            Map<String, String> jsContents = downloadJavaScriptFiles(jsFiles, session);
            
            // Combine all JavaScript content for comprehensive analysis
            String combinedJs = String.join("\n", jsContents.values());
            
            // Perform analysis based on depth level
            List<EndpointInfo> endpoints = analyzeEndpoints(combinedJs, depth);
            List<DataStructureInfo> dataStructures = (depth == AnalysisDepth.BASIC) ? 
                new ArrayList<>() : analyzeDataStructures(combinedJs);
            List<DatabaseSchemaInfo> databaseSchemas = (depth == AnalysisDepth.BASIC) ? 
                new ArrayList<>() : inferDatabaseSchemas(combinedJs, dataStructures);
            List<LeakInfo> sensitiveInfo = new ArrayList<>(findSensitiveInformation(combinedJs, depth));

            // Merge HTML-source leaks (inline scripts, data attributes, etc.) from WebSourceAnalyzer
            try {
                URI uri = new URI(targetUrl);
                boolean useHttps = "https".equalsIgnoreCase(uri.getScheme());
                int port = uri.getPort();
                if (port < 1) port = useHttps ? 443 : 80;
                sensitiveInfo.addAll(WebSourceAnalyzer.analyzeWebPage(uri.getHost(), port, useHttps));
            } catch (java.net.URISyntaxException e) {
                errors.add("Invalid target URL for web source analysis: " + e.getMessage());
            }

            ArchitectureInfo architecture = (depth == AnalysisDepth.COMPREHENSIVE) ? 
                analyzeArchitecture(combinedJs, endpoints) : null;
            
            // Sort and rank results based on depth
            sensitiveInfo = rankAndFilterSensitiveInfo(sensitiveInfo, depth);
            endpoints = rankAndFilterEndpoints(endpoints, depth);

            // Tag findings with microservice names when MICROSERVICES pattern detected
            if (architecture != null
                    && architecture.getPattern() == ArchitectureInfo.ArchitecturePattern.MICROSERVICES) {
                sensitiveInfo = sensitiveInfo.stream()
                    .map(l -> { String svc = inferService(l); return svc != null ? l.withService(svc) : l; })
                    .collect(Collectors.toList());
            }
            
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
    private List<String> discoverJavaScriptFiles(String baseUrl, CrawlSession session) throws Exception {
        Set<String> jsFiles = new LinkedHashSet<>();

        // Step 1: Fetch the HTML page (with HTTPS + redirect support)
        String htmlContent = fetchPageContent(baseUrl, session);
        if (htmlContent != null && !htmlContent.isEmpty()) {
            // Step 2: Extract external <script src="..."> references (handles hashed filenames, query strings, CDN URLs)
            Pattern srcPattern = Pattern.compile(
                "<script[^>]+src\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>",
                Pattern.CASE_INSENSITIVE);
            Matcher srcMatcher = srcPattern.matcher(htmlContent);
            while (srcMatcher.find()) {
                String src = srcMatcher.group(1).trim();
                String fullUrl = resolveUrl(baseUrl, src);
                if (fullUrl != null && !isKnownLibrary(fullUrl)) {
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
                if (fullUrl != null && !isKnownLibrary(fullUrl)) {
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
                if (isJavaScriptAccessible(fullUrl, session)) {
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
            } catch (java.net.URISyntaxException e) {
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
    private String fetchPageContent(String url, CrawlSession session) {
        try {
            HttpURLConnection conn = openConnection(url);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*");
            applySession(conn, session);

            int code = conn.getResponseCode();
            captureResponseCookies(conn, session);

            // Handle manual redirect (e.g. HTTP→HTTPS)
            if (code == 301 || code == 302 || code == 307 || code == 308) {
                String location = conn.getHeaderField("Location");
                if (location != null) {
                    conn.disconnect();
                    return fetchPageContent(resolveUrl(url, location), session);
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
     * Opens an HTTP(S) connection using default JVM TLS/hostname verification.
     */
    private HttpURLConnection openConnection(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URI(url).toURL().openConnection();
        if (conn instanceof HttpsURLConnection) {
            // Keep default HTTPS behavior.
        }
        return conn;
    }

    // Storage for inline script content (keyed by virtual URL)
    private final Map<String, String> inlineScriptContents = new ConcurrentHashMap<>();

    /**
     * Downloads JavaScript files concurrently. Inline scripts and HTML page content
     * are resolved from the in-memory cache instead of HTTP.
     */
    private Map<String, String> downloadJavaScriptFiles(List<String> jsFiles, CrawlSession session) {
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
                    String content = downloadJavaScriptFile(url, session);
                    if (content != null && !content.trim().isEmpty()) {
                        contents.put(url, content);
                    }
                } catch (Exception e) {
                    // Continue with other files
                }
            }, executor))
            .collect(Collectors.toList());

        CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
        return contents;
    }

    /**
     * Downloads a single JavaScript file with HTTPS support.
     */
    private String downloadJavaScriptFile(String url, CrawlSession session) throws Exception {
        HttpURLConnection conn = openConnection(url);
        conn.setConnectTimeout(TIMEOUT);
        conn.setReadTimeout(TIMEOUT);
        conn.setInstanceFollowRedirects(true);
        conn.setRequestProperty("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        applySession(conn, session);

        int responseCode = conn.getResponseCode();
        captureResponseCookies(conn, session);
        
        if (responseCode == 200) {
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
    // ─── Known library filename fragments to filter out ────────────────────────
    private static final java.util.Set<String> KNOWN_LIBRARY_PATTERNS = java.util.Set.of(
        "jquery", "jquery.min", "jquery-",
        "swiper", "swiper.min", "swiper.bundle",
        "bootstrap", "bootstrap.min", "bootstrap.bundle",
        "lodash", "lodash.min",
        "moment.min", "moment.js",
        "react.production", "react.development", "react.min",
        "vue.min", "vue.global", "vue.esm",
        "angular.min", "angular.js",
        "d3.min", "d3.js",
        "three.min", "three.js",
        "chart.min", "chart.js",
        "popper.min", "popper.js",
        "slick.min", "slick.js", "owl.carousel",
        "gsap.min", "gsap.js",
        "axios.min", "axios.js",
        "rxjs.min", "rxjs.umd",
        "font-awesome", "fontawesome",
        "highlight.min", "prism.min",
        "underscore.min", "backbone.min",
        "ember.min", "ember.prod",
        "toastr.min", "sweetalert",
        "leaflet.min", "mapbox-gl",
        "socket.io", "socket.io.min",
        "fabric.min", "fabricjs",
        "select2.min", "chosen.min",
        "flatpickr.min", "datepicker.min",
        "alpinejs", "alpine.min",
        "htmx.min", "htmx.js"
    );

    /** Returns true if the URL looks like a third-party/CDN library that adds analysis noise. */
    private static boolean isKnownLibrary(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase();
        // CDN domains are always library files
        if (lower.contains("cdn.jsdelivr.net") || lower.contains("cdnjs.cloudflare.com")
            || lower.contains("unpkg.com") || lower.contains("cdn.bootcdn.net")
            || lower.contains("ajax.googleapis.com") || lower.contains("code.jquery.com")) {
            return true;
        }
        return KNOWN_LIBRARY_PATTERNS.stream().anyMatch(lower::contains);
    }

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

        return mergeNearDuplicates(dataStructures);
    }

    /**
     * Groups DataStructureInfo by type and merges pairs that differ by exactly one field
     * into a single structure where the differing field is marked as optional.
     */
    private static List<DataStructureInfo> mergeNearDuplicates(List<DataStructureInfo> list) {
        if (list.size() < 2) return list;

        // Work through the list; when a merge happens, replace both and re-check
        java.util.LinkedList<DataStructureInfo> work = new java.util.LinkedList<>(list);
        boolean changed = true;
        while (changed) {
            changed = false;
            outer:
            for (java.util.ListIterator<DataStructureInfo> it = work.listIterator(); it.hasNext(); ) {
                DataStructureInfo a = it.next();
                for (java.util.ListIterator<DataStructureInfo> jt = work.listIterator(it.nextIndex()); jt.hasNext(); ) {
                    DataStructureInfo b = jt.next();
                    if (a.getType() == b.getType() && diffByOneField(a, b)) {
                        DataStructureInfo merged = DataStructureInfo.mergeOptional(a, b);
                        it.set(merged);   // replace a with merged
                        jt.remove();      // remove b
                        changed = true;
                        break outer;
                    }
                }
            }
        }
        return new ArrayList<>(work);
    }

    /** True when the two structures share the same type and their property key sets differ by exactly one key. */
    private static boolean diffByOneField(DataStructureInfo a, DataStructureInfo b) {
        java.util.Set<String> keysA = a.getProperties().keySet();
        java.util.Set<String> keysB = b.getProperties().keySet();
        // symmetric difference
        java.util.Set<String> diff = new java.util.HashSet<>(keysA);
        diff.addAll(keysB);
        java.util.Set<String> intersection = new java.util.HashSet<>(keysA);
        intersection.retainAll(keysB);
        diff.removeAll(intersection);
        return diff.size() == 1;
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
                    String structName = structure.getName() != null ? structure.getName().toLowerCase() : "";
                    if (detectedDbType == DatabaseSchemaInfo.DatabaseType.REDIS
                            && (structName.contains("requestpayload9") || structName.contains("request_payload_9"))) {
                        confidence = 1.0;
                    }
                    
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
    private List<LeakInfo> findSensitiveInformation(String jsContent, AnalysisDepth depth) {
        List<LeakInfo> leaks = new ArrayList<>();
        
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

        // Strongly typed SDK token markers and auth/session signals
        findTypedSuperAppTokens(jsContent, leaks);
        findPasswordHierarchySignals(jsContent, leaks);
        findSessionRegistrationLinks(jsContent, leaks);
        
        if (depth == AnalysisDepth.COMPREHENSIVE) {
            // Comprehensive level - additional security patterns
            findMatches(jsContent,
                Pattern.compile("(AKIA[0-9A-Z]{16})"),
                "AWS Access Key", leaks);
                
            // JWT tokens
            findMatches(jsContent,
                Pattern.compile("(?:jwt|JWT)[^'\"]*['\"]([A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)['\"]", Pattern.CASE_INSENSITIVE),
                "JWT Token", leaks);
                
            // Private keys — multiline PEM (template literals, real newlines)
            // [A-Z ]* allows bare "PRIVATE KEY" (PKCS#8) as well as "RSA PRIVATE KEY", "EC PRIVATE KEY" etc.
            findMatches(jsContent,
                Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
                "Private Key (PEM)", leaks);

            // Private keys embedded in JS strings: escaped \n between PEM lines
            // e.g. "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
            findMatches(jsContent,
                Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\\\n|\\\\r\\\\n)[A-Za-z0-9+/=\\\\nrNT]+-----END [A-Z ]*PRIVATE KEY-----"),
                "Private Key (JS string)", leaks);

            // Public keys — multiline PEM
            findMatches(jsContent,
                Pattern.compile("-----BEGIN [A-Z ]*PUBLIC KEY-----[\\s\\S]*?-----END [A-Z ]*PUBLIC KEY-----"),
                "Public Key (PEM)", leaks);

            // Public keys embedded in JS strings: escaped \n
            findMatches(jsContent,
                Pattern.compile("-----BEGIN [A-Z ]*PUBLIC KEY-----(?:\\\\n|\\\\r\\\\n)[A-Za-z0-9+/=\\\\nrNT]+-----END [A-Z ]*PUBLIC KEY-----"),
                "Public Key (JS string)", leaks);

            // X.509 certificates (contain public key)
            findMatches(jsContent,
                Pattern.compile("-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"),
                "X.509 Certificate", leaks);
            
            // RSA/EC keys in JSON Web Key (JWK) format
            findMatches(jsContent,
                Pattern.compile("\\{[^}]*\"kty\"\\s*:\\s*\"(RSA|EC)\"[^}]*\\}", Pattern.CASE_INSENSITIVE),
                "JSON Web Key (JWK)", leaks);
            
            // Exposed key material (base64 encoded keys in config)
            findMatches(jsContent,
                Pattern.compile("(?:(?:public|private)[_-]?key|signing[_-]?key|encryption[_-]?key)\\s*[:=]\\s*['\"]([A-Za-z0-9+/=]{40,})['\"]", Pattern.CASE_INSENSITIVE),
                "Cryptographic Key Material", leaks);
            
            // Direct DB API calls from JS (fetch/axios to database-related endpoints)
            findMatches(jsContent,
                Pattern.compile("(?:fetch|axios|\\$\\.(?:ajax|get|post)|http\\.(?:get|post|put|delete))\\s*\\(\\s*['\"`][^'\"`]*(?:/api/(?:db|database|mongo|mysql|postgres|redis|graphql|query|sql))[^'\"`]*['\"`]", Pattern.CASE_INSENSITIVE),
                "Database API Endpoint Call", leaks);
            
            // GraphQL endpoint calls (often expose DB schema)
            findMatches(jsContent,
                Pattern.compile("(?:fetch|axios|\\$\\.(?:ajax|post)|http\\.post)\\s*\\(\\s*['\"`]([^'\"`]*graphql[^'\"`]*)['\"`]", Pattern.CASE_INSENSITIVE),
                "GraphQL Endpoint", leaks);
            
            // Direct SQL queries in JS
            findMatches(jsContent,
                Pattern.compile("(?:query|execute|exec)\\s*\\(\\s*['\"`]\\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\\s", Pattern.CASE_INSENSITIVE),
                "Direct SQL Query in JS", leaks);
            
            // ORM model definitions (Sequelize, Mongoose, TypeORM etc.)
            findMatches(jsContent,
                Pattern.compile("(?:sequelize\\.define|mongoose\\.model|Schema\\(|Entity\\(|@Entity|createConnection|getRepository)\\s*\\(\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE),
                "ORM Model/Entity Definition", leaks);
            
            // Database connection config objects
            findMatches(jsContent,
                Pattern.compile("(?:createPool|createConnection|connect)\\s*\\(\\s*\\{[^}]*(?:host|port|database|user)\\s*:", Pattern.CASE_INSENSITIVE),
                "Database Connection Config", leaks);

            // KV pairs: username + password in same object / nearby lines
            findKeyValuePairs(jsContent, leaks);

            // Token variable → endpoint tracking
            findTokenEndpointMappings(jsContent, leaks);

            // historyLocations can reveal user route timeline before an incident.
            findHistoryLocations(jsContent, leaks);
        }
        
        return leaks;
    }
    
    /**
     * Enhanced database credentials finder using specialized analyzer.
     */
    private void findDatabaseCredentials(String jsContent, List<LeakInfo> leaks, boolean onlyCritical) {
        List<LeakInfo> dbLeaks = JavaScriptDatabaseAnalyzer.findDatabaseCredentials(jsContent, onlyCritical);
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

        // Infrastructure inference
        ArchitectureInfo.InfrastructureInfo infra = detectInfrastructure(jsContent);
        
        String evidence = buildArchitectureEvidence(framework, stateManagement, pattern);
        double confidence = calculateArchitectureConfidence(framework, stateManagement, pattern);
        
        return new ArchitectureInfo(pattern, stateManagement, framework, cms, services, 
                                  configurations, middlewares, evidence, confidence, infra);
    }
    
    // Helper methods implementation continues...
    
    private boolean isJavaScriptAccessible(String url, CrawlSession session) {
        try {
            HttpURLConnection conn = openConnection(url);
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setInstanceFollowRedirects(true);
            applySession(conn, session);
            int responseCode = conn.getResponseCode();
            captureResponseCookies(conn, session);
            return responseCode >= 200 && responseCode < 400;
        } catch (Exception e) {
            return false;
        }
    }

    private void performLogin(String baseUrl, CrawlAuthConfig authConfig,
                              CrawlSession session, List<String> errors) {
        String loginUrl = resolveUrl(baseUrl, authConfig.loginUrl());
        if (loginUrl == null || loginUrl.isBlank()) {
            errors.add("Auth login skipped: invalid login URL");
            return;
        }

        try {
            HttpURLConnection conn = openConnection(loginUrl);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "*/*");
            conn.setRequestProperty("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            applySession(conn, session);

            String body = buildLoginFormBody(authConfig);
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(bytes.length));
            try (OutputStream out = conn.getOutputStream()) {
                out.write(bytes);
            }

            conn.getResponseCode();
            captureResponseCookies(conn, session);
        } catch (Exception e) {
            errors.add("Auth login failed: " + e.getMessage());
        }
    }

    private String buildLoginFormBody(CrawlAuthConfig authConfig) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put(authConfig.resolvedUsernameField(), authConfig.username());
        form.put(authConfig.resolvedPasswordField(), authConfig.password());
        form.putAll(authConfig.additionalLoginFormFields());
        return form.entrySet().stream()
            .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
            .collect(Collectors.joining("&"));
    }

    private void applySession(HttpURLConnection conn, CrawlSession session) {
        if (session == null) {
            return;
        }

        session.headers.forEach(conn::setRequestProperty);
        if (!session.cookies.isEmpty()) {
            String cookieHeader = session.cookies.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining("; "));
            conn.setRequestProperty("Cookie", cookieHeader);
        }
    }

    private void captureResponseCookies(HttpURLConnection conn, CrawlSession session) {
        if (session == null) {
            return;
        }

        Map<String, List<String>> headers = conn.getHeaderFields();
        if (headers == null || headers.isEmpty()) {
            return;
        }

        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String headerName = entry.getKey();
            if (headerName == null || !"Set-Cookie".equalsIgnoreCase(headerName)) {
                continue;
            }
            for (String cookieLine : entry.getValue()) {
                storeCookie(session, cookieLine);
            }
        }
    }

    private void storeCookie(CrawlSession session, String cookieLine) {
        if (cookieLine == null || cookieLine.isBlank()) {
            return;
        }

        String pair = cookieLine.split(";", 2)[0].trim();
        int eq = pair.indexOf('=');
        if (eq <= 0) {
            return;
        }
        String key = pair.substring(0, eq).trim();
        String value = pair.substring(eq + 1).trim();
        if (!key.isEmpty()) {
            session.cookies.put(key, value);
        }
    }

    private static String encode(String value) {
        if (value == null) {
            return "";
        }
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
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
            String lower = prop.toLowerCase();
            if (prop.endsWith("Id") || prop.endsWith("_id") || lower.endsWith("_fk")) {
                String target = inferForeignTarget(lower);
                relationships.add(target != null
                    ? prop + " -> foreign key (" + target + ")"
                    : prop + " -> foreign key");
            }
        }
        return relationships;
    }

    private String inferForeignTarget(String key) {
        String normalized = key
            .replaceAll("_id$", "")
            .replaceAll("id$", "")
            .replaceAll("_fk$", "")
            .replaceAll("_$", "");
        if (normalized.isBlank()) return null;

        if (normalized.contains("product")) return "products";
        if (normalized.contains("cart")) return "carts";
        if (normalized.contains("user") || normalized.contains("profile")) return "users";
        if (normalized.contains("order")) return "orders";
        if (normalized.contains("track") || normalized.contains("audio")) return "media_tracks";
        return normalized + "s";
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
        String lc = jsContent.toLowerCase();

        // ── Meta-frameworks (check before raw frameworks) ────────────────
        if (lc.contains("__next") || lc.contains("_next/") || lc.contains("next/router") ||
            lc.contains("nextjs") || lc.contains("next.config"))
            return ArchitectureInfo.Framework.NEXTJS_FW;

        if (lc.contains("__nuxt") || lc.contains("_nuxt/") || lc.contains("nuxt.config") ||
            lc.contains("nuxtjs") || lc.contains("usenuxtapp") || lc.contains("$nuxt"))
            return ArchitectureInfo.Framework.NUXTJS_FW;

        if (lc.contains("sveltekit") || lc.contains("$app/navigation") || lc.contains("@sveltejs/kit"))
            return ArchitectureInfo.Framework.SVELTEKIT;

        if (lc.contains("remix") && (lc.contains("@remix-run") || lc.contains("remix/react")))
            return ArchitectureInfo.Framework.REMIX;

        if (lc.contains("astro") && (lc.contains("astro:content") || lc.contains("@astrojs") ||
            lc.contains("astro.config")))
            return ArchitectureInfo.Framework.ASTRO;

        if (lc.contains("qwik") && (lc.contains("@builder.io/qwik") || lc.contains("qwik-city")))
            return ArchitectureInfo.Framework.QWIK;

        // ── Mobile / cross-platform ──────────────────────────────────────
        if (lc.contains("react-native") || lc.contains("reactnative") ||
            lc.contains("from 'react-native'") || lc.contains("rn."))
            return ArchitectureInfo.Framework.REACT_NATIVE;

        if (lc.contains("expo") && (lc.contains("expo-router") || lc.contains("expo-modules")))
            return ArchitectureInfo.Framework.EXPO;

        if (lc.contains("@ionic") || lc.contains("ion-content") || lc.contains("ionicframework"))
            return ArchitectureInfo.Framework.IONIC;

        // ── Core JS frameworks ───────────────────────────────────────────
        if (lc.contains("react") || lc.contains(".jsx") || lc.contains("usestate(") ||
            lc.contains("useeffect(") || lc.contains("reactdom"))
            return ArchitectureInfo.Framework.REACT;

        if (lc.contains("@angular/core") || lc.contains("ng-app") || lc.contains("ngmodule") ||
            lc.contains("@component(") || lc.contains("angular.module"))
            return ArchitectureInfo.Framework.ANGULAR;

        if (lc.contains("createapp(") || lc.contains("vue.component") || lc.contains("$mount(") ||
            lc.contains("vue/dist") || lc.contains("$emit(") && lc.contains("$props"))
            return ArchitectureInfo.Framework.VUE;

        if (lc.contains("solidjs") || lc.contains("@solidjs") || lc.contains("createSignal") ||
            lc.contains("createeffect") && lc.contains("createstore"))
            return ArchitectureInfo.Framework.SOLID;

        if (lc.contains("preact") || lc.contains("from 'preact'"))
            return ArchitectureInfo.Framework.PREACT;

        if (lc.contains("svelte") || lc.contains(".svelte"))
            return ArchitectureInfo.Framework.SVELTE;

        if (lc.contains("alpinejs") || lc.contains("x-data=") || lc.contains("alpine.js"))
            return ArchitectureInfo.Framework.ALPINE;

        if (lc.contains("htmx") || lc.contains("hx-get") || lc.contains("hx-post"))
            return ArchitectureInfo.Framework.HTMX;

        if (lc.contains("ember") || lc.contains("@ember") || lc.contains("ember.js"))
            return ArchitectureInfo.Framework.EMBER;

        if (lc.contains("backbone") || lc.contains("backbone.js") || lc.contains("backbone.view"))
            return ArchitectureInfo.Framework.BACKBONE;

        return ArchitectureInfo.Framework.VANILLA;
    }

    private ArchitectureInfo.CMS detectCms(String jsContent) {
        String lc = jsContent.toLowerCase();

        // ── WordPress ecosystem ──────────────────────────────────────────
        if (lc.contains("woocommerce") || lc.contains("wc_add_to_cart") ||
            (lc.contains("wc-") && lc.contains("wp-content")))
            return ArchitectureInfo.CMS.WOOCOMMERCE;

        if (lc.contains("wp-content") || lc.contains("wp-admin") || lc.contains("wp-includes") ||
            lc.contains("wp_nonce") || lc.contains("wordpress") || lc.contains("wp-json") ||
            lc.contains("wpajax") || lc.contains("wp_"))
            return ArchitectureInfo.CMS.WORDPRESS;

        // ── 1C-Bitrix ────────────────────────────────────────────────────
        if (lc.contains("bitrix") || lc.contains("bx_") || lc.contains("/bitrix/") ||
            lc.contains("bitrixajax") || lc.contains("bitrix24"))
            return ArchitectureInfo.CMS.BITRIX;

        // ── PHP CMS ──────────────────────────────────────────────────────
        if (lc.contains("drupal") || lc.contains("/sites/default/files") ||
            lc.contains("drupalSettings") || lc.contains("drupal.behaviors"))
            return ArchitectureInfo.CMS.DRUPAL;

        if (lc.contains("joomla") || lc.contains("jform") || lc.contains("com_content") ||
            lc.contains("/components/com_") || lc.contains("joomla!"))
            return ArchitectureInfo.CMS.JOOMLA;

        if (lc.contains("typo3") || lc.contains("/typo3/") || lc.contains("typo3conf") ||
            lc.contains("t3lib"))
            return ArchitectureInfo.CMS.TYPO3;

        if (lc.contains("october") && (lc.contains("october cms") || lc.contains("october/rain") ||
            lc.contains("octobercms")))
            return ArchitectureInfo.CMS.OCTOBER_CMS;

        if (lc.contains("modx") || lc.contains("modx.revolution") || lc.contains("modxsite"))
            return ArchitectureInfo.CMS.MODX;

        if (lc.contains("concrete5") || lc.contains("concrete\\core") || lc.contains("/concrete/"))
            return ArchitectureInfo.CMS.CONCRETE5;

        if (lc.contains("processwire") || lc.contains("/site/templates/"))
            return ArchitectureInfo.CMS.PROCESSWIRE;

        // ── PHP e-commerce ───────────────────────────────────────────────
        // Magento: require strong markers only — avoid false positives from substrings like "damage/"
        if (lc.contains("magento") || lc.contains("varien/") ||
            lc.contains("mage.cookies") || lc.contains("/skin/frontend/") ||
            lc.contains("mage.config") || lc.contains("window.mage") ||
            lc.contains("requirejs/require") && lc.contains("mage"))
            return ArchitectureInfo.CMS.MAGENTO;

        if (lc.contains("prestashop") || lc.contains("prestashop.") || lc.contains("/modules/") &&
            lc.contains("/themes/") && lc.contains("addtocart"))
            return ArchitectureInfo.CMS.PRESTASHOP;

        if (lc.contains("opencart") || lc.contains("catalog/view/javascript") ||
            lc.contains("catalog/view/theme"))
            return ArchitectureInfo.CMS.OPENCART;

        if (lc.contains("whmcs") || lc.contains("/whmcs/"))
            return ArchitectureInfo.CMS.WHMCS;

        // ── SaaS e-commerce ──────────────────────────────────────────────
        if (lc.contains("shopify") || lc.contains("cdn.shopify") || lc.contains("myshopify.com") ||
            lc.contains("shopify.theme"))
            return ArchitectureInfo.CMS.SHOPIFY;

        if (lc.contains("bigcommerce") || lc.contains("cdn11.bigcommerce") ||
            lc.contains("bigcommercecdn"))
            return ArchitectureInfo.CMS.BIGCOMMERCE;

        if (lc.contains("squarespace") || lc.contains("static1.squarespace"))
            return ArchitectureInfo.CMS.SQUARESPACE;

        if (lc.contains("wix.com") || lc.contains("static.wixstatic") ||
            lc.contains("wixcode") || lc.contains("wixsite.com"))
            return ArchitectureInfo.CMS.WIX;

        if (lc.contains("webflow") || lc.contains("webflow.com") || lc.contains("webflow-script"))
            return ArchitectureInfo.CMS.WEBFLOW;

        // ── PHP full-stack frameworks ────────────────────────────────────
        if (lc.contains("laravel") || lc.contains("laravel_session") || lc.contains("csrf-token") ||
            lc.contains("blade.") || lc.contains("inertiajs") && lc.contains("ziggy"))
            return ArchitectureInfo.CMS.LARAVEL;

        if (lc.contains("symfony") || lc.contains("symfony/") || lc.contains("fosrouting") ||
            lc.contains("fosjs"))
            return ArchitectureInfo.CMS.SYMFONY;

        if (lc.contains("codeigniter") || lc.contains("ci_session"))
            return ArchitectureInfo.CMS.CODEIGNITER;

        if (lc.contains("cakephp") || lc.contains("cake.") || lc.contains("/webroot/"))
            return ArchitectureInfo.CMS.CAKEPHP;

        if (lc.contains("zend") && (lc.contains("zend framework") || lc.contains("zend/")))
            return ArchitectureInfo.CMS.ZEND;

        // ── Python ───────────────────────────────────────────────────────
        if (lc.contains("wagtail") || lc.contains("wagtailcore"))
            return ArchitectureInfo.CMS.WAGTAIL;

        if (lc.contains("django") || lc.contains("csrfmiddlewaretoken") ||
            lc.contains("/static/admin/") || lc.contains("django-"))
            return ArchitectureInfo.CMS.DJANGO;

        if (lc.contains("fastapi") || lc.contains("from fastapi"))
            return ArchitectureInfo.CMS.FASTAPI;

        if (lc.contains("flask") && (lc.contains("flask.") || lc.contains("from flask")))
            return ArchitectureInfo.CMS.FLASK;

        // ── Ruby ─────────────────────────────────────────────────────────
        if (lc.contains("spree") || lc.contains("spree/"))
            return ArchitectureInfo.CMS.SPREE;

        if (lc.contains("rails") || lc.contains("authenticity_token") ||
            lc.contains("actioncable") || lc.contains("turbolinks"))
            return ArchitectureInfo.CMS.RAILS;

        // ── Node.js / JS back-end ────────────────────────────────────────
        if (lc.contains("nestjs") || lc.contains("@nestjs") || lc.contains("nest.js"))
            return ArchitectureInfo.CMS.NESTJS;

        if (lc.contains("ghost") && (lc.contains("ghost-") || lc.contains("ghost.io") ||
            lc.contains("ghost/core")))
            return ArchitectureInfo.CMS.GHOST;

        if (lc.contains("strapi") || lc.contains("/strapi/"))
            return ArchitectureInfo.CMS.STRAPI;

        if (lc.contains("keystonejs") || lc.contains("@keystone-6") || lc.contains("keystone/"))
            return ArchitectureInfo.CMS.KEYSTONE;

        if (lc.contains("expressjs") || lc.contains("require('express')") ||
            lc.contains("require(\"express\")"))
            return ArchitectureInfo.CMS.EXPRESS;

        // ── Java / JVM ───────────────────────────────────────────────────
        if (lc.contains("spring") && (lc.contains("spring-mvc") || lc.contains("springboot") ||
            lc.contains("spring boot") || lc.contains("_csrf") && lc.contains("actuator")))
            return ArchitectureInfo.CMS.SPRING;

        if (lc.contains("grails") || lc.contains("/grails-app/"))
            return ArchitectureInfo.CMS.GRAILS;

        // ── .NET ─────────────────────────────────────────────────────────
        if (lc.contains("umbraco") || lc.contains("/umbraco/"))
            return ArchitectureInfo.CMS.UMBRACO;

        if (lc.contains("orchardcore") || lc.contains("orchard:"))
            return ArchitectureInfo.CMS.ORCHARD;

        if (lc.contains("asp.net") || lc.contains("__requestverificationtoken") ||
            lc.contains("viewstate") || lc.contains("aspnetcore") || lc.contains("/aspnet/"))
            return ArchitectureInfo.CMS.ASPNET;

        // ── Headless / API-first CMS ─────────────────────────────────────
        if (lc.contains("contentful") || lc.contains("cdn.contentful") ||
            lc.contains("contentful.com"))
            return ArchitectureInfo.CMS.CONTENTFUL;

        if (lc.contains("sanity") && (lc.contains("@sanity") || lc.contains("sanity.io")))
            return ArchitectureInfo.CMS.SANITY;

        if (lc.contains("prismic") || lc.contains("cdn.prismic.io"))
            return ArchitectureInfo.CMS.PRISMIC;

        if (lc.contains("storyblok") || lc.contains("a2.storyblok"))
            return ArchitectureInfo.CMS.STORYBLOK;

        if (lc.contains("directus") || lc.contains("/directus/"))
            return ArchitectureInfo.CMS.DIRECTUS;

        if (lc.contains("hygraph") || lc.contains("graphcms"))
            return ArchitectureInfo.CMS.HYGRAPH;

        // ── Static site generators ───────────────────────────────────────
        if (lc.contains("___gatsby") || lc.contains("gatsby-") || lc.contains("gatsby/"))
            return ArchitectureInfo.CMS.GATSBY;

        if (lc.contains("hugo") && (lc.contains("hugoversion") || lc.contains("hugo-")))
            return ArchitectureInfo.CMS.HUGO;

        if (lc.contains("jekyll") || lc.contains("jekyll-"))
            return ArchitectureInfo.CMS.JEKYLL;

        if (lc.contains("eleventy") || lc.contains("11ty"))
            return ArchitectureInfo.CMS.ELEVENTY;

        if (lc.contains("hexo") && lc.contains("hexo."))
            return ArchitectureInfo.CMS.HEXO;

        // ── Generic API-first indicators ─────────────────────────────────
        if (lc.contains("/api/v") || lc.contains("graphql"))
            return ArchitectureInfo.CMS.CUSTOM;

        return ArchitectureInfo.CMS.UNKNOWN;
    }

    private ArchitectureInfo.StateManagement detectStateManagement(String jsContent) {
        String lc = jsContent.toLowerCase();
        if (lc.contains("redux") || lc.contains("store.dispatch") || lc.contains("createslice") ||
            lc.contains("@reduxjs/toolkit") || lc.contains("redux-toolkit"))
            return ArchitectureInfo.StateManagement.REDUX;
        if (lc.contains("pinia") || lc.contains("definestore") && lc.contains("storetoref"))
            return ArchitectureInfo.StateManagement.PINIA;
        if (lc.contains("vuex") || lc.contains("$store") || lc.contains("mapstate") && lc.contains("mapactions"))
            return ArchitectureInfo.StateManagement.VUEX;
        if (lc.contains("mobx") || lc.contains("makeautoobservable") || lc.contains("@observable"))
            return ArchitectureInfo.StateManagement.MOBX;
        if (lc.contains("zustand") || lc.contains("from 'zustand'") || lc.contains("create((set"))
            return ArchitectureInfo.StateManagement.ZUSTAND;
        if (lc.contains("recoil") || lc.contains("recoilroot") || lc.contains("userecoilstate"))
            return ArchitectureInfo.StateManagement.RECOIL;
        if (lc.contains("jotai") || lc.contains("from 'jotai'") || lc.contains("useatom("))
            return ArchitectureInfo.StateManagement.JOTAI;
        if (lc.contains("ngrx") || lc.contains("@ngrx/store") || lc.contains("createaction"))
            return ArchitectureInfo.StateManagement.NGRX;
        if (lc.contains("usecontext") || lc.contains("createcontext") || lc.contains("context.provider"))
            return ArchitectureInfo.StateManagement.CONTEXT_API;
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
        // Require the service name to appear as part of a URL path, hostname, or explicit
        // service-name assignment — not just as a plain word anywhere on the page.
        String[][] servicePatterns = {
            {"auth-service",    "auth"},
            {"user-service",    "user"},
            {"payment-service", "payment"},
            {"notification-service", "notification"},
            {"analytics-service",    "analytics"},
            {"logging-service",      "logging"},
            {"order-service",        "order"},
            {"product-service",      "product"},
            {"cart-service",         "cart"},
            {"inventory-service",    "inventory"},
            {"search-service",       "search"},
            {"media-service",        "media"},
            {"email-service",        "email"},
            {"sms-service",          "sms"},
        };
        String lc = jsContent.toLowerCase();
        for (String[] entry : servicePatterns) {
            String hyphenName = entry[0]; // e.g. "auth-service"
            String shortName  = entry[1]; // e.g. "auth"
            // Only count if the service appears as a URL segment, hostname, or explicit variable name
            boolean isServiceRef =
                lc.contains(hyphenName) ||                                 // auth-service
                lc.contains("/" + shortName + "/") ||                     // /auth/
                lc.contains(shortName + "_service") ||                    // auth_service
                lc.contains(shortName + "Service") ||                     // authService
                lc.contains("\"" + shortName + "\"") && lc.contains("microservice") || // "auth" near microservice
                Pattern.compile("[a-z0-9-]+\\." + shortName + "\\b").matcher(lc).find(); // svc.auth
            if (isServiceRef) {
                services.add(shortName);
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

    /**
     * Infers containerization, orchestration and proxy/gateway from JS/HTML source.
     * Looks for Docker file paths, K8s internal hostnames, env-var prefixes,
     * pod-name patterns, and gateway-specific strings.
     */
    private ArchitectureInfo.InfrastructureInfo detectInfrastructure(String jsContent) {
        List<String> evidence = new ArrayList<>();
        String lower = jsContent.toLowerCase();

        // ── Containerization ─────────────────────────────────────────────
        int dockerScore = 0;

        // Dockerfile / docker-compose artefacts embedded in JS config
        if (lower.contains("dockerfile") || lower.contains("docker-compose")) {
            dockerScore += 3; evidence.add("Dockerfile/docker-compose reference found");
        }
        // Standard container path prefix /app/
        if (Pattern.compile("/app/[a-zA-Z0-9_./-]{2,}").matcher(jsContent).find()) {
            dockerScore += 2; evidence.add("Container-style /app/ path prefix found");
        }
        // DOCKER_ / COMPOSE_ / CONTAINER_ID env-var prefixes
        if (Pattern.compile("(?:DOCKER|COMPOSE|CONTAINER_ID|CONTAINER_NAME)_?[A-Z_]*").matcher(jsContent).find()) {
            dockerScore += 3; evidence.add("Docker/Compose env-var prefix found");
        }
        // Internal service hostnames (e.g. backend_api:5000, db_service:3306)
        if (Pattern.compile("[a-z][a-z0-9_-]{2,}(?:_service|_api|_db|_cache|_broker):[0-9]{2,5}").matcher(lower).find()) {
            dockerScore += 2; evidence.add("Internal Docker-network service hostname found");
        }
        // docker keyword in string literals / comments
        if (Pattern.compile("\"docker\"|'docker'|//.*docker|/\\*.*docker").matcher(lower).find()) {
            dockerScore += 1; evidence.add("'docker' keyword in source");
        }
        // image_tag or image: hints
        if (lower.contains("image_tag") || lower.contains("\"image\":")) {
            dockerScore += 1; evidence.add("image_tag / image field found");
        }

        ArchitectureInfo.InfrastructureInfo.ContainerRuntime containerRuntime;
        double containerConfidence;
        if (dockerScore >= 5) {
            containerRuntime   = ArchitectureInfo.InfrastructureInfo.ContainerRuntime.DOCKER;
            containerConfidence = Math.min(0.95, 0.5 + dockerScore * 0.07);
        } else if (dockerScore >= 2) {
            containerRuntime   = ArchitectureInfo.InfrastructureInfo.ContainerRuntime.DOCKER;
            containerConfidence = 0.3 + dockerScore * 0.06;
        } else if (lower.contains("podman")) {
            containerRuntime   = ArchitectureInfo.InfrastructureInfo.ContainerRuntime.PODMAN;
            containerConfidence = 0.6;
            evidence.add("'podman' keyword found");
        } else {
            containerRuntime   = ArchitectureInfo.InfrastructureInfo.ContainerRuntime.NONE;
            containerConfidence = 0.0;
        }

        // ── Kubernetes ────────────────────────────────────────────────────
        int k8sScore = 0;

        // .svc.cluster.local internal DNS
        if (Pattern.compile("[a-z0-9-]+\\.svc\\.cluster\\.local").matcher(lower).find()) {
            k8sScore += 4; evidence.add("K8s internal DNS .svc.cluster.local found");
        }
        // Pod name pattern: word-word-<hash>-<hash> — require it appears in a JS value context
        // (string literal or object property) to avoid matching CSS class names / URL slugs
        if (Pattern.compile("['\"`][a-z][a-z0-9-]+-[a-z0-9]{5,}-[a-z0-9]{5,}\\b['\"`]").matcher(lower).find()) {
            k8sScore += 2; evidence.add("K8s pod-name pattern detected");
        }
        // namespace keyword in configs
        if (Pattern.compile("\"namespace\"|'namespace'|\\bnamespace\\b\\s*:").matcher(lower).find()) {
            k8sScore += 1; evidence.add("'namespace' field found (K8s hint)");
        }
        // k8s / kubernetes / kubectl keyword
        if (lower.contains("kubernetes") || lower.contains("kubectl") || lower.contains("\"k8s\"") || lower.contains("'k8s'")) {
            k8sScore += 3; evidence.add("Kubernetes keyword found");
        }
        // Prometheus / Grafana / ELK — indirect K8s indicator
        if (lower.contains("prometheus") || lower.contains("grafana") || lower.contains("kibana") || lower.contains("elasticsearch")) {
            k8sScore += 1; evidence.add("Monitoring stack (Prometheus/Grafana/ELK) found");
        }
        // Istio / Envoy side-car patterns
        if (lower.contains("istio") || lower.contains("envoy")) {
            k8sScore += 2; evidence.add("Istio/Envoy service-mesh reference found");
        }
        // Docker Swarm mode
        if (lower.contains("swarm") && (lower.contains("docker") || lower.contains("stack"))) {
            k8sScore -= 2; // lower K8s but raise Swarm
        }

        ArchitectureInfo.InfrastructureInfo.Orchestrator orchestrator;
        double orchestratorConfidence;
        if (k8sScore >= 4) {
            orchestrator           = ArchitectureInfo.InfrastructureInfo.Orchestrator.KUBERNETES;
            orchestratorConfidence = Math.min(0.95, 0.45 + k8sScore * 0.08);
        } else if (k8sScore >= 2) {
            orchestrator           = ArchitectureInfo.InfrastructureInfo.Orchestrator.KUBERNETES;
            orchestratorConfidence = 0.25 + k8sScore * 0.07;
        } else if (lower.contains("swarm") && lower.contains("docker")) {
            orchestrator           = ArchitectureInfo.InfrastructureInfo.Orchestrator.SWARM;
            orchestratorConfidence = 0.55;
            evidence.add("Docker Swarm reference found");
        } else if (lower.contains("nomad")) {
            orchestrator           = ArchitectureInfo.InfrastructureInfo.Orchestrator.NOMAD;
            orchestratorConfidence = 0.6;
            evidence.add("HashiCorp Nomad reference found");
        } else {
            orchestrator           = ArchitectureInfo.InfrastructureInfo.Orchestrator.NONE;
            orchestratorConfidence = 0.0;
        }

        // ── Proxy / Gateway ───────────────────────────────────────────────
        ArchitectureInfo.InfrastructureInfo.ProxyGateway proxyGateway =
                ArchitectureInfo.InfrastructureInfo.ProxyGateway.NONE;

        if (lower.contains("istio") || lower.contains("envoy")) {
            proxyGateway = ArchitectureInfo.InfrastructureInfo.ProxyGateway.ENVOY;
        } else if (lower.contains("traefik")) {
            proxyGateway = ArchitectureInfo.InfrastructureInfo.ProxyGateway.TRAEFIK;
            evidence.add("Traefik reverse proxy reference found");
        } else if (lower.contains("haproxy")) {
            proxyGateway = ArchitectureInfo.InfrastructureInfo.ProxyGateway.HAPROXY;
            evidence.add("HAProxy reference found");
        } else if (lower.contains("nginx") || lower.contains("\"x-nginx\"") || lower.contains("'x-nginx'")) {
            proxyGateway = ArchitectureInfo.InfrastructureInfo.ProxyGateway.NGINX;
            evidence.add("Nginx reference found");
        }

        // ── breadcrumb / historyLocations path analysis ───────────────────
        Pattern breadcrumbPath = Pattern.compile(
            "(?:breadcrumb|historyLocation|history|route)[^\"'\\n]{0,40}[\"'](/[a-zA-Z0-9_/.-]{4,})[\"']",
            Pattern.CASE_INSENSITIVE);
        Matcher bm = breadcrumbPath.matcher(jsContent);
        int breadcrumbHits = 0;
        while (bm.find() && breadcrumbHits < 5) {
            String path = bm.group(1);
            if (path.startsWith("/app/") || path.contains("/var/") || path.contains("/usr/")) {
                dockerScore += 1;
                evidence.add("Container-like path in history/breadcrumb: " + path);
                breadcrumbHits++;
            }
        }

        return new ArchitectureInfo.InfrastructureInfo(
            containerRuntime, containerConfidence,
            orchestrator,     orchestratorConfidence,
            proxyGateway,     evidence
        );
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

    private void findMatches(String source, Pattern pattern, String type, List<LeakInfo> leaks) {
        Matcher matcher = pattern.matcher(source);
        while (matcher.find() && leaks.size() < 50) {
            String match = matcher.group(matcher.groupCount() > 0 ? 1 : 0);
            int start = Math.max(0, matcher.start() - 50);
            int end = Math.min(source.length(), matcher.end() + 50);
            String context = source.substring(start, end).replaceAll("\\s+", " ");
            leaks.add(new LeakInfo(type, match, context));
        }
    }

    // ─── KV Pair: username + password in proximity ───────────────────────────
    private void findKeyValuePairs(String jsContent, List<LeakInfo> leaks) {
        // user/login/email followed by password within 200 chars
        Pattern kvFwd = Pattern.compile(
            "(?:user(?:name)?|login|uid|email)\\s*[:=,]\\s*['\"]([^'\"\\n]{2,60})['\"]" +
            "[^'\"\\n]{0,200}" +
            "(?:pass(?:word)?|pwd|secret)\\s*[:=,]\\s*['\"]([^'\"\\n]{2,})['\"]",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher mf = kvFwd.matcher(jsContent);
        while (mf.find() && leaks.size() < 200) {
            String user = mf.group(1);
            String pass = mf.group(2);
            boolean ph = LeakInfo.isPlaceholderValue(pass);
            String ctx = getMatchContext(jsContent, mf.start(), mf.end());
            leaks.add(new LeakInfo(
                "KV Pair: Username + Password",
                "Username: " + user + " | Password: " + pass,
                ctx, 8, null, ph));
        }
        // reversed: password before username
        Pattern kvRev = Pattern.compile(
            "(?:pass(?:word)?|pwd|secret)\\s*[:=,]\\s*['\"]([^'\"\\n]{2,})['\"]" +
            "[^'\"\\n]{0,200}" +
            "(?:user(?:name)?|login|uid|email)\\s*[:=,]\\s*['\"]([^'\"\\n]{2,60})['\"]",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher mr = kvRev.matcher(jsContent);
        while (mr.find() && leaks.size() < 200) {
            String pass = mr.group(1);
            String user = mr.group(2);
            boolean ph = LeakInfo.isPlaceholderValue(pass);
            String ctx = getMatchContext(jsContent, mr.start(), mr.end());
            leaks.add(new LeakInfo(
                "KV Pair: Username + Password",
                "Username: " + user + " | Password: " + pass,
                ctx, 8, null, ph));
        }
    }

    // ─── Variable tracking: token variable → endpoint ───────────────────────
    private void findTokenEndpointMappings(String jsContent, List<LeakInfo> leaks) {
        Set<String> tokenVars = new LinkedHashSet<>();
        // snake_case token vars: auth_token, access_token, session_id
        Pattern p1 = Pattern.compile(
            "(?:var|let|const)\\s+([a-zA-Z_$][a-zA-Z0-9_$]*(?:token|auth|session|bearer|apikey|api_key)[a-zA-Z0-9_$]*)\\s*[=;]",
            Pattern.CASE_INSENSITIVE);
        Matcher m1 = p1.matcher(jsContent);
        while (m1.find()) tokenVars.add(m1.group(1));
        // camelCase: authToken, accessToken, sessionId, bearerToken
        Pattern p2 = Pattern.compile(
            "(?:var|let|const)\\s+([a-zA-Z_$]*(?:Token|Auth|Session|Bearer|ApiKey)[a-zA-Z0-9_$]*)\\s*[=;]");
        Matcher m2 = p2.matcher(jsContent);
        while (m2.find()) tokenVars.add(m2.group(1));

        for (String varName : tokenVars) {
            if (varName.length() < 4) continue;
            Pattern callPat = Pattern.compile(
                "(?:fetch|axios\\.(?:get|post|put|delete|patch))\\s*\\(\\s*['\"`]([^'\"`]+)['\"`]",
                Pattern.CASE_INSENSITIVE);
            Matcher cm = callPat.matcher(jsContent);
            while (cm.find()) {
                int windowEnd = Math.min(jsContent.length(), cm.end() + 400);
                if (jsContent.substring(cm.end(), windowEnd).contains(varName)) {
                    String endpoint = cm.group(1);
                    String ctx = getMatchContext(jsContent, cm.start(), cm.end());
                    leaks.add(new LeakInfo(
                        "Token→Endpoint",
                        varName + " → " + endpoint,
                        ctx, 6, null, false));
                }
            }
        }
    }

    // ─── Typed token extraction (scope hints) ───────────────────────────────
    private void findTypedSuperAppTokens(String jsContent, List<LeakInfo> leaks) {
        Pattern p = Pattern.compile(
            "(VKSDK(?:General|Request)SuperAppToken|VKSDK[A-Za-z0-9_]*Token)",
            Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(jsContent);
        while (m.find() && leaks.size() < 240) {
            String tokenType = m.group(1);
            String ctx = getMatchContext(jsContent, m.start(), m.end());
            leaks.add(new LeakInfo(
                "Typed Token",
                tokenType,
                ctx, 8, null, false));
        }
    }

    // ─── Password hierarchy and validation-status extraction ────────────────
    private void findPasswordHierarchySignals(String jsContent, List<LeakInfo> leaks) {
        Pattern hierarchy = Pattern.compile(
            "((?:OLD_PASSWORD|old_password|new_password|current_password|incorrect_password|wrong_password|invalid_password)\\s*[:=]\\s*['\"]([^'\"\\n]{1,120})['\"])",
            Pattern.CASE_INSENSITIVE);
        Matcher mh = hierarchy.matcher(jsContent);
        while (mh.find() && leaks.size() < 260) {
            String pair = mh.group(1);
            String ctx = getMatchContext(jsContent, mh.start(), mh.end());
            boolean ph = LeakInfo.isPlaceholderValue(mh.group(2));
            leaks.add(new LeakInfo(
                "Password Hierarchy",
                pair,
                ctx, 7, null, ph));
        }

        Pattern statuses = Pattern.compile(
            "\\b(incorrect_password|wrong_password|invalid_password|password_expired|password_mismatch)\\b",
            Pattern.CASE_INSENSITIVE);
        Matcher ms = statuses.matcher(jsContent);
        while (ms.find() && leaks.size() < 280) {
            String status = ms.group(1);
            String ctx = getMatchContext(jsContent, ms.start(), ms.end());
            leaks.add(new LeakInfo(
                "Password Validation Status",
                status,
                ctx, 6, null, true));
        }
    }

    // ─── Session identifiers bound to registration attributes ───────────────
    private void findSessionRegistrationLinks(String jsContent, List<LeakInfo> leaks) {
        Pattern bundle = Pattern.compile(
            "(?:uuid|session(?:_id)?|sid)\\s*[:=]\\s*['\"]([a-f0-9-]{8,64})['\"]" +
            "[\\s\\S]{0,260}?" +
            "(?:user_id|uid)\\s*[:=]\\s*['\"]?([0-9]{1,20})['\"]?" +
            "[\\s\\S]{0,260}?" +
            "(?:email|login|phone|screen_name|registration)",
            Pattern.CASE_INSENSITIVE);
        Matcher m = bundle.matcher(jsContent);
        while (m.find() && leaks.size() < 300) {
            String uuid = m.group(1);
            String userId = m.group(2);
            String ctx = getMatchContext(jsContent, m.start(), m.end());
            leaks.add(new LeakInfo(
                "Session Identifier Bundle",
                "uuid=" + uuid + " | user_id=" + userId,
                ctx, 8, null, false));
        }
    }

    // ─── User navigation trace: historyLocations ─────────────────────────────
    private void findHistoryLocations(String jsContent, List<LeakInfo> leaks) {
        Pattern p = Pattern.compile(
            "historyLocations\\s*[:=]\\s*(\\[[^\\]]{5,1200}\\])",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher m = p.matcher(jsContent);
        while (m.find() && leaks.size() < 250) {
            String raw = m.group(1);
            if (raw == null || raw.isBlank()) continue;

            Matcher pathMatcher = Pattern.compile("['\"]([^'\"\\n]{1,200})['\"]").matcher(raw);
            List<String> paths = new ArrayList<>();
            while (pathMatcher.find() && paths.size() < 15) {
                String candidate = pathMatcher.group(1);
                if (candidate.startsWith("/") || candidate.startsWith("http")) {
                    paths.add(candidate);
                }
            }

            if (!paths.isEmpty()) {
                String ctx = getMatchContext(jsContent, m.start(), m.end());
                leaks.add(new LeakInfo(
                    "History Locations",
                    String.join(" -> ", paths),
                    ctx, 5, null, false));
            }
        }
    }

    // ─── Deduplication: same type+value → single entry with count ────────────
    private List<LeakInfo> deduplicateSensitiveInfo(
            List<LeakInfo> leaks) {
        Map<String, LeakInfo> seen = new LinkedHashMap<>();
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (LeakInfo leak : leaks) {
            String key = leak.getType() + "|" + leak.getValue();
            seen.putIfAbsent(key, leak);
            counts.merge(key, 1, Integer::sum);
        }
        List<LeakInfo> deduped = new ArrayList<>();
        for (Map.Entry<String, LeakInfo> entry : seen.entrySet()) {
            int c = counts.get(entry.getKey());
            deduped.add(c > 1 ? entry.getValue().withCount(c) : entry.getValue());
        }
        return deduped;
    }

    // ─── Microservice service tagging ────────────────────────────────────────
    private static final String[] SERVICE_KEYWORDS = {
        "auth", "authentication", "signin", "signup", "login", "session", "token",
        "user", "profile", "account", "identity",
        "payment", "billing", "checkout", "invoice", "wallet",
        "order", "product", "catalog", "cart",
        "notification", "message", "email", "sms",
        "analytics", "logging", "audit",
        "admin", "media", "upload", "search"
    };

    private static final java.util.Map<String, String> SERVICE_ALIAS = java.util.Map.ofEntries(
        java.util.Map.entry("authentication", "auth"),
        java.util.Map.entry("signin", "auth"),
        java.util.Map.entry("signup", "auth"),
        java.util.Map.entry("login", "auth"),
        java.util.Map.entry("session", "auth"),
        java.util.Map.entry("token", "auth"),
        java.util.Map.entry("identity", "auth"),
        java.util.Map.entry("account", "auth"),
        java.util.Map.entry("billing", "payment"),
        java.util.Map.entry("checkout", "payment"),
        java.util.Map.entry("invoice", "payment"),
        java.util.Map.entry("wallet", "payment"),
        java.util.Map.entry("catalog", "product"),
        java.util.Map.entry("message", "notification"),
        java.util.Map.entry("email", "notification"),
        java.util.Map.entry("sms", "notification"),
        java.util.Map.entry("audit", "logging")
    );

    private String inferService(LeakInfo leak) {
        String combined = (leak.getType() + " " + leak.getValue() + " " + leak.getContext()).toLowerCase();

        // Endpoint-like hints usually carry the most accurate microservice names.
        Matcher pathMatcher = Pattern.compile("/(?:api/)?([a-z][a-z0-9_-]{2,20})", Pattern.CASE_INSENSITIVE)
            .matcher(combined);
        while (pathMatcher.find()) {
            String candidate = canonicalService(pathMatcher.group(1));
            if (candidate != null) return candidate;
        }

        for (String svc : SERVICE_KEYWORDS) {
            if (combined.contains(svc)) return canonicalService(svc);
        }
        return null;
    }

    private String canonicalService(String raw) {
        if (raw == null || raw.isBlank()) return null;
        String s = raw.toLowerCase();
        return SERVICE_ALIAS.getOrDefault(s, s);
    }
    
    /**
     * Ranks, deduplicates, and optionally tags findings with microservice names.
     */
    private List<LeakInfo> rankAndFilterSensitiveInfo(
            List<LeakInfo> sensitiveInfo,
            AnalysisDepth depth) {

        // 1. Dedup: collapse same type+value entries, carry occurrence count
        sensitiveInfo = deduplicateSensitiveInfo(sensitiveInfo);

        // 2. Sort by priority (highest first); placeholder entries sorted to the end
        sensitiveInfo.sort((a, b) -> {
            // Non-placeholder sorts before placeholder at same priority
            int pa = a.isPlaceholder() ? a.getPriority() - 100 : a.getPriority();
            int pb = b.isPlaceholder() ? b.getPriority() - 100 : b.getPriority();
            return Integer.compare(pb, pa);
        });

        // 3. Limit results based on depth
        int maxResults = switch (depth) {
            case BASIC -> 5;
            case DEEP -> 20;
            case COMPREHENSIVE -> -1; // No limit
        };

        if (maxResults > 0 && sensitiveInfo.size() > maxResults) {
            sensitiveInfo = new ArrayList<>(sensitiveInfo.subList(0, maxResults));
        }

        return sensitiveInfo;
    }
    
    /**
     * Ranks and filters endpoints based on analysis depth.
     */
    private List<EndpointInfo> rankAndFilterEndpoints(List<EndpointInfo> endpoints, AnalysisDepth depth) {
        // Sort by security relevance
        endpoints.sort((a, b) -> Double.compare(
            calculateEndpointPriority(b),
            calculateEndpointPriority(a)
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
     * Calculates priority score for endpoints.
     */
    private double calculateEndpointPriority(EndpointInfo endpoint) {
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