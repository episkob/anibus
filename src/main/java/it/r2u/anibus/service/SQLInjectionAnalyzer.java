package it.r2u.anibus.service;

import it.r2u.anibus.model.ArchitectureInfo;
import it.r2u.anibus.model.DatabaseSchemaInfo;
import it.r2u.anibus.model.EndpointInfo;
import it.r2u.anibus.model.JavaScriptAnalysisResult;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
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

    private final Map<String, List<String>> payloadsByCategory = new LinkedHashMap<>();
    private final Map<String, List<InjectionResult>> results = new LinkedHashMap<>();
    private SiteFingerprint lastFingerprint;

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

    // Patterns indicating WAF or input filter rejection (false positive indicator)
    private static final List<Pattern> WAF_REJECTION_PATTERNS = List.of(
            Pattern.compile("no\\s*hack", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(attack|intrusion|injection|hack(?:ing)?)\\s+(detected|blocked|attempt)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("blocked\\s+by\\s+(?:waf|firewall|security|filter)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:request|ip|input)\\s+(?:has\\s+been\\s+|was\\s+)?(?:blocked|denied|rejected)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("access\\s+denied", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:illegal|invalid|malicious|dangerous)\\s+(?:character|input|request|payload)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("web\\s+application\\s+firewall", Pattern.CASE_INSENSITIVE),
            Pattern.compile("mod_security|modsecurity|sucuri.*block|cloudflare.*block|incapsula.*block", Pattern.CASE_INSENSITIVE),
            Pattern.compile("security\\s+violation", Pattern.CASE_INSENSITIVE),
            Pattern.compile("not\\s+acceptable.*security|security.*not\\s+acceptable", Pattern.CASE_INSENSITIVE)
    );

    // HTML parsing patterns for auto-discovery
    // Matches ANY <form> tag (with or without action attribute)
    private static final Pattern FORM_PATTERN = Pattern.compile(
            "<form(\\b[^>]*)>([\\s\\S]*?)</form>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern FORM_ACTION_PATTERN = Pattern.compile(
            "action=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
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
    // Match hidden inputs regardless of type/name attribute order
    private static final Pattern HIDDEN_INPUT_PATTERN = Pattern.compile(
            "<input[^>]*(?:type=[\"']hidden[\"'][^>]*name=[\"']([^\"']*)[\"']|name=[\"']([^\"']*)[\"'][^>]*type=[\"']hidden[\"'])[^>]*/?>",
            Pattern.CASE_INSENSITIVE);
    // All <a href="..."> links for crawling
    private static final Pattern ALL_LINKS_PATTERN = Pattern.compile(
            "<a[^>]*href=[\"']([^\"'#][^\"']*)[\"']",
            Pattern.CASE_INSENSITIVE);

    // Crawling limits
    private static final int CRAWL_MAX_PAGES = 30;
    private static final int CRAWL_MAX_DEPTH = 2;

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
        // Enable global cookie handling — all HttpURLConnection requests will auto-send/receive cookies
        CookieManager cm = new CookieManager();
        cm.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(cm);
    }

    /**
     * Load injection payloads from individual category files in payloads/ folder.
     * Reads payloads/index.txt to discover which category files to load.
     */
    private void loadPayloads() {
        try {
            List<String> categoryFiles = readIndexFile("/it/r2u/anibus/injections/payloads/index.txt");
            for (String category : categoryFiles) {
                loadPayloadFile(category, "/it/r2u/anibus/injections/payloads/" + category + ".txt");
            }
        } catch (Exception e) {
            // Fallback: try loading legacy monolithic file
            loadPayloadFile("legacy", "/it/r2u/anibus/injections/sql-injections.txt");
        }

        if (payloadsByCategory.isEmpty() || payloadsByCategory.values().stream().allMatch(List::isEmpty)) {
            payloadsByCategory.computeIfAbsent("error-based", k -> new ArrayList<>()).addAll(List.of(
                    "' OR '1'='1", "' OR '1'='1'--", "' UNION SELECT NULL--", "' AND SLEEP(3)--"
            ));
        }
    }

    private void loadPayloadFile(String category, String resourcePath) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                Objects.requireNonNull(getClass().getResourceAsStream(resourcePath)),
                StandardCharsets.UTF_8))) {
            List<String> categoryPayloads = payloadsByCategory.computeIfAbsent(category, k -> new ArrayList<>());
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    categoryPayloads.add(line);
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
     * Returns all payloads as a flat list (all categories combined).
     */
    private List<String> getAllPayloads() {
        return payloadsByCategory.values().stream()
                .flatMap(List::stream)
                .collect(Collectors.toList());
    }

    /**
     * Returns the number of loaded payloads across all categories.
     */
    public int getPayloadCount() {
        return payloadsByCategory.values().stream().mapToInt(List::size).sum();
    }

    /**
     * Returns the set of loaded payload categories.
     */
    public Set<String> getPayloadCategories() {
        return Collections.unmodifiableSet(payloadsByCategory.keySet());
    }

    /**
     * Returns the set of CMS names that have injection profiles loaded.
     */
    public Set<String> getSupportedCmsTypes() {
        return Collections.unmodifiableSet(cmsProfiles.keySet());
    }

    /**
     * Returns the last site fingerprint from an intelligent scan (may be null).
     */
    public SiteFingerprint getLastFingerprint() {
        return lastFingerprint;
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

        // 1. Discover forms with input fields (matches forms with or without action attribute)
        Matcher formMatcher = FORM_PATTERN.matcher(htmlSource);
        while (formMatcher.find()) {
            String formAttributes = formMatcher.group(1);
            String formBody = formMatcher.group(2);

            // Extract action (defaults to "" → resolves to baseUrl when absent)
            Matcher actionMatcher = FORM_ACTION_PATTERN.matcher(formAttributes);
            String action = actionMatcher.find() ? actionMatcher.group(1) : "";

            // Determine form method
            Matcher methodMatcher = FORM_METHOD_PATTERN.matcher(formAttributes);
            String method = methodMatcher.find() ? methodMatcher.group(1).toUpperCase() : "GET";

            // Extract all input/select/textarea names
            List<String> params = new ArrayList<>();
            extractFieldNames(formBody, INPUT_PATTERN, params);
            extractFieldNames(formBody, SELECT_PATTERN, params);
            extractFieldNames(formBody, TEXTAREA_PATTERN, params);

            // Remove hidden fields (CSRF tokens, session IDs, nonces — not useful for injection)
            List<String> hiddenFields = new ArrayList<>();
            extractHiddenFieldNames(formBody, hiddenFields);
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
     * Extract hidden input field names (handles both type-before-name and name-before-type attribute order).
     */
    private void extractHiddenFieldNames(String html, List<String> target) {
        Matcher m = HIDDEN_INPUT_PATTERN.matcher(html);
        while (m.find()) {
            // group(1) = name when type comes first; group(2) = name when name comes first
            String name = m.group(1) != null ? m.group(1).trim() : (m.group(2) != null ? m.group(2).trim() : "");
            if (!name.isEmpty() && !target.contains(name)) {
                target.add(name);
            }
        }
    }

    /**
     * Crawl the target site to discover endpoints from multiple pages.
     * Follows same-origin links up to CRAWL_MAX_DEPTH and CRAWL_MAX_PAGES.
     * Collects forms and parameterized links from each discovered page.
     *
     * @param baseUrl           the starting URL
     * @param initialHtml       HTML already fetched for the base URL (avoids re-fetch)
     * @param progressCallback  callback for progress updates
     * @return list of all discovered endpoints across all crawled pages
     */
    public List<EndpointInfo> crawlAndDiscoverEndpoints(String baseUrl, String initialHtml,
                                                         Consumer<String> progressCallback) {
        List<EndpointInfo> allDiscovered = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Set<String> endpointDedup = new HashSet<>();

        // Normalize origin for same-origin check
        String origin = extractOrigin(baseUrl);
        if (origin == null) return allDiscovered;

        // BFS queue: pairs of (url, depth)
        Deque<String[]> queue = new ArrayDeque<>();
        queue.add(new String[]{baseUrl, "0"});
        visited.add(normalizeForVisited(baseUrl));

        // Process initial page without re-fetching
        List<EndpointInfo> baseEndpoints = discoverEndpointsFromHtml(initialHtml, baseUrl);
        addUniqueEndpoints(baseEndpoints, allDiscovered, endpointDedup);

        // Extract links from initial page for crawling
        List<String> initialLinks = extractAllLinks(initialHtml, baseUrl, origin);
        for (String link : initialLinks) {
            String normalized = normalizeForVisited(link);
            if (visited.add(normalized)) {
                queue.add(new String[]{link, "1"});
            }
        }

        // Remove the base URL from queue since we already processed it
        queue.pollFirst();

        int pagesCrawled = 1;

        while (!queue.isEmpty() && pagesCrawled < CRAWL_MAX_PAGES) {
            if (Thread.currentThread().isInterrupted()) break;

            String[] entry = queue.pollFirst();
            String pageUrl = entry[0];
            int depth = Integer.parseInt(entry[1]);

            String html = fetchHtmlSource(pageUrl);
            if (html == null || html.isEmpty()) continue;
            pagesCrawled++;

            // Discover endpoints on this page
            List<EndpointInfo> pageEndpoints = discoverEndpointsFromHtml(html, pageUrl);
            int added = addUniqueEndpoints(pageEndpoints, allDiscovered, endpointDedup);

            if (added > 0 && progressCallback != null) {
                progressCallback.accept("Crawl: " + pageUrl + " → " + added + " new endpoints");
            }

            // Extract links for further crawling (only if not at max depth)
            if (depth < CRAWL_MAX_DEPTH) {
                List<String> links = extractAllLinks(html, pageUrl, origin);
                for (String link : links) {
                    String normalized = normalizeForVisited(link);
                    if (visited.add(normalized)) {
                        queue.add(new String[]{link, String.valueOf(depth + 1)});
                    }
                }
            }
        }

        if (progressCallback != null) {
            progressCallback.accept("Crawled " + pagesCrawled + " pages, found " +
                    allDiscovered.size() + " endpoints total");
        }

        return allDiscovered;
    }

    /**
     * Extract all same-origin links from HTML.
     */
    private List<String> extractAllLinks(String html, String pageUrl, String origin) {
        List<String> links = new ArrayList<>();
        Matcher m = ALL_LINKS_PATTERN.matcher(html);
        while (m.find()) {
            String href = m.group(1).trim();
            if (href.isEmpty() || href.startsWith("javascript:") || href.startsWith("mailto:")
                    || href.startsWith("tel:") || href.startsWith("data:")) continue;

            String resolved = resolveUrl(href, pageUrl);
            // Same-origin check
            if (resolved.startsWith(origin) && !isStaticResource(resolved)) {
                links.add(resolved);
            }
        }
        return links;
    }

    /**
     * Extract scheme + host + port from a URL.
     */
    private String extractOrigin(String url) {
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();
            if (scheme == null || host == null) return null;
            return scheme + "://" + host + (port > 0 ? ":" + port : "");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Normalize URL for visited-set deduplication (strip fragment, trailing slash variations).
     */
    private String normalizeForVisited(String url) {
        int fragIdx = url.indexOf('#');
        if (fragIdx >= 0) url = url.substring(0, fragIdx);
        // Normalize trailing slash for root paths
        if (url.endsWith("/") && url.chars().filter(c -> c == '/').count() > 3) {
            url = url.substring(0, url.length() - 1);
        }
        return url.toLowerCase();
    }

    /**
     * Check if a URL points to a static resource (images, css, fonts, etc.).
     */
    private boolean isStaticResource(String url) {
        String lower = url.toLowerCase();
        return lower.matches(".*\\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp[34]|avi|pdf|zip|tar|gz)([?#].*)?$");
    }

    /**
     * Add endpoints to a list, deduplicating by method + URL + params.
     * Returns the number of new endpoints added.
     */
    private int addUniqueEndpoints(List<EndpointInfo> source, List<EndpointInfo> target, Set<String> dedup) {
        int added = 0;
        for (EndpointInfo ep : source) {
            String key = (ep.getHttpMethod() != null ? ep.getHttpMethod() : "GET") + "|" + ep.getUrl()
                    + "|" + (ep.getParameters() != null ? String.join(",", ep.getParameters()) : "");
            if (dedup.add(key)) {
                target.add(ep);
                added++;
            }
        }
        return added;
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
     * Uses all loaded payloads (non-intelligent mode).
     */
    public Map<String, List<InjectionResult>> testEndpointsWithCmsSupport(
            List<EndpointInfo> jsEndpoints, String baseUrl,
            String cmsType, String htmlSource,
            Consumer<String> progressCallback) {
        return testEndpointsWithCmsSupport(jsEndpoints, baseUrl, cmsType, htmlSource, getAllPayloads(), progressCallback);
    }

    /**
     * Full scan with explicit payload list (used for intelligent mode).
     */
    public Map<String, List<InjectionResult>> testEndpointsWithCmsSupport(
            List<EndpointInfo> jsEndpoints, String baseUrl,
            String cmsType, String htmlSource,
            List<String> activePayloads,
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

        // 1c. Crawl site: discover forms and links from the base page AND linked subpages
        if (htmlSource != null && !htmlSource.isEmpty()) {
            if (progressCallback != null) {
                progressCallback.accept("Crawling site for forms and injectable links...");
            }
            List<EndpointInfo> crawledEndpoints = crawlAndDiscoverEndpoints(baseUrl, htmlSource, progressCallback);
            for (EndpointInfo ep : crawledEndpoints) {
                String key = (ep.getHttpMethod() != null ? ep.getHttpMethod() : "GET") + "|" + ep.getUrl();
                if (dedup.add(key)) {
                    allEndpoints.add(ep);
                }
            }
        }

        if (allEndpoints.isEmpty()) {
            // Fallback: probe the base URL itself with common injectable parameter names
            if (progressCallback != null) {
                progressCallback.accept("No endpoints discovered — falling back to base URL with common parameters...");
            }
            List<String> commonParams = List.of("id", "q", "search", "page", "user", "name",
                    "login", "pw", "password", "cat", "item", "order", "sort", "type", "lang");
            allEndpoints.add(new EndpointInfo(
                    baseUrl, baseUrl, "/", "GET",
                    new ArrayList<>(commonParams), Map.of(), "Fallback: base URL common params", false));
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
                    activePayloads.size() + " injection payloads (" + (testable.size() * activePayloads.size()) + " total tests)...");
        }

        // Phase 3: Run injection tests
        int totalTests = testable.size() * activePayloads.size();
        int completed = 0;

        for (EndpointInfo endpoint : testable) {
            if (Thread.currentThread().isInterrupted()) break;

            List<InjectionResult> endpointResults = new ArrayList<>();
            String endpointUrl = resolveEndpointUrl(endpoint, baseUrl);

            // Fetch baseline response (clean request without injection) for comparison
            BaselineResponse baseline = fetchBaseline(endpointUrl, endpoint);

            for (String payload : activePayloads) {
                if (Thread.currentThread().isInterrupted()) break;

                completed++;
                if (progressCallback != null && completed % 10 == 0) {
                    progressCallback.accept(String.format("Injection testing: %d/%d (%.0f%%) — %s",
                            completed, totalTests, (completed * 100.0) / totalTests, endpointUrl));
                }

                InjectionResult result = testPayload(endpointUrl, endpoint, payload, baseline);
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
     * Full automatic scan (non-intelligent): fetches HTML, detects CMS,
     * discovers forms/links, and runs injection tests with ALL payloads.
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

        lastFingerprint = null;
        return testEndpointsWithCmsSupport(jsEndpoints, baseUrl, detectedCms, htmlSource, progressCallback);
    }

    /**
     * Intelligent full scan: uses JavaScript analysis results to build a site fingerprint
     * and selects only relevant payload categories based on detected technologies.
     * This dramatically reduces noise and focuses on likely-effective attack vectors.
     *
     * @param jsEndpoints       endpoints discovered from JS analysis (may be null)
     * @param baseUrl           the target base URL
     * @param jsResult          results from JavaScript security analysis (for fingerprinting)
     * @param progressCallback  callback for progress updates
     * @return map of endpoint → list of injection results
     */
    public Map<String, List<InjectionResult>> fullScan(
            List<EndpointInfo> jsEndpoints, String baseUrl,
            JavaScriptAnalysisResult jsResult,
            Consumer<String> progressCallback) {

        // Phase 0: Reuse HTML from JS analysis (already fetched) or fetch if unavailable
        String htmlSource = jsResult.getHtmlSource();
        if (htmlSource == null || htmlSource.isEmpty()) {
            if (progressCallback != null) {
                progressCallback.accept("Fetching target page for intelligent fingerprinting...");
            }
            htmlSource = fetchHtmlSource(baseUrl);
        }

        // Phase 1: Build site fingerprint from JS analysis + HTML
        if (progressCallback != null) {
            progressCallback.accept("Building site fingerprint from analysis data...");
        }
        SiteFingerprint fingerprint = buildFingerprint(jsResult, htmlSource);
        lastFingerprint = fingerprint;

        // Use CMS from fingerprint
        String detectedCms = fingerprint.getDetectedCms();
        if (detectedCms != null && progressCallback != null) {
            progressCallback.accept("Detected CMS: " + detectedCms);
        }

        // Phase 2: Intelligent payload selection
        List<String> selectedPayloads = selectPayloads(fingerprint);

        if (progressCallback != null) {
            int totalPayloads = getPayloadCount();
            progressCallback.accept(String.format(
                    "⚡ Intelligent mode: %d/%d payloads selected (categories: %s)",
                    selectedPayloads.size(), totalPayloads,
                    String.join(", ", fingerprint.getSelectedCategories())));
            for (String ev : fingerprint.getEvidence()) {
                progressCallback.accept("  ► " + ev);
            }
        }

        return testEndpointsWithCmsSupport(jsEndpoints, baseUrl, detectedCms, htmlSource,
                selectedPayloads, progressCallback);
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
     * Test a single payload against an endpoint, comparing response to baseline.
     */
    private InjectionResult testPayload(String endpointUrl, EndpointInfo endpoint,
                                        String payload, BaselineResponse baseline) {
        try {
            boolean isTimeBased = TIME_BASED_KEYWORDS.stream()
                    .anyMatch(k -> payload.toUpperCase().contains(k));

            String method = endpoint.getHttpMethod() != null ? endpoint.getHttpMethod() : "GET";

            String testUrl;
            String postBody = null;

            if ("GET".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method)) {
                // Inject into URL parameters — use known params if available
                testUrl = injectIntoUrl(endpointUrl, endpoint, payload);
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
            boolean wafBlocked = isWafRejection(response.body);

            // 1. Check for database error messages (reliable even with WAF — real DB errors are concrete)
            if (!wafBlocked) {
                for (Map.Entry<String, Pattern> entry : DB_ERROR_PATTERNS.entrySet()) {
                    // Skip if baseline already contains this pattern (normal page content)
                    if (baseline != null && entry.getValue().matcher(baseline.body).find()) continue;
                    if (entry.getValue().matcher(response.body).find()) {
                        detectedDb = entry.getKey();
                        evidence.add("Database error detected: " + entry.getKey());
                        vulnerable = true;
                        break;
                    }
                }
            }

            // 2. Check for data leakage patterns (skip if present in baseline)
            if (!wafBlocked) {
                for (Pattern p : DATA_LEAK_PATTERNS) {
                    if (baseline != null && p.matcher(baseline.body).find()) continue;
                    if (p.matcher(response.body).find()) {
                        evidence.add("Data leakage pattern detected");
                        vulnerable = true;
                        break;
                    }
                }
            }

            // 3. Time-based detection (compare with baseline timing, not fixed threshold)
            if (isTimeBased && !wafBlocked) {
                long baselineTime = baseline != null ? baseline.responseTime : 500;
                if (responseTime > baselineTime + 2000) {
                    evidence.add(String.format("Time-based delay detected: %dms (baseline: %dms, delta: +%dms)",
                            responseTime, baselineTime, responseTime - baselineTime));
                    vulnerable = true;
                }
            }

            // 4. HTTP 500 errors with specific content (skip if WAF is just blocking)
            if (!wafBlocked && response.statusCode == 500 && response.body.length() > 100) {
                String lowerBody = response.body.toLowerCase();
                boolean hasDbKeyword = lowerBody.contains("sql") ||
                        lowerBody.contains("query") ||
                        lowerBody.contains("syntax") ||
                        lowerBody.contains("database") ||
                        lowerBody.contains("table");
                if (hasDbKeyword) {
                    evidence.add("Server error with database-related content (HTTP 500)");
                    vulnerable = true;
                }
            }

            // 5. Authentication bypass: requires baseline comparison
            //    Only flag if response is significantly different from baseline
            //    (actual bypass changes the page from login to dashboard)
            if (!wafBlocked && baseline != null && response.statusCode == 200
                    && payload.toUpperCase().contains("OR")
                    && (payload.contains("'1'='1") || payload.contains("1=1"))) {
                if (!isSimilarResponse(response.body, baseline.body)) {
                    evidence.add("Possible authentication bypass (response differs from baseline on OR injection)");
                    vulnerable = true;
                }
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
     * Uses known parameter names from endpoint discovery when available.
     */
    private String injectIntoUrl(String url, EndpointInfo endpoint, String payload) {
        String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);

        // If endpoint has known parameters, build a proper query string with all params
        List<String> params = endpoint.getParameters();
        if (params != null && !params.isEmpty()) {
            // Strip existing query string from URL
            String baseUrl = url.contains("?") ? url.substring(0, url.indexOf('?')) : url;
            StringBuilder qs = new StringBuilder(baseUrl).append("?");
            for (int i = 0; i < params.size(); i++) {
                if (i > 0) qs.append("&");
                qs.append(URLEncoder.encode(params.get(i), StandardCharsets.UTF_8));
                qs.append("=").append(encodedPayload);
            }
            return qs.toString();
        }

        // Fallback: no known params
        if (url.contains("?")) {
            return url + encodedPayload;
        } else if (url.contains("{") || url.matches(".*/(\\d+)$")) {
            return url.replaceAll("/[^/]*$", "/" + encodedPayload);
        } else {
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

            conn.setRequestMethod("GET".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method) ? method.toUpperCase() : 
                "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method) ? method.toUpperCase() : "POST");
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

            java.io.InputStream responseStream = statusCode >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (responseStream == null) responseStream = conn.getInputStream();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseStream, StandardCharsets.UTF_8))) {
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
            String header = "=== SQL INJECTION TESTING ===\n";
            if (lastFingerprint != null) {
                header += formatFingerprintSummary(lastFingerprint);
            }
            return header + "No vulnerabilities found.\n";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== SQL INJECTION TESTING ===\n");

        // Show fingerprint summary if intelligent mode was used
        if (lastFingerprint != null) {
            sb.append(formatFingerprintSummary(lastFingerprint));
        }

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
        sb.append("Payloads tested: ").append(getPayloadCount()).append("\n");

        return sb.toString();
    }

    private String formatFingerprintSummary(SiteFingerprint fp) {
        StringBuilder sb = new StringBuilder();
        sb.append("--- SITE FINGERPRINT ---\n");
        if (fp.getDetectedCms() != null) {
            sb.append("CMS: ").append(fp.getDetectedCms()).append("\n");
        }
        if (!fp.getDetectedDatabases().isEmpty()) {
            sb.append("Databases: ").append(String.join(", ", fp.getDetectedDatabases())).append("\n");
        }
        if (!fp.getTechnologies().isEmpty()) {
            sb.append("Technologies: ").append(String.join(", ", fp.getTechnologies())).append("\n");
        }
        sb.append("SQL: ").append(fp.isSqlDetected() ? "Yes" : "No");
        sb.append(" | NoSQL: ").append(fp.isNoSqlDetected() ? "Yes" : "No");
        sb.append(" | WAF: ").append(fp.isWafDetected() ? "Yes" : "No");
        sb.append(" | XML/SOAP: ").append(fp.isXmlSoapDetected() ? "Yes" : "No");
        sb.append(" | LDAP: ").append(fp.isLdapDetected() ? "Yes" : "No");
        sb.append(" | Login forms: ").append(fp.isHasLoginForms() ? "Yes" : "No");
        sb.append("\n");
        sb.append("Selected categories: ").append(String.join(", ", fp.getSelectedCategories())).append("\n\n");
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
     * Releases any resources held by this analyzer.
     */
    public void shutdown() {
        // No resources to clean up
    }

    // =================== Intelligent Payload Selection ===================

    /**
     * Build a site fingerprint from JavaScript analysis results and HTML source.
     * The fingerprint determines which injection categories are relevant for this target.
     */
    public SiteFingerprint buildFingerprint(JavaScriptAnalysisResult jsResult, String htmlSource) {
        SiteFingerprint fp = new SiteFingerprint();

        // --- Extract intelligence from JavaScript analysis ---
        if (jsResult != null) {
            extractFingerprintFromJsResult(fp, jsResult);
        }

        // --- Extract intelligence from HTML ---
        if (htmlSource != null && !htmlSource.isEmpty()) {
            extractFingerprintFromHtml(fp, htmlSource);
        }

        // Fallback: if no DB type detected at all, assume SQL is possible
        if (!fp.sqlDetected && !fp.noSqlDetected) {
            fp.sqlDetected = true;
            fp.evidence.add("No specific database detected — including SQL payloads by default");
        }

        return fp;
    }

    private void extractFingerprintFromJsResult(SiteFingerprint fp, JavaScriptAnalysisResult jsResult) {
        // CMS detection from architecture
        if (jsResult.getArchitecture() != null) {
            ArchitectureInfo arch = jsResult.getArchitecture();

            if (arch.getCms() != null && arch.getCms() != ArchitectureInfo.CMS.UNKNOWN) {
                fp.detectedCms = mapArchitectureCmsToName(arch.getCms());
                fp.evidence.add("CMS detected from JS analysis: " + arch.getCms());
            }

            if (arch.getFramework() != null && arch.getFramework() != ArchitectureInfo.Framework.UNKNOWN) {
                fp.technologies.add(arch.getFramework().name());
            }

            // Check middlewares for WAF/security indicators
            if (arch.getMiddlewares() != null) {
                for (String mw : arch.getMiddlewares()) {
                    String lower = mw.toLowerCase();
                    if (lower.contains("helmet") || lower.contains("csurf")
                            || lower.contains("rate-limit") || lower.contains("express-rate-limit")) {
                        fp.wafDetected = true;
                        fp.evidence.add("Security middleware detected: " + mw);
                    }
                }
            }
        }

        // Database detection from inferred schemas
        if (jsResult.getDatabaseSchemas() != null) {
            for (DatabaseSchemaInfo schema : jsResult.getDatabaseSchemas()) {
                switch (schema.getDatabaseType()) {
                    case SQL -> {
                        fp.sqlDetected = true;
                        fp.evidence.add("SQL database schema: " + schema.getTableName());
                    }
                    case MONGODB -> {
                        fp.noSqlDetected = true;
                        fp.detectedDatabases.add("MongoDB");
                        fp.evidence.add("MongoDB schema: " + schema.getTableName());
                    }
                    case REDIS -> {
                        fp.noSqlDetected = true;
                        fp.detectedDatabases.add("Redis");
                        fp.evidence.add("Redis usage detected");
                    }
                    case ELASTICSEARCH -> {
                        fp.noSqlDetected = true;
                        fp.detectedDatabases.add("Elasticsearch");
                        fp.evidence.add("Elasticsearch usage detected");
                    }
                    default -> { /* UNKNOWN — no action */ }
                }
            }
        }

        // Check sensitive info for DB type hints (connection strings, credentials)
        if (jsResult.getSensitiveInfo() != null) {
            for (WebSourceAnalyzer.LeakInfo leak : jsResult.getSensitiveInfo()) {
                String desc = leak.toString().toLowerCase();
                detectDatabaseFromText(fp, desc);
                if (desc.contains("ldap")) {
                    fp.ldapDetected = true;
                    fp.evidence.add("LDAP reference found in sensitive info");
                }
            }
        }
    }

    private void extractFingerprintFromHtml(SiteFingerprint fp, String htmlSource) {
        String lower = htmlSource.toLowerCase();

        // CMS from HTML (if not already detected from JS)
        if (fp.detectedCms == null) {
            fp.detectedCms = detectCmsFromHtml(htmlSource);
            if (fp.detectedCms != null) {
                fp.evidence.add("CMS detected from HTML: " + fp.detectedCms);
            }
        }

        // Login form detection
        if (lower.contains("type=\"password\"") || lower.contains("type='password'")
                || lower.contains("name=\"password\"") || lower.contains("name=\"passwd\"")
                || lower.contains("id=\"loginform\"") || lower.contains("action=\"/login\"")
                || lower.contains("action=\"/signin\"")) {
            fp.hasLoginForms = true;
            fp.evidence.add("Login/authentication form detected");
        }

        // SOAP/XML service detection
        if (lower.contains("wsdl") || lower.contains("xmlns:soap") || lower.contains("soap:envelope")
                || lower.contains("application/soap+xml") || lower.contains("text/xml")) {
            fp.xmlSoapDetected = true;
            fp.evidence.add("SOAP/XML service indicators found");
        }

        // LDAP detection
        if (lower.contains("ldap://") || lower.contains("ldaps://")
                || lower.contains("active directory") || lower.contains("ldap_bind")) {
            fp.ldapDetected = true;
            fp.evidence.add("LDAP service indicators found in HTML");
        }

        // WAF detection from HTML content/meta tags
        if (lower.contains("cloudflare") || lower.contains("__cf_bm") || lower.contains("cf-ray")
                || lower.contains("akamai") || lower.contains("sucuri") || lower.contains("incapsula")
                || lower.contains("mod_security") || lower.contains("wordfence")) {
            fp.wafDetected = true;
            fp.evidence.add("WAF indicators found in HTML");
        }

        // Technology hints → likely database
        if (lower.contains(".php") || lower.contains("x-powered-by: php")) {
            fp.technologies.add("PHP");
            if (!fp.sqlDetected && fp.detectedDatabases.isEmpty()) {
                fp.sqlDetected = true;
                fp.detectedDatabases.add("MySQL");
                fp.evidence.add("PHP detected — MySQL likely");
            }
        }
        if (lower.contains("asp.net") || lower.contains("__viewstate") || lower.contains("__eventvalidation")) {
            fp.technologies.add("ASP.NET");
            if (!fp.sqlDetected && fp.detectedDatabases.isEmpty()) {
                fp.sqlDetected = true;
                fp.detectedDatabases.add("Microsoft SQL Server");
                fp.evidence.add("ASP.NET detected — MSSQL likely");
            }
        }
        if (lower.contains("django") || lower.contains("csrfmiddlewaretoken")) {
            fp.technologies.add("Django");
        }
        if (lower.contains("laravel") || lower.contains("laravel_session")) {
            fp.technologies.add("Laravel");
            if (!fp.sqlDetected && fp.detectedDatabases.isEmpty()) {
                fp.sqlDetected = true;
                fp.detectedDatabases.add("MySQL");
                fp.evidence.add("Laravel detected — MySQL likely");
            }
        }
        if (lower.contains("express") || lower.contains("x-powered-by: express")) {
            fp.technologies.add("Express.js");
        }
    }

    private void detectDatabaseFromText(SiteFingerprint fp, String text) {
        if (text.contains("mysql") || text.contains("mariadb")) {
            fp.sqlDetected = true;
            fp.detectedDatabases.add("MySQL");
            fp.evidence.add("MySQL connection detected in sensitive info");
        }
        if (text.contains("postgresql") || text.contains("postgres")) {
            fp.sqlDetected = true;
            fp.detectedDatabases.add("PostgreSQL");
            fp.evidence.add("PostgreSQL connection detected in sensitive info");
        }
        if (text.contains("mongodb") || text.contains("mongo://") || text.contains("mongoose")) {
            fp.noSqlDetected = true;
            fp.detectedDatabases.add("MongoDB");
            fp.evidence.add("MongoDB connection detected in sensitive info");
        }
        if (text.contains("mssql") || text.contains("sqlserver") || text.contains("sql server")) {
            fp.sqlDetected = true;
            fp.detectedDatabases.add("Microsoft SQL Server");
            fp.evidence.add("MSSQL connection detected in sensitive info");
        }
        if (text.contains("oracle") || text.contains("ora-")) {
            fp.sqlDetected = true;
            fp.detectedDatabases.add("Oracle");
            fp.evidence.add("Oracle connection detected in sensitive info");
        }
        if (text.contains("sqlite")) {
            fp.sqlDetected = true;
            fp.detectedDatabases.add("SQLite");
            fp.evidence.add("SQLite usage detected in sensitive info");
        }
    }

    /**
     * Map architecture CMS enum to CMS profile name used in injection profiles.
     */
    private String mapArchitectureCmsToName(ArchitectureInfo.CMS cms) {
        return switch (cms) {
            case WORDPRESS, WOOCOMMERCE -> "WordPress";
            case DRUPAL -> "Drupal";
            case JOOMLA -> "Joomla";
            case MAGENTO -> "Magento";
            case SHOPIFY -> "Shopify";
            case LARAVEL -> null; // framework, not CMS for injection profiles
            case DJANGO -> null;
            case RAILS -> null;
            case NEXTJS, NUXTJS, GATSBY -> null;
            case STRAPI, CONTENTFUL -> null;
            default -> null;
        };
    }

    /**
     * Select payload categories based on the site fingerprint.
     * Returns a filtered list of payloads relevant to the detected technology stack.
     */
    public List<String> selectPayloads(SiteFingerprint fingerprint) {
        Set<String> selectedCategories = new LinkedHashSet<>();

        // Always include error-based (fast, universal detection probe)
        selectedCategories.add("error-based");

        // Always include auth-bypass if login forms detected (or as default)
        if (fingerprint.hasLoginForms) {
            selectedCategories.add("auth-bypass");
        }

        // SQL database categories
        if (fingerprint.sqlDetected) {
            selectedCategories.add("boolean-based");
            selectedCategories.add("union-based");
            selectedCategories.add("info-extraction");
            selectedCategories.add("time-based");
            selectedCategories.add("integer-injection");
            selectedCategories.add("stacked-queries");
            selectedCategories.add("auth-bypass");
        }

        // NoSQL categories
        if (fingerprint.noSqlDetected) {
            selectedCategories.add("nosql");
        }

        // XPath for XML/SOAP services
        if (fingerprint.xmlSoapDetected) {
            selectedCategories.add("xpath");
        }

        // LDAP injection
        if (fingerprint.ldapDetected) {
            selectedCategories.add("ldap");
        }

        // WAF evasion
        if (fingerprint.wafDetected) {
            selectedCategories.add("encoding-evasion");
        }

        // Collect filtered payloads from selected categories
        List<String> selected = new ArrayList<>();
        for (String category : selectedCategories) {
            List<String> categoryPayloads = payloadsByCategory.get(category);
            if (categoryPayloads == null) continue;

            if ("time-based".equals(category) && !fingerprint.detectedDatabases.isEmpty()) {
                // For time-based, filter by detected DB engine for precision
                selected.addAll(filterTimeBasedPayloads(categoryPayloads, fingerprint.detectedDatabases));
            } else {
                selected.addAll(categoryPayloads);
            }
        }

        fingerprint.selectedCategories.addAll(selectedCategories);
        return selected;
    }

    /**
     * Filter time-based payloads to match the detected database engine.
     * E.g., skip WAITFOR DELAY for MySQL targets, skip SLEEP for MSSQL targets.
     */
    private List<String> filterTimeBasedPayloads(List<String> timePayloads, Set<String> databases) {
        List<String> filtered = new ArrayList<>();
        for (String payload : timePayloads) {
            String upper = payload.toUpperCase();
            boolean relevant = false;

            if (databases.contains("MySQL") || databases.contains("MariaDB")) {
                if (upper.contains("SLEEP") || upper.contains("BENCHMARK")) relevant = true;
            }
            if (databases.contains("Microsoft SQL Server")) {
                if (upper.contains("WAITFOR")) relevant = true;
            }
            if (databases.contains("PostgreSQL")) {
                if (upper.contains("PG_SLEEP")) relevant = true;
            }
            // For Oracle, SQLite, or unknown SQL types — include all time-based
            if (databases.contains("Oracle") || databases.contains("SQLite")
                    || databases.stream().noneMatch(db ->
                    db.equals("MySQL") || db.equals("MariaDB")
                            || db.equals("Microsoft SQL Server") || db.equals("PostgreSQL"))) {
                relevant = true;
            }

            if (relevant) filtered.add(payload);
        }
        return filtered.isEmpty() ? timePayloads : filtered;
    }

    // =================== Site Fingerprint ===================

    /**
     * Represents the technology fingerprint of a target site,
     * used to intelligently select injection payload categories.
     */
    public static class SiteFingerprint {
        private final Set<String> detectedDatabases = new LinkedHashSet<>();
        private final Set<String> technologies = new LinkedHashSet<>();
        private final Set<String> selectedCategories = new LinkedHashSet<>();
        private final List<String> evidence = new ArrayList<>();
        private String detectedCms;
        private boolean noSqlDetected;
        private boolean sqlDetected;
        private boolean wafDetected;
        private boolean xmlSoapDetected;
        private boolean ldapDetected;
        private boolean hasLoginForms;

        public Set<String> getDetectedDatabases() { return Collections.unmodifiableSet(detectedDatabases); }
        public Set<String> getTechnologies() { return Collections.unmodifiableSet(technologies); }
        public Set<String> getSelectedCategories() { return Collections.unmodifiableSet(selectedCategories); }
        public List<String> getEvidence() { return Collections.unmodifiableList(evidence); }
        public String getDetectedCms() { return detectedCms; }
        public boolean isNoSqlDetected() { return noSqlDetected; }
        public boolean isSqlDetected() { return sqlDetected; }
        public boolean isWafDetected() { return wafDetected; }
        public boolean isXmlSoapDetected() { return xmlSoapDetected; }
        public boolean isLdapDetected() { return ldapDetected; }
        public boolean isHasLoginForms() { return hasLoginForms; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("SiteFingerprint{");
            if (detectedCms != null) sb.append("cms=").append(detectedCms).append(", ");
            if (!detectedDatabases.isEmpty()) sb.append("db=").append(detectedDatabases).append(", ");
            if (!technologies.isEmpty()) sb.append("tech=").append(technologies).append(", ");
            sb.append("sql=").append(sqlDetected);
            sb.append(", nosql=").append(noSqlDetected);
            sb.append(", waf=").append(wafDetected);
            if (xmlSoapDetected) sb.append(", xml/soap");
            if (ldapDetected) sb.append(", ldap");
            if (hasLoginForms) sb.append(", loginForms");
            sb.append("}");
            return sb.toString();
        }
    }

    // =================== Response Analysis Helpers ===================

    /**
     * Check if the response body contains WAF or input filter rejection patterns.
     */
    private boolean isWafRejection(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) return false;
        for (Pattern p : WAF_REJECTION_PATTERNS) {
            if (p.matcher(responseBody).find()) return true;
        }
        return false;
    }

    /**
     * Check if two response bodies are structurally similar (same page).
     * Uses length comparison with tolerance for dynamic content (CSRF tokens, timestamps).
     */
    private boolean isSimilarResponse(String body1, String body2) {
        if (body1 == null && body2 == null) return true;
        if (body1 == null || body2 == null) return false;
        int len1 = body1.length();
        int len2 = body2.length();
        if (len1 == 0 && len2 == 0) return true;
        // Length-based similarity: within 5% tolerance (min 50 chars for small pages)
        int maxLen = Math.max(len1, len2);
        return Math.abs(len1 - len2) <= Math.max(maxLen * 0.05, 50);
    }

    /**
     * Fetch a baseline response (clean request without injection) for comparison.
     */
    private BaselineResponse fetchBaseline(String endpointUrl, EndpointInfo endpoint) {
        try {
            String method = endpoint.getHttpMethod() != null ? endpoint.getHttpMethod() : "GET";
            String testUrl;
            String postBody = null;

            if ("GET".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method)) {
                // For GET, include known parameters with benign values as baseline
                List<String> params = endpoint.getParameters();
                if (params != null && !params.isEmpty()) {
                    StringBuilder qs = new StringBuilder(endpointUrl).append(endpointUrl.contains("?") ? "&" : "?");
                    for (int i = 0; i < params.size(); i++) {
                        if (i > 0) qs.append("&");
                        qs.append(URLEncoder.encode(params.get(i), StandardCharsets.UTF_8)).append("=test");
                    }
                    testUrl = qs.toString();
                } else {
                    testUrl = endpointUrl;
                }
            } else {
                testUrl = endpointUrl;
                postBody = buildBaselineBody(endpoint);
            }

            long startTime = System.currentTimeMillis();
            HttpResponse response = sendRequest(testUrl, method, postBody);
            long responseTime = System.currentTimeMillis() - startTime;

            if (response == null) return null;
            return new BaselineResponse(response.statusCode, response.body, response.body.length(), responseTime);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Build a normal (non-injection) request body for baseline POST requests.
     */
    private String buildBaselineBody(EndpointInfo endpoint) {
        List<String> params = endpoint.getParameters();
        if (params != null && !params.isEmpty()) {
            StringBuilder body = new StringBuilder();
            for (int i = 0; i < params.size(); i++) {
                if (i > 0) body.append("&");
                body.append(URLEncoder.encode(params.get(i), StandardCharsets.UTF_8));
                body.append("=test");
            }
            return body.toString();
        }
        return "id=test";
    }

    // --- Inner classes ---

    private record HttpResponse(int statusCode, String body) {}

    private record BaselineResponse(int statusCode, String body, int bodyLength, long responseTime) {}

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
