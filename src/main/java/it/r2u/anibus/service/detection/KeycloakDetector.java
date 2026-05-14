package it.r2u.anibus.service.detection;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Keycloak Detection and Key Extraction Service
 * Detects Keycloak instances and extracts public/private keys from JavaScript files
 */
public class KeycloakDetector {
    
    private static final int TIMEOUT = 5000;
    private static final int MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
    
    public static class KeycloakInfo {
        private boolean isKeycloak;
        private String version;
        private String realmUrl;
        private String detectedRealmName; // realm name found dynamically in the page
        private String keycloakBasePath;  // path prefix where Keycloak was found, e.g. "/keycloak"
        private final List<ExtractedKey> keys;
        private final List<String> exposedEndpoints;
        private boolean hasAdminConsole;
        private String adminUrl;
        
        public KeycloakInfo() {
            this.keys = new ArrayList<>();
            this.exposedEndpoints = new ArrayList<>();
        }
        
        public boolean isKeycloak() { return isKeycloak; }
        public void setKeycloak(boolean keycloak) { isKeycloak = keycloak; }
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
        public String getRealmUrl() { return realmUrl; }
        public void setRealmUrl(String realmUrl) { this.realmUrl = realmUrl; }
        public String getDetectedRealmName() { return detectedRealmName; }
        public void setDetectedRealmName(String name) { this.detectedRealmName = name; }
        public String getKeycloakBasePath() { return keycloakBasePath; }
        public void setKeycloakBasePath(String path) { this.keycloakBasePath = path; }
        public List<ExtractedKey> getKeys() { return keys; }
        public List<String> getExposedEndpoints() { return exposedEndpoints; }
        public boolean hasAdminConsole() { return hasAdminConsole; }
        public void setHasAdminConsole(boolean hasAdminConsole) { this.hasAdminConsole = hasAdminConsole; }
        public String getAdminUrl() { return adminUrl; }
        public void setAdminUrl(String adminUrl) { this.adminUrl = adminUrl; }
        
        @Override
        public String toString() {
            if (!isKeycloak) {
                return "";
            }
            
            StringBuilder sb = new StringBuilder();
            sb.append("[KEYCLOAK] Keycloak Detected!\n");
            
            if (version != null) {
                sb.append("  Version: ").append(version).append("\n");
            }
            
            if (realmUrl != null) {
                sb.append("  Realm URL: ").append(realmUrl).append("\n");
            }
            
            if (hasAdminConsole && adminUrl != null) {
                sb.append("  [WARN] Admin Console: ").append(adminUrl).append("\n");
            }
            
            if (!exposedEndpoints.isEmpty()) {
                sb.append("  [ENDPOINTS] Exposed Endpoints:\n");
                for (String endpoint : exposedEndpoints) {
                    sb.append("    - ").append(endpoint).append("\n");
                }
            }
            
            if (!keys.isEmpty()) {
                sb.append("  [ALERT] EXPOSED KEYS FOUND:\n");
                for (ExtractedKey key : keys) {
                    sb.append("    ").append(key.toString()).append("\n");
                }
            }
            
            return sb.toString().trim();
        }
    }
    
    public static class ExtractedKey {
        private String keyType; // "public", "private", "client_secret"
        private String algorithm; // "RS256", "HS256", etc.
        private final String keyValue;
        private final String source; // URL where found
        private String context; // Additional context (realm name, client ID, etc.)
        
        public ExtractedKey(String keyType, String keyValue, String source) {
            this.keyType = keyType;
            this.keyValue = keyValue;
            this.source = source;
        }
        
        public String getKeyType() { return keyType; }
        public void setKeyType(String keyType) { this.keyType = keyType; }
        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
        public String getKeyValue() { return keyValue; }
        public String getSource() { return source; }
        public String getContext() { return context; }
        public void setContext(String context) { this.context = context; }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(keyType.toUpperCase()).append(" KEY");
            
            if (algorithm != null) {
                sb.append(" (").append(algorithm).append(")");
            }
            
            if (context != null) {
                sb.append(" [").append(context).append("]");
            }
            
            sb.append(": ");
            
            // Show full key value (no truncation for security analysis)
            sb.append(keyValue);
            
            sb.append("\n    Found in: ").append(source);
            
            return sb.toString();
        }
    }
    
    /**
     * Detect Keycloak and extract keys
     */
    public static KeycloakInfo detectKeycloak(String host, int port, boolean useSSL) {
        KeycloakInfo info = new KeycloakInfo();
        
        String protocol = useSSL ? "https" : "http";
        String baseUrl = protocol + "://" + host + ":" + port;
        
        // Check if Keycloak is present
        if (!checkKeycloakEndpoints(baseUrl, info)) {
            return info;
        }
        
        info.setKeycloak(true);
        
        // Try to extract keys from various sources
        extractKeysFromJavaScript(baseUrl, info);
        extractKeysFromRealmConfig(baseUrl, info);
        extractKeysFromWellKnown(baseUrl, info);
        
        return info;
    }
    
    /**
     * Check for Keycloak endpoints
     */
    private static boolean checkKeycloakEndpoints(String baseUrl, KeycloakInfo info) {
        // Common Keycloak paths
        String[] keycloakPaths = {
            "/auth",
            "/auth/",
            "/auth/realms", 
            "/realms",
            "/keycloak",           // Common custom path
            "/keycloak/",
            "/keycloak/realms",
            "/",
            "/auth/admin",
            "/admin"
        };
        
        for (String path : keycloakPaths) {
            try {
                String url = baseUrl + path;
                String response = fetchUrl(url);
                
                if (response != null) {
                    String lower = response.toLowerCase();
                    
                    // Check for Keycloak signatures
                    if (lower.contains("keycloak") || 
                        lower.contains("kc-") ||
                        lower.contains("realm") && lower.contains("auth-server-url") ||
                        lower.contains("\"kc_locale\"") ||
                        lower.contains("keycloak.min.js")) {
                        
                        // Extract version
                        Pattern versionPattern = Pattern.compile("keycloak[\\s-]*(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE);
                        Matcher matcher = versionPattern.matcher(response);
                        if (matcher.find()) {
                            info.setVersion(matcher.group(1));
                        }
                        
                        // Check for admin console
                        if (path.contains("admin") || lower.contains("admin console")) {
                            info.setHasAdminConsole(true);
                            info.setAdminUrl(url);
                        }
                        
                        info.getExposedEndpoints().add(url);

                        // Determine the Keycloak base prefix (e.g. "/keycloak", "/auth", "")
                        String foundPath = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
                        // Strip any trailing segment like "/realms" or "/admin"
                        String kcBase = foundPath;
                        for (String suffix : new String[]{"/realms", "/admin"}) {
                            if (kcBase.endsWith(suffix)) {
                                kcBase = kcBase.substring(0, kcBase.length() - suffix.length());
                                break;
                            }
                        }
                        info.setKeycloakBasePath(kcBase);

                        // Try to find realm name from embedded JSON (handles both
                        // Keycloak login-page context and realm endpoint responses)
                        Pattern realmPattern = Pattern.compile("\"realm\"\\s*:\\s*\"([^\"]+)\"");
                        matcher = realmPattern.matcher(response);
                        if (matcher.find()) {
                            String realmName = matcher.group(1);
                            info.setDetectedRealmName(realmName);
                            // Store the canonical realm URL using the actual base path
                            info.setRealmUrl(baseUrl + kcBase + "/realms/" + realmName);
                        }
                        
                        return true;
                    }
                }
            } catch (Exception e) {
                // Continue checking other paths silently
            }
        }
        
        return false;
    }
    
    /**
     * Extract keys from JavaScript files
     */
    private static void extractKeysFromJavaScript(String baseUrl, KeycloakInfo info) {
        String[] jsPaths = {
            "/auth/js/keycloak.js",
            "/js/keycloak.js",
            "/keycloak.js",
            "/keycloak/js/keycloak.js",         // Custom Keycloak path
            "/keycloak/resources/*/keycloak.js",
            "/auth/resources/*/login/*/*/js/keycloak.js",
            "/resources/*/common/keycloak/js/keycloak.js",
            "/welcome-content/keycloak.js"
        };
        
        for (String jsPath : jsPaths) {
            try {
                String url = baseUrl + jsPath;
                String content = fetchUrl(url);
                
                if (content != null && !content.isEmpty()) {
                    extractKeysFromContent(content, url, info);
                }
            } catch (Exception e) {
                // Continue
            }
        }
        
        // Also scan common config files
        String[] configPaths = {
            "/keycloak.json",
            "/auth/keycloak.json",
            "/config/keycloak.json",
            "/keycloak/keycloak.json",          // Custom Keycloak path
            "/keycloak/config/keycloak.json"
        };
        
        for (String configPath : configPaths) {
            try {
                String url = baseUrl + configPath;
                String content = fetchUrl(url);
                
                if (content != null && !content.isEmpty()) {
                    extractKeysFromConfig(content, url, info);
                }
            } catch (Exception e) {
                // Continue
            }
        }
    }
    
    /**
     * Extract keys from realm configuration
     */
    private static void extractKeysFromRealmConfig(String baseUrl, KeycloakInfo info) {
        // Try to access realm configurations — combine hardcoded list with dynamically discovered realm
        java.util.LinkedHashSet<String> realmSet = new java.util.LinkedHashSet<>();
        if (info.getDetectedRealmName() != null) realmSet.add(info.getDetectedRealmName());
        realmSet.addAll(java.util.Arrays.asList("master", "main", "default", "demo", "ready2tools"));
        String[] realms = realmSet.toArray(new String[0]);

        // Build realm base path list: prefer detected Keycloak base, then fallback paths
        java.util.LinkedHashSet<String> basePathSet = new java.util.LinkedHashSet<>();
        if (info.getKeycloakBasePath() != null) basePathSet.add(info.getKeycloakBasePath() + "/realms/");
        basePathSet.addAll(java.util.Arrays.asList("/auth/realms/", "/keycloak/realms/", "/realms/"));
        String[] realmBasePaths = basePathSet.toArray(new String[0]);

        for (String basePath : realmBasePaths) {
            for (String realm : realms) {
                try {
                    String url = baseUrl + basePath + realm;
                    String content = fetchUrl(url);
                    
                    if (content != null && content.contains("public_key")) {
                        extractPublicKeyFromRealm(content, url, realm, info);
                    }
                } catch (Exception e) {
                    // Continue
                }
            }
        }
    }
    
    /**
     * Extract keys from .well-known/openid-configuration
     */
    private static void extractKeysFromWellKnown(String baseUrl, KeycloakInfo info) {
        // Combine dynamically discovered realm with hardcoded fallbacks
        java.util.LinkedHashSet<String> realmSet = new java.util.LinkedHashSet<>();
        if (info.getDetectedRealmName() != null) realmSet.add(info.getDetectedRealmName());
        realmSet.addAll(java.util.Arrays.asList("master", "main", "default", "demo", "ready2tools"));
        String[] realms = realmSet.toArray(new String[0]);

        java.util.LinkedHashSet<String> basePathSet = new java.util.LinkedHashSet<>();
        if (info.getKeycloakBasePath() != null) basePathSet.add(info.getKeycloakBasePath() + "/realms/");
        basePathSet.addAll(java.util.Arrays.asList("/auth/realms/", "/keycloak/realms/", "/realms/"));
        String[] realmBasePaths = basePathSet.toArray(new String[0]);

        for (String basePath : realmBasePaths) {
            for (String realm : realms) {
                try {
                    // OpenID Connect Discovery endpoint
                    String url = baseUrl + basePath + realm + "/.well-known/openid-configuration";
                    String content = fetchUrl(url);
                    
                    if (content != null) {
                        info.getExposedEndpoints().add(url);
                        
                        // Extract jwks_uri
                        Pattern jwksPattern = Pattern.compile("\"jwks_uri\"\\s*:\\s*\"([^\"]+)\"");
                        Matcher matcher = jwksPattern.matcher(content);
                        
                        if (matcher.find()) {
                            String jwksUri = matcher.group(1);
                            extractKeysFromJWKS(jwksUri, realm, info);
                        }
                    }
                } catch (Exception e) {
                    // Continue
                }
            }
        }
    }
    
    /**
     * Extract keys from JWKS endpoint
     */
    private static void extractKeysFromJWKS(String jwksUrl, String realm, KeycloakInfo info) {
        try {
            String content = fetchUrl(jwksUrl);
            
            if (content != null && content.contains("keys")) {
                info.getExposedEndpoints().add(jwksUrl);
                
                // Extract public keys from JWKS
                Pattern keyPattern = Pattern.compile("\"n\"\\s*:\\s*\"([^\"]+)\"");
                Matcher matcher = keyPattern.matcher(content);
                
                while (matcher.find()) {
                    String modulus = matcher.group(1);
                    ExtractedKey key = new ExtractedKey("public", modulus, jwksUrl);
                    key.setContext("Realm: " + realm);
                    key.setAlgorithm("RSA");
                    info.getKeys().add(key);
                }
            }
        } catch (Exception e) {
            // Silently fail
        }
    }
    
    /**
     * Extract public key from realm JSON
     */
    private static void extractPublicKeyFromRealm(String content, String url, String realm, KeycloakInfo info) {
        Pattern publicKeyPattern = Pattern.compile("\"public_key\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = publicKeyPattern.matcher(content);
        
        if (matcher.find()) {
            String publicKey = matcher.group(1);
            ExtractedKey key = new ExtractedKey("public", publicKey, url);
            key.setContext("Realm: " + realm);
            key.setAlgorithm("RSA");
            info.getKeys().add(key);
        }
    }
    
    /**
     * Extract keys from JavaScript/config content
     */
    private static void extractKeysFromContent(String content, String url, KeycloakInfo info) {
        // Look for various key patterns
        
        // Public key patterns
        Pattern[] publicKeyPatterns = {
            Pattern.compile("public[_-]?key[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9+/=]{100,})[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("publicKey[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9+/=]{100,})[\"']"),
            Pattern.compile("realm-public-key[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9+/=]{100,})[\"']")
        };
        
        for (Pattern pattern : publicKeyPatterns) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String keyValue = matcher.group(1);
                ExtractedKey key = new ExtractedKey("public", keyValue, url);
                key.setAlgorithm("RSA");
                info.getKeys().add(key);
            }
        }
        
        // Private key patterns (very dangerous if exposed!)
        Pattern[] privateKeyPatterns = {
            Pattern.compile("private[_-]?key[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9+/=]{100,})[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("privateKey[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9+/=]{100,})[\"']"),
            Pattern.compile("-----BEGIN (RSA )?PRIVATE KEY-----([\\s\\S]+?)-----END (RSA )?PRIVATE KEY-----")
        };
        
        for (Pattern pattern : privateKeyPatterns) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String keyValue = matcher.group(matcher.groupCount());
                ExtractedKey key = new ExtractedKey("private", keyValue, url);
                key.setAlgorithm("RSA");
                info.getKeys().add(key);
            }
        }
    }
    
    /**
     * Extract keys from config files
     */
    private static void extractKeysFromConfig(String content, String url, KeycloakInfo info) {
        // Client credentials
        Pattern credentialsPattern = Pattern.compile("\"credentials\"\\s*:\\s*\\{[^}]*\"secret\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = credentialsPattern.matcher(content);
        
        if (matcher.find()) {
            String secret = matcher.group(1);
            ExtractedKey key = new ExtractedKey("client_secret", secret, url);
            info.getKeys().add(key);
        }
        
        // Also extract using generic method
        extractKeysFromContent(content, url, info);
    }
    
    /**
     * Fetch URL content
     */
    private static String fetchUrl(String urlString) {
        try {
            URI uri = new URI(urlString);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            conn.setInstanceFollowRedirects(true);
            
            // For HTTPS, keep default JVM certificate and hostname verification.
            if (conn instanceof javax.net.ssl.HttpsURLConnection) {
                // Default verification is intentionally preserved.
            }
            
            int responseCode = conn.getResponseCode();
            
            if (responseCode == 200) {
                try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                    StringBuilder content = new StringBuilder();
                    String line;
                    int totalSize = 0;
                    
                    while ((line = in.readLine()) != null && totalSize < MAX_FILE_SIZE) {
                        content.append(line).append("\n");
                        totalSize += line.length();
                    }
                    conn.disconnect();
                    
                    return content.toString();
                }
            }
            
            conn.disconnect();
        } catch (java.io.IOException | java.net.URISyntaxException e) {
            // Silently fail
        }
        
        return null;
    }
}
