package it.r2u.anibus.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;

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
        private List<ExtractedKey> keys;
        private List<String> exposedEndpoints;
        private boolean hasAdminConsole;
        private String adminUrl;
        private boolean hasAccountConsole;
        private String accountConsoleUrl;
        private boolean selfRegistrationEnabled;
        private boolean sslValid;
        private String sslIssue;
        private final List<String> securityWarnings = new ArrayList<>();
        
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
        public List<ExtractedKey> getKeys() { return keys; }
        public List<String> getExposedEndpoints() { return exposedEndpoints; }
        public boolean hasAdminConsole() { return hasAdminConsole; }
        public void setHasAdminConsole(boolean hasAdminConsole) { this.hasAdminConsole = hasAdminConsole; }
        public String getAdminUrl() { return adminUrl; }
        public void setAdminUrl(String adminUrl) { this.adminUrl = adminUrl; }
        public boolean hasAccountConsole() { return hasAccountConsole; }
        public void setHasAccountConsole(boolean v) { this.hasAccountConsole = v; }
        public String getAccountConsoleUrl() { return accountConsoleUrl; }
        public void setAccountConsoleUrl(String url) { this.accountConsoleUrl = url; }
        public boolean isSelfRegistrationEnabled() { return selfRegistrationEnabled; }
        public void setSelfRegistrationEnabled(boolean v) { this.selfRegistrationEnabled = v; }
        public boolean isSslValid() { return sslValid; }
        public void setSslValid(boolean v) { this.sslValid = v; }
        public String getSslIssue() { return sslIssue; }
        public void setSslIssue(String v) { this.sslIssue = v; }
        public List<String> getSecurityWarnings() { return securityWarnings; }
        
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
                sb.append("  [WARN] Admin Console EXPOSED: ").append(adminUrl).append("\n");
            }
            
            if (hasAccountConsole && accountConsoleUrl != null) {
                sb.append("  [WARN] Account Console EXPOSED: ").append(accountConsoleUrl).append("\n");
            }
            
            if (selfRegistrationEnabled) {
                sb.append("  [CRITICAL] Self-Registration is ENABLED — anyone can create accounts!\n");
            }
            
            if (!sslValid && sslIssue != null) {
                sb.append("  [WARN] SSL Certificate Issue: ").append(sslIssue).append("\n");
            }
            
            if (!securityWarnings.isEmpty()) {
                sb.append("  [SECURITY WARNINGS]\n");
                for (String warn : securityWarnings) {
                    sb.append("    ⚠ ").append(warn).append("\n");
                }
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
        private String keyValue;
        private String source; // URL where found
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
        
        // Enhanced checks
        checkAdminConsole(baseUrl, info);
        checkAccountConsole(baseUrl, info);
        checkSelfRegistration(baseUrl, info);
        checkSslCertificate(host, port, info);
        extractVersionFromHtml(baseUrl, info);
        
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
                        
                        // Try to find realm name
                        Pattern realmPattern = Pattern.compile("\"realm\"\\s*:\\s*\"([^\"]+)\"");
                        matcher = realmPattern.matcher(response);
                        if (matcher.find()) {
                            String realmName = matcher.group(1);
                            info.setRealmUrl(baseUrl + "/auth/realms/" + realmName);
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
        // Try to access realm configurations
        String[] realms = {"master", "main", "default", "demo", "ready2tools"}; // Added ready2tools for r2u
        String[] realmBasePaths = {"/auth/realms/", "/keycloak/realms/", "/realms/"};
        
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
        String[] realms = {"master", "main", "default", "demo", "ready2tools"}; // Added ready2tools for r2u
        String[] realmBasePaths = {"/auth/realms/", "/keycloak/realms/", "/realms/"};
        
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
        Pattern credentialsPattern = Pattern.compile("\"credentials\"\\s*:\\s*\\{[^}]*\"secret\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = credentialsPattern.matcher(content);
        if (matcher.find()) {
            String secret = matcher.group(1);
            ExtractedKey key = new ExtractedKey("client_secret", secret, url);
            info.getKeys().add(key);
        }
        extractKeysFromContent(content, url, info);
    }

    // ═══════════════════════════════════════════════════════════
    //  Enhanced Keycloak Security Checks
    // ═══════════════════════════════════════════════════════════

    /**
     * Check if Admin Console is publicly accessible.
     */
    private static void checkAdminConsole(String baseUrl, KeycloakInfo info) {
        String[] adminPaths = {
            "/keycloak/admin/", "/auth/admin/", "/admin/",
            "/keycloak/admin/master/console/", "/auth/admin/master/console/"
        };
        for (String path : adminPaths) {
            try {
                String url = baseUrl + path;
                String content = fetchUrl(url);
                if (content != null) {
                    String lower = content.toLowerCase();
                    if (lower.contains("keycloak") || lower.contains("admin console")
                            || lower.contains("sign in") || lower.contains("login-actions")) {
                        info.setHasAdminConsole(true);
                        info.setAdminUrl(url);
                        info.getExposedEndpoints().add(url);
                        info.getSecurityWarnings().add(
                            "Admin Console is publicly accessible at " + url
                            + " — restrict via reverse proxy / IP allowlist");
                        return;
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    /**
     * Check if Account Console is publicly accessible for each realm.
     */
    private static void checkAccountConsole(String baseUrl, KeycloakInfo info) {
        String[] realms = {"master", "main", "default", "demo", "ready2tools"};
        String[] bases  = {"/keycloak/realms/", "/auth/realms/", "/realms/"};
        for (String bp : bases) {
            for (String realm : realms) {
                try {
                    String url = baseUrl + bp + realm + "/account/";
                    String content = fetchUrl(url);
                    if (content != null) {
                        String lower = content.toLowerCase();
                        if (lower.contains("account console") || lower.contains("account management")
                                || lower.contains("keycloak")) {
                            info.setHasAccountConsole(true);
                            info.setAccountConsoleUrl(url);
                            info.getExposedEndpoints().add(url);
                            info.getSecurityWarnings().add(
                                "Account Console exposed for realm '" + realm + "' at " + url);
                            return;
                        }
                    }
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Check if self-registration is enabled on any discovered realm.
     */
    private static void checkSelfRegistration(String baseUrl, KeycloakInfo info) {
        String[] realms = {"master", "main", "default", "demo", "ready2tools"};
        String[] bases  = {"/keycloak/realms/", "/auth/realms/", "/realms/"};
        for (String bp : bases) {
            for (String realm : realms) {
                try {
                    // The registration page returns HTTP 200 when self-reg is on
                    String regUrl = baseUrl + bp + realm + "/login-actions/registration";
                    HttpURLConnection conn = openConnection(regUrl);
                    conn.setRequestMethod("GET");
                    conn.setConnectTimeout(TIMEOUT);
                    conn.setReadTimeout(TIMEOUT);
                    conn.setInstanceFollowRedirects(true);
                    conn.setRequestProperty("User-Agent", "Mozilla/5.0");
                    int code = conn.getResponseCode();
                    if (code == 200) {
                        StringBuilder body = new StringBuilder();
                        try (BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                            String line;
                            while ((line = r.readLine()) != null && body.length() < 50_000) body.append(line);
                        }
                        String lower = body.toString().toLowerCase();
                        if (lower.contains("register") || lower.contains("sign up")
                                || lower.contains("create account")
                                || lower.contains("kc-register-form")) {
                            info.setSelfRegistrationEnabled(true);
                            info.getSecurityWarnings().add(
                                "Self-registration is ENABLED on realm '" + realm
                                + "' — anyone can create accounts");
                            return;
                        }
                    }
                    conn.disconnect();
                } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Validate SSL certificate (expiry, issuer, self-signed).
     */
    private static void checkSslCertificate(String host, int port, KeycloakInfo info) {
        try {
            URI uri = new URI("https://" + host + ":" + port);
            HttpURLConnection raw = (HttpURLConnection) uri.toURL().openConnection();
            if (!(raw instanceof HttpsURLConnection httpsConn)) {
                return; // not HTTPS
            }
            // Use default trust-manager so we can detect real cert issues
            httpsConn.setConnectTimeout(TIMEOUT);
            httpsConn.setReadTimeout(TIMEOUT);
            httpsConn.setRequestProperty("User-Agent", "Mozilla/5.0");
            try {
                httpsConn.connect();
                Certificate[] certs = httpsConn.getServerCertificates();
                if (certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                    Date now = new Date();
                    if (now.after(x509.getNotAfter())) {
                        info.setSslValid(false);
                        info.setSslIssue("Certificate EXPIRED on " + x509.getNotAfter());
                        info.getSecurityWarnings().add("SSL certificate expired: " + x509.getNotAfter());
                    } else if (now.before(x509.getNotBefore())) {
                        info.setSslValid(false);
                        info.setSslIssue("Certificate not yet valid (starts " + x509.getNotBefore() + ")");
                    } else {
                        info.setSslValid(true);
                        // Check if self-signed
                        if (x509.getIssuerX500Principal().equals(x509.getSubjectX500Principal())) {
                            info.setSslIssue("Self-signed certificate");
                            info.getSecurityWarnings().add(
                                "Self-signed SSL certificate — traffic can be MITM-intercepted");
                        }
                    }
                }
                httpsConn.disconnect();
            } catch (javax.net.ssl.SSLHandshakeException e) {
                info.setSslValid(false);
                info.setSslIssue("SSL handshake failed: " + e.getMessage());
                info.getSecurityWarnings().add("SSL handshake failure (self-signed / expired / mismatched CN)");
            }
        } catch (Exception ignored) {}
    }

    /**
     * Try to extract Keycloak version from HTML pages or server headers.
     */
    private static void extractVersionFromHtml(String baseUrl, KeycloakInfo info) {
        if (info.getVersion() != null) return; // already found
        String[] paths = {
            "/keycloak/", "/auth/", "/keycloak/admin/", "/auth/admin/",
            "/keycloak/welcome-content/", "/auth/welcome-content/"
        };
        Pattern[] versionPatterns = {
            Pattern.compile("Keycloak[\\s\\-/]v?(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"version\"\\s*:\\s*\"(\\d+\\.\\d+\\.\\d+)\""),
            Pattern.compile("kc-logo-text[^>]*>[^<]*?(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/resources/(\\d+\\.\\d+\\.\\d+)/")
        };
        for (String path : paths) {
            try {
                String content = fetchUrl(baseUrl + path);
                if (content == null) continue;
                for (Pattern p : versionPatterns) {
                    Matcher m = p.matcher(content);
                    if (m.find()) {
                        info.setVersion(m.group(1));
                        return;
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    /**
     * Opens an HTTP(S) connection with SSL trust-all for scanning.
     */
    private static HttpURLConnection openConnection(String url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URI(url).toURL().openConnection();
        if (conn instanceof HttpsURLConnection httpsConn) {
            javax.net.ssl.TrustManager[] trustAll = {new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String t) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String t) {}
            }};
            javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
            sc.init(null, trustAll, new java.security.SecureRandom());
            httpsConn.setSSLSocketFactory(sc.getSocketFactory());
            httpsConn.setHostnameVerifier((h, s) -> true);
        }
        return conn;
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
            
            // For HTTPS, trust all certificates
            if (conn instanceof javax.net.ssl.HttpsURLConnection) {
                javax.net.ssl.HttpsURLConnection httpsConn = (javax.net.ssl.HttpsURLConnection) conn;
                javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    }
                };
                javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
                sc.init(null, trustAll, new java.security.SecureRandom());
                httpsConn.setSSLSocketFactory(sc.getSocketFactory());
                httpsConn.setHostnameVerifier((hostname, session) -> true);
            }
            
            int responseCode = conn.getResponseCode();
            
            if (responseCode == 200) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder content = new StringBuilder();
                String line;
                int totalSize = 0;
                
                while ((line = in.readLine()) != null && totalSize < MAX_FILE_SIZE) {
                    content.append(line).append("\n");
                    totalSize += line.length();
                }
                in.close();
                conn.disconnect();
                
                return content.toString();
            }
            
            conn.disconnect();
        } catch (Exception e) {
            // Silently fail
        }
        
        return null;
    }
}
