package it.r2u.anibus.service.detection;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Identity Provider Detection Service.
 *
 * Detects the following IAM / SSO platforms and extracts exposed keys /
 * configuration from their well-known endpoints:
 *
 * Self-hosted: Authentik, Zitadel, Casdoor, Authelia, Shibboleth, Gluu,
 *              IdentityServer (Duende / IdentityServer4)
 * Cloud SaaS:  Auth0, Okta, Clerk, Firebase Authentication, AWS Cognito,
 *              Azure Active Directory (Microsoft Entra ID), Logto
 */
public class IdentityProviderDetector {

    private static final int TIMEOUT     = 6_000;
    private static final int MAX_BYTES   = 2 * 1024 * 1024;

    // ── Public result types ───────────────────────────────────────────────────

    public static class ProviderInfo {
        private boolean detected;
        private String  providerName;
        private String  category;        // "Self-hosted" | "Cloud SaaS"
        private String  version;
        private String  detectedRealm;   // tenant / realm / organisation name
        private final List<String>        exposedEndpoints = new ArrayList<>();
        private final List<ExtractedKey>  keys             = new ArrayList<>();
        private final List<String>        clientRefs       = new ArrayList<>(); // client IDs, app IDs found

        public boolean isDetected()               { return detected; }
        public String  getProviderName()          { return providerName; }
        public String  getCategory()              { return category; }
        public String  getVersion()               { return version; }
        public String  getDetectedRealm()         { return detectedRealm; }
        public List<String>       getExposedEndpoints() { return exposedEndpoints; }
        public List<ExtractedKey> getKeys()             { return keys; }
        public List<String>       getClientRefs()       { return clientRefs; }

        void setDetected(boolean v)      { detected      = v; }
        void setProviderName(String v)   { providerName  = v; }
        void setCategory(String v)       { category      = v; }
        void setVersion(String v)        { version       = v; }
        void setDetectedRealm(String v)  { detectedRealm = v; }

        @Override
        public String toString() {
            if (!detected) return "";
            StringBuilder sb = new StringBuilder();
            sb.append("[IAM] ").append(providerName).append(" Detected");
            if (category != null)   sb.append(" [").append(category).append("]");
            sb.append("\n");
            if (version != null)    sb.append("  Version: ").append(version).append("\n");
            if (detectedRealm != null) sb.append("  Tenant/Realm: ").append(detectedRealm).append("\n");
            if (!exposedEndpoints.isEmpty()) {
                sb.append("  [ENDPOINTS] Exposed Endpoints:\n");
                exposedEndpoints.forEach(e -> sb.append("    - ").append(e).append("\n"));
            }
            if (!clientRefs.isEmpty()) {
                sb.append("  [INFO] Client References:\n");
                clientRefs.forEach(c -> sb.append("    - ").append(c).append("\n"));
            }
            if (!keys.isEmpty()) {
                sb.append("  [ALERT] EXPOSED KEYS FOUND:\n");
                keys.forEach(k -> sb.append("    ").append(k).append("\n"));
            }
            return sb.toString().trim();
        }
    }

    public static class ExtractedKey {
        private final String type;       // "public", "private", "client_secret", "jwk"
        private final String value;
        private final String source;
        private String algorithm;
        private String context;

        public ExtractedKey(String type, String value, String source) {
            this.type = type; this.value = value; this.source = source;
        }
        void setAlgorithm(String a) { algorithm = a; }
        void setContext(String c)   { context   = c; }
        public String getType()  { return type;  }
        public String getValue() { return value; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(type.toUpperCase()).append(" KEY");
            if (algorithm != null) sb.append(" (").append(algorithm).append(")");
            if (context   != null) sb.append(" [").append(context).append("]");
            sb.append(": ").append(value);
            sb.append("\n    Found in: ").append(source);
            return sb.toString();
        }
    }

    // ── Provider profiles ─────────────────────────────────────────────────────

    /** Immutable fingerprint descriptor for one provider. */
    private record ProviderProfile(
            String name,
            String category,
            String[] probePaths,          // HTTP paths to try
            String[] htmlSignatures,      // case-insensitive substrings to look for
            String[] headerSignatures,    // response header prefixes/values
            String[] oidcPaths,           // well-known OIDC paths (relative)
            Pattern  versionPattern,      // optional version extractor
            Pattern  tenantPattern,       // optional tenant/realm extractor from body
            Pattern  clientIdPattern      // optional client-id extractor from body
    ) {}

    private static final ProviderProfile[] PROFILES = {

        // ── Self-hosted ──────────────────────────────────────────────────────

        new ProviderProfile(
            "Authentik", "Self-hosted",
            new String[]{ "/", "/if/flow/default-authentication-flow/" },
            new String[]{ "authentik", "goauthentik.io", "ak-application-wizard", "ak-flow-provider" },
            new String[]{ "x-authentik" },
            new String[]{ "/application/o/.well-known/openid-configuration",
                          "/.well-known/openid-configuration" },
            Pattern.compile("authentik[\\s_-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            null,
            Pattern.compile("\"client_id\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Zitadel", "Self-hosted",
            new String[]{ "/", "/ui/login" },
            new String[]{ "zitadel", "ZITADEL" },
            new String[]{ "x-zitadel", "grpc-status" },
            new String[]{ "/.well-known/openid-configuration",
                          "/oauth/v2/.well-known/openid-configuration" },
            Pattern.compile("zitadel[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"organization_id\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"client_id\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Casdoor", "Self-hosted",
            new String[]{ "/", "/login" },
            new String[]{ "casdoor", "Casdoor" },
            new String[]{ "x-casdoor" },
            new String[]{ "/.well-known/openid-configuration",
                          "/api/.well-known/openid-configuration" },
            Pattern.compile("casdoor[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"owner\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"clientId\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Authelia", "Self-hosted",
            new String[]{ "/", "/api/state" },
            new String[]{ "authelia", "Authelia" },
            new String[]{ "x-authelia" },
            new String[]{ "/api/oidc/.well-known/openid-configuration",
                          "/.well-known/openid-configuration" },
            Pattern.compile("authelia[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            null,
            Pattern.compile("\"client_id\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Shibboleth IdP", "Self-hosted",
            new String[]{ "/idp/", "/idp/status", "/Shibboleth.sso/Status" },
            new String[]{ "shibboleth", "Shib-", "ShibbolethDS", "idp/profile" },
            new String[]{ "shib-", "x-shibboleth" },
            new String[]{ "/idp/shibboleth" }, // Shibboleth metadata URL (XML)
            Pattern.compile("Shibboleth[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("entityID\\s*=\\s*\"([^\"]+)\""),
            null
        ),

        new ProviderProfile(
            "Gluu Server", "Self-hosted",
            new String[]{ "/oxauth/", "/identity/", "/.well-known/openid-configuration" },
            new String[]{ "gluu", "GluuCE", "oxAuth" },
            new String[]{ "x-gluu", "x-oxauth" },
            new String[]{ "/.well-known/openid-configuration",
                          "/oxauth/.well-known/openid-configuration" },
            Pattern.compile("gluu[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"issuer\"\\s*:\\s*\"([^\"]+)\""),
            null
        ),

        new ProviderProfile(
            "IdentityServer (Duende)", "Self-hosted",
            new String[]{ "/connect/authorize", "/.well-known/openid-configuration" },
            new String[]{ "IdentityServer", "Duende", "OpenIddict" },
            new String[]{ "x-identityserver", "x-powered-by: Duende" },
            new String[]{ "/.well-known/openid-configuration" },
            Pattern.compile("Duende[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"issuer\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"client_id\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Logto", "Self-hosted",
            new String[]{ "/", "/sign-in", "/api/swagger.json" },
            new String[]{ "logto", "Logto" },
            new String[]{ "x-logto" },
            new String[]{ "/oidc/.well-known/openid-configuration",
                          "/.well-known/openid-configuration" },
            Pattern.compile("logto[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"tenant_id\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"app_id\"\\s*:\\s*\"([^\"]+)\"")
        ),

        // ── Cloud SaaS ───────────────────────────────────────────────────────

        new ProviderProfile(
            "Auth0", "Cloud SaaS",
            new String[]{ "/", "/.well-known/openid-configuration",
                          "/userinfo", "/authorize" },
            new String[]{ "auth0", "Auth0", "a0-lock", "__auth0" },
            new String[]{ "x-auth0", "set-cookie: auth0" },
            new String[]{ "/.well-known/openid-configuration",
                          "/.well-known/jwks.json" },
            Pattern.compile("auth0[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"tenant\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"clientID\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Okta", "Cloud SaaS",
            new String[]{ "/", "/oauth2/default/.well-known/openid-configuration",
                          "/.well-known/openid-configuration", "/api/v1/well-known/oidc" },
            new String[]{ "okta", "Okta", "okta-signin", "OktaAuth", "_okta_" },
            new String[]{ "x-okta", "set-cookie: oktaStateToken" },
            new String[]{ "/oauth2/default/.well-known/openid-configuration",
                          "/.well-known/openid-configuration" },
            Pattern.compile("okta[\\s/-]*(\\d+\\.\\d+[.\\d]*)", Pattern.CASE_INSENSITIVE),
            null,
            Pattern.compile("\"clientId\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Clerk", "Cloud SaaS",
            new String[]{ "/", "/.well-known/jwks.json",
                          "/.well-known/openid-configuration" },
            new String[]{ "clerk", "Clerk", "__clerk_frontend_api", "clerk.js" },
            new String[]{ "x-clerk" },
            new String[]{ "/.well-known/jwks.json",
                          "/.well-known/openid-configuration" },
            null,
            Pattern.compile("\"organization_id\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"publishableKey\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Firebase Authentication", "Cloud SaaS",
            new String[]{ "/", "/__/auth/iframe", "/__/firebase/init.json" },
            new String[]{ "firebase", "FirebaseUI", "firebaseapp.com",
                          "firebaseConfig", "identitytoolkit" },
            new String[]{ "x-firebase" },
            new String[]{ }, // Firebase does not expose a standard JWKS endpoint directly
            null,
            Pattern.compile("\"projectId\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"apiKey\"\\s*:\\s*\"([A-Za-z0-9_\\-]{35,})\"")
        ),

        new ProviderProfile(
            "AWS Cognito", "Cloud SaaS",
            new String[]{ "/", "/login", "/oauth2/token",
                          "/.well-known/openid-configuration" },
            new String[]{ "cognito", "Cognito", "amazonaws.com/cognito",
                          "CognitoIdentityServiceProvider", "AmazonCognitoIdentity" },
            new String[]{ "x-amzn-cognito", "x-amz-cf" },
            new String[]{ "/.well-known/openid-configuration" },
            null,
            Pattern.compile("\"userPoolId\"\\s*:\\s*\"([^\"]+)\""),
            Pattern.compile("\"userPoolWebClientId\"\\s*:\\s*\"([^\"]+)\"")
        ),

        new ProviderProfile(
            "Azure Active Directory (Entra ID)", "Cloud SaaS",
            new String[]{ "/", "/.well-known/openid-configuration",
                          "/v2.0/.well-known/openid-configuration" },
            new String[]{ "login.microsoftonline.com", "microsoft", "msal",
                          "aadcdn.msauth.net", "MicrosoftAjax", "microsoftonline" },
            new String[]{ "x-ms-", "x-powered-by: ASP.NET" },
            new String[]{ "/v2.0/.well-known/openid-configuration",
                          "/.well-known/openid-configuration" },
            null,
            Pattern.compile("\"tid\"\\s*:\\s*\"([0-9a-f\\-]{36})\""),
            Pattern.compile("\"appId\"\\s*:\\s*\"([0-9a-f\\-]{36})\"")
        ),
    };

    // ── Main entry point ──────────────────────────────────────────────────────

    /**
     * Probe {@code host:port} and attempt to identify any known identity
     * provider.  Returns a {@link ProviderInfo} whose {@code isDetected()}
     * is {@code false} if nothing was found.
     */
    public static ProviderInfo detect(String host, int port, boolean useSSL) {
        String protocol = useSSL ? "https" : "http";
        String baseUrl  = protocol + "://" + host + ":" + port;

        for (ProviderProfile profile : PROFILES) {
            ProviderInfo info = tryProfile(baseUrl, profile);
            if (info.isDetected()) return info;
        }

        return new ProviderInfo(); // not detected
    }

    // ── Per-profile detection ─────────────────────────────────────────────────

    private static ProviderInfo tryProfile(String baseUrl, ProviderProfile p) {
        ProviderInfo info = new ProviderInfo();

        for (String path : p.probePaths()) {
            String body    = fetchUrl(baseUrl + path);
            String headers = fetchHeaders(baseUrl + path);
            if (body == null && headers == null) continue;

            String combined = (body != null ? body : "") + "\n" + (headers != null ? headers : "");
            String lower    = combined.toLowerCase();

            // Check HTML/body signatures
            boolean bodyMatch = false;
            for (String sig : p.htmlSignatures()) {
                if (lower.contains(sig.toLowerCase())) { bodyMatch = true; break; }
            }
            // Check header signatures
            boolean headerMatch = false;
            for (String sig : p.headerSignatures()) {
                if (lower.contains(sig.toLowerCase())) { headerMatch = true; break; }
            }

            if (!bodyMatch && !headerMatch) continue;

            // Confirmed — populate info
            info.setDetected(true);
            info.setProviderName(p.name());
            info.setCategory(p.category());
            info.getExposedEndpoints().add(baseUrl + path);

            // Extract version
            if (p.versionPattern() != null && body != null) {
                Matcher m = p.versionPattern().matcher(body);
                if (m.find()) info.setVersion(m.group(1));
            }

            // Extract tenant / realm / organisation
            if (p.tenantPattern() != null && body != null) {
                Matcher m = p.tenantPattern().matcher(body);
                if (m.find()) info.setDetectedRealm(m.group(1));
            }

            // Extract client IDs / app keys
            if (p.clientIdPattern() != null && body != null) {
                Matcher m = p.clientIdPattern().matcher(body);
                LinkedHashSet<String> seen = new LinkedHashSet<>();
                while (m.find() && seen.size() < 5) seen.add(m.group(1));
                info.getClientRefs().addAll(seen);
            }

            // Try OIDC well-known discovery
            for (String oidcPath : p.oidcPaths()) {
                tryOidcDiscovery(baseUrl, oidcPath, p.name(), info);
            }

            return info;
        }

        return info;
    }

    // ── OIDC / JWKS extraction ────────────────────────────────────────────────

    private static void tryOidcDiscovery(String baseUrl, String oidcPath,
                                          String providerName, ProviderInfo info) {
        String url  = baseUrl + oidcPath;
        String body = fetchUrl(url);
        if (body == null) return;

        info.getExposedEndpoints().add(url);

        // Extract jwks_uri and fetch JWKS
        Pattern jwksPattern = Pattern.compile("\"jwks_uri\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = jwksPattern.matcher(body);
        if (m.find()) {
            String jwksUri = m.group(1);
            fetchJwks(jwksUri, providerName, info);
        }

        // Extract issuer / tenant from discovery doc if not already set
        if (info.getDetectedRealm() == null) {
            Pattern issuerPat = Pattern.compile("\"issuer\"\\s*:\\s*\"([^\"]+)\"");
            Matcher im = issuerPat.matcher(body);
            if (im.find()) info.setDetectedRealm(im.group(1));
        }
    }

    private static void fetchJwks(String jwksUrl, String providerName, ProviderInfo info) {
        String body = fetchUrl(jwksUrl);
        if (body == null || !body.contains("\"keys\"")) return;

        info.getExposedEndpoints().add(jwksUrl);

        // RSA public key modulus (n)
        Pattern nPat = Pattern.compile("\"n\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = nPat.matcher(body);
        while (m.find()) {
            ExtractedKey key = new ExtractedKey("public", m.group(1), jwksUrl);
            key.setAlgorithm("RSA");
            key.setContext("Provider: " + providerName);
            info.getKeys().add(key);
        }

        // EC public key x,y coordinates (just record presence)
        Pattern ecPat = Pattern.compile("\"kty\"\\s*:\\s*\"EC\"[^}]*\"x\"\\s*:\\s*\"([^\"]+)\"");
        Matcher em = ecPat.matcher(body);
        while (em.find()) {
            ExtractedKey key = new ExtractedKey("public", em.group(1), jwksUrl);
            key.setAlgorithm("EC");
            key.setContext("Provider: " + providerName);
            info.getKeys().add(key);
        }

        // Firebase / Cognito: raw PEM certificates embedded in JWK response
        Pattern pemPat = Pattern.compile(
            "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----");
        Matcher pm = pemPat.matcher(body);
        while (pm.find()) {
            ExtractedKey key = new ExtractedKey("public", pm.group(0), jwksUrl);
            key.setAlgorithm("X.509");
            key.setContext("Provider: " + providerName);
            info.getKeys().add(key);
        }
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    /**
     * Fetch response body.  Returns {@code null} on any error or non-200 status.
     * Silently disables SSL certificate verification so internal / self-signed
     * certificates do not block detection.
     */
    private static String fetchUrl(String urlString) {
        try {
            URI uri = new URI(urlString);
            HttpURLConnection conn = openConnection(uri);

            int code = conn.getResponseCode();
            if (code < 200 || code >= 400) { conn.disconnect(); return null; }

            try (BufferedReader in = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                StringBuilder sb = new StringBuilder();
                String line;
                int read = 0;
                while ((line = in.readLine()) != null && read < MAX_BYTES) {
                    sb.append(line).append('\n');
                    read += line.length();
                }
                conn.disconnect();
                return sb.toString();
            }
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Fetch response headers as a concatenated string for signature matching.
     */
    private static String fetchHeaders(String urlString) {
        try {
            URI uri = new URI(urlString);
            HttpURLConnection conn = openConnection(uri);
            conn.getResponseCode(); // trigger the request
            StringBuilder sb = new StringBuilder();
            conn.getHeaderFields().forEach((k, vs) -> {
                if (k != null) vs.forEach(v -> sb.append(k).append(": ").append(v).append('\n'));
            });
            conn.disconnect();
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static HttpURLConnection openConnection(URI uri) throws Exception {
        HttpURLConnection conn =
            (HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(TIMEOUT);
        conn.setReadTimeout(TIMEOUT);
        conn.setRequestProperty("User-Agent",
            "Mozilla/5.0 (compatible; security-scanner/1.0)");
        conn.setInstanceFollowRedirects(true);

        // Disable SSL certificate verification for internal / self-signed certs
        if (conn instanceof javax.net.ssl.HttpsURLConnection https) {
            https.setSSLSocketFactory(TrustAllSsl.SOCKET_FACTORY);
            https.setHostnameVerifier((h, s) -> true);
        }
        return conn;
    }

    // ── Trust-all SSL helper (internal / self-signed certs) ──────────────────

    private static final class TrustAllSsl {
        static final javax.net.ssl.SSLSocketFactory SOCKET_FACTORY;
        static {
            try {
                javax.net.ssl.TrustManager[] tm = {
                    new javax.net.ssl.X509TrustManager() {
                        @Override public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                        @Override public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                        @Override public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
                    }
                };
                javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
                ctx.init(null, tm, new java.security.SecureRandom());
                SOCKET_FACTORY = ctx.getSocketFactory();
            } catch (java.security.NoSuchAlgorithmException | java.security.KeyManagementException ex) {
                throw new RuntimeException("TrustAllSsl init failed", ex);
            }
        }
    }
}
