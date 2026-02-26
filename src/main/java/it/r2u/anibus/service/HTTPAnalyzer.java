package it.r2u.anibus.service;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Advanced HTTP Analyzer
 * Provides detailed HTTP/HTTPS analysis including SSL certificates, security headers, CMS detection
 */
public class HTTPAnalyzer {
    
    private static final int TIMEOUT = 5000;
    private static final int MAX_PAGE_SIZE = 5 * 1024 * 1024; // 5 MB
    
    public static class HTTPInfo {
        private String url;
        private String pageTitle;
        private SSLCertInfo sslCert;
        private Map<String, String> securityHeaders;
        private String cms;
        private List<String> technologies;
        private int statusCode;
        private String server;
        
        public HTTPInfo(String url) {
            this.url = url;
            this.securityHeaders = new HashMap<>();
            this.technologies = new ArrayList<>();
        }
        
        // Getters and setters
        public String getUrl() { return url; }
        public String getPageTitle() { return pageTitle; }
        public void setPageTitle(String pageTitle) { this.pageTitle = pageTitle; }
        public SSLCertInfo getSslCert() { return sslCert; }
        public void setSslCert(SSLCertInfo sslCert) { this.sslCert = sslCert; }
        public Map<String, String> getSecurityHeaders() { return securityHeaders; }
        public String getCms() { return cms; }
        public void setCms(String cms) { this.cms = cms; }
        public List<String> getTechnologies() { return technologies; }
        public int getStatusCode() { return statusCode; }
        public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
        public String getServer() { return server; }
        public void setServer(String server) { this.server = server; }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("[HTTP] HTTP Analysis:\n");
            
            if (pageTitle != null) {
                sb.append("  [TITLE] Title: ").append(pageTitle).append("\n");
            }
            
            if (server != null) {
                sb.append("  [SERVER] Server: ").append(server).append("\n");
            }
            
            if (cms != null) {
                sb.append("  [CMS] CMS: ").append(cms).append("\n");
            }
            
            if (!technologies.isEmpty()) {
                sb.append("  [TECH] Technologies: ").append(String.join(", ", technologies)).append("\n");
            }
            
            if (sslCert != null) {
                sb.append(sslCert.toString()).append("\n");
            }
            
            sb.append(formatSecurityHeaders());
            
            return sb.toString().trim();
        }
        
        private String formatSecurityHeaders() {
            if (securityHeaders.isEmpty()) {
                return "  [INSECURE] Security Headers: None found";
            }
            
            StringBuilder sb = new StringBuilder();
            sb.append("  [SECURE] Security Headers:\n");
            
            String[] important = {"Strict-Transport-Security", "Content-Security-Policy", 
                                 "X-Frame-Options", "X-Content-Type-Options", 
                                 "X-XSS-Protection", "Referrer-Policy"};
            
            for (String header : important) {
                if (securityHeaders.containsKey(header)) {
                    sb.append("    ✅ ").append(header).append("\n");
                } else {
                    sb.append("    ❌ ").append(header).append(" (missing)\n");
                }
            }
            
            return sb.toString();
        }
    }
    
    public static class SSLCertInfo {
        private String commonName;
        private String issuer;
        private Date validFrom;
        private Date validTo;
        private boolean isExpired;
        private boolean isSelfSigned;
        private int daysUntilExpiry;
        
        public String getCommonName() { return commonName; }
        public void setCommonName(String commonName) { this.commonName = commonName; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public Date getValidFrom() { return validFrom; }
        public void setValidFrom(Date validFrom) { this.validFrom = validFrom; }
        public Date getValidTo() { return validTo; }
        public void setValidTo(Date validTo) { this.validTo = validTo; }
        public boolean isExpired() { return isExpired; }
        public void setExpired(boolean expired) { isExpired = expired; }
        public boolean isSelfSigned() { return isSelfSigned; }
        public void setSelfSigned(boolean selfSigned) { isSelfSigned = selfSigned; }
        public int getDaysUntilExpiry() { return daysUntilExpiry; }
        public void setDaysUntilExpiry(int daysUntilExpiry) { this.daysUntilExpiry = daysUntilExpiry; }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("  [SSL] SSL Certificate:\n");
            
            if (commonName != null) {
                sb.append("    CN: ").append(commonName).append("\n");
            }
            
            if (issuer != null) {
                sb.append("    Issuer: ").append(issuer).append("\n");
            }
            
            if (isSelfSigned) {
                sb.append("    [WARN] Self-Signed Certificate\n");
            }
            
            if (validTo != null) {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
                sb.append("    Valid Until: ").append(sdf.format(validTo));
                
                if (isExpired) {
                    sb.append(" ❌ EXPIRED\n");
                } else if (daysUntilExpiry < 30) {
                    sb.append(" [WARN] Expires in ").append(daysUntilExpiry).append(" days\n");
                } else {
                    sb.append(" ✅ (").append(daysUntilExpiry).append(" days remaining)\n");
                }
            }
            
            return sb.toString();
        }
    }
    
    /**
     * Analyze HTTP/HTTPS service
     */
    public static HTTPInfo analyzeHTTP(String host, int port, boolean isSSL) {
        String protocol = isSSL ? "https" : "http";
        String url = protocol + "://" + host + ":" + port;
        
        HTTPInfo info = new HTTPInfo(url);
        
        try {
            URI uri = new URI(url);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            conn.setInstanceFollowRedirects(true);
            
            // For HTTPS, get SSL certificate info
            if (isSSL && conn instanceof HttpsURLConnection) {
                HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
                
                // Trust all certificates for scanning purposes
                TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }};
                
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, trustAll, new java.security.SecureRandom());
                httpsConn.setSSLSocketFactory(sc.getSocketFactory());
                httpsConn.setHostnameVerifier((hostname, session) -> true);
                
                conn.connect();
                
                // Get certificate
                Certificate[] certs = httpsConn.getServerCertificates();
                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate cert = (X509Certificate) certs[0];
                    info.setSslCert(extractCertInfo(cert));
                }
            } else {
                conn.connect();
            }
            
            info.setStatusCode(conn.getResponseCode());
            
            // Get headers
            Map<String, List<String>> headers = conn.getHeaderFields();
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                String key = entry.getKey();
                if (key != null) {
                    String value = String.join(", ", entry.getValue());
                    
                    // Collect security headers
                    if (key.equalsIgnoreCase("Strict-Transport-Security") ||
                        key.equalsIgnoreCase("Content-Security-Policy") ||
                        key.equalsIgnoreCase("X-Frame-Options") ||
                        key.equalsIgnoreCase("X-Content-Type-Options") ||
                        key.equalsIgnoreCase("X-XSS-Protection") ||
                        key.equalsIgnoreCase("Referrer-Policy") ||
                        key.equalsIgnoreCase("Permissions-Policy")) {
                        info.getSecurityHeaders().put(key, value);
                    }
                    
                    // Server header
                    if (key.equalsIgnoreCase("Server")) {
                        info.setServer(value);
                    }
                    
                    // CMS detection from headers
                    if (key.equalsIgnoreCase("X-Powered-By")) {
                        detectTechnologyFromHeader(info, value);
                    }
                }
            }
            
            // Read page content
            if (info.getStatusCode() == 200) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder content = new StringBuilder();
                String line;
                int totalSize = 0;
                
                while ((line = in.readLine()) != null && totalSize < MAX_PAGE_SIZE) {
                    content.append(line).append("\n");
                    totalSize += line.length();
                }
                in.close();
                
                String pageContent = content.toString();
                
                // Extract page title
                info.setPageTitle(extractPageTitle(pageContent));
                
                // Detect CMS
                info.setCms(detectCMS(pageContent, headers));
                
                // Detect technologies
                detectTechnologies(info, pageContent);
            }
            
            conn.disconnect();
            
        } catch (Exception e) {
            // Silently fail
        }
        
        return info;
    }
    
    /**
     * Extract SSL certificate information
     */
    private static SSLCertInfo extractCertInfo(X509Certificate cert) {
        SSLCertInfo info = new SSLCertInfo();
        
        try {
            // Common Name
            String dn = cert.getSubjectX500Principal().getName();
            Pattern cnPattern = Pattern.compile("CN=([^,]+)");
            Matcher matcher = cnPattern.matcher(dn);
            if (matcher.find()) {
                info.setCommonName(matcher.group(1));
            }
            
            // Issuer
            String issuerDN = cert.getIssuerX500Principal().getName();
            matcher = cnPattern.matcher(issuerDN);
            if (matcher.find()) {
                info.setIssuer(matcher.group(1));
            }
            
            // Check if self-signed
            info.setSelfSigned(cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal()));
            
            // Validity
            info.setValidFrom(cert.getNotBefore());
            info.setValidTo(cert.getNotAfter());
            
            // Check expiry
            Date now = new Date();
            info.setExpired(now.after(cert.getNotAfter()));
            
            long diff = cert.getNotAfter().getTime() - now.getTime();
            info.setDaysUntilExpiry((int) (diff / (1000 * 60 * 60 * 24)));
            
        } catch (Exception e) {
            // Ignore errors
        }
        
        return info;
    }
    
    /**
     * Extract page title from HTML
     */
    private static String extractPageTitle(String html) {
        Pattern pattern = Pattern.compile("<title>([^<]+)</title>", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(html);
        
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        
        return null;
    }
    
    /**
     * Detect CMS from page content and headers
     */
    private static String detectCMS(String content, Map<String, List<String>> headers) {
        String lowerContent = content.toLowerCase();
        
        // WordPress
        if (lowerContent.contains("wp-content") || lowerContent.contains("wp-includes") || 
            lowerContent.contains("wordpress")) {
            return "WordPress";
        }
        
        // Joomla
        if (lowerContent.contains("joomla") || lowerContent.contains("/components/com_")) {
            return "Joomla";
        }
        
        // Drupal
        if (lowerContent.contains("drupal") || lowerContent.contains("/sites/default/")) {
            return "Drupal";
        }
        
        // Bitrix
        if (lowerContent.contains("bitrix") || lowerContent.contains("/bitrix/")) {
            return "1C-Bitrix";
        }
        
        // ModX
        if (lowerContent.contains("modx") || lowerContent.contains("/assets/components/")) {
            return "ModX";
        }
        
        // OpenCart
        if (lowerContent.contains("opencart")) {
            return "OpenCart";
        }
        
        // PrestaShop
        if (lowerContent.contains("prestashop")) {
            return "PrestaShop";
        }
        
        // Magento
        if (lowerContent.contains("magento") || lowerContent.contains("mage/")) {
            return "Magento";
        }
        
        // Shopify
        if (lowerContent.contains("shopify") || lowerContent.contains("cdn.shopify.com")) {
            return "Shopify";
        }
        
        // Wix
        if (lowerContent.contains("wix.com") || lowerContent.contains("wixstatic.com")) {
            return "Wix";
        }
        
        // Squarespace
        if (lowerContent.contains("squarespace")) {
            return "Squarespace";
        }
        
        // Weebly
        if (lowerContent.contains("weebly")) {
            return "Weebly";
        }
        
        return null;
    }
    
    /**
     * Detect technologies from page content
     */
    private static void detectTechnologies(HTTPInfo info, String content) {
        String lowerContent = content.toLowerCase();
        
        // JavaScript frameworks
        if (lowerContent.contains("react")) info.getTechnologies().add("React");
        if (lowerContent.contains("vue") || lowerContent.contains("vuejs")) info.getTechnologies().add("Vue.js");
        if (lowerContent.contains("angular")) info.getTechnologies().add("Angular");
        if (lowerContent.contains("jquery")) info.getTechnologies().add("jQuery");
        if (lowerContent.contains("bootstrap")) info.getTechnologies().add("Bootstrap");
        
        // Backend frameworks
        if (lowerContent.contains("laravel")) info.getTechnologies().add("Laravel");
        if (lowerContent.contains("symfony")) info.getTechnologies().add("Symfony");
        if (lowerContent.contains("django")) info.getTechnologies().add("Django");
        if (lowerContent.contains("flask")) info.getTechnologies().add("Flask");
        if (lowerContent.contains("express")) info.getTechnologies().add("Express.js");
        if (lowerContent.contains("asp.net") || lowerContent.contains("aspnet")) info.getTechnologies().add("ASP.NET");
        
        // Analytics
        if (lowerContent.contains("google-analytics") || lowerContent.contains("gtag")) info.getTechnologies().add("Google Analytics");
        if (lowerContent.contains("yandex.metrika") || lowerContent.contains("metrika/tag.js")) info.getTechnologies().add("Yandex.Metrika");
        
        // CDN
        if (lowerContent.contains("cloudflare")) info.getTechnologies().add("Cloudflare");
        if (lowerContent.contains("akamai")) info.getTechnologies().add("Akamai");
    }
    
    /**
     * Detect technology from X-Powered-By header
     */
    private static void detectTechnologyFromHeader(HTTPInfo info, String value) {
        String lower = value.toLowerCase();
        
        if (lower.contains("php")) info.getTechnologies().add("PHP");
        if (lower.contains("asp.net")) info.getTechnologies().add("ASP.NET");
        if (lower.contains("express")) info.getTechnologies().add("Express.js");
        if (lower.contains("nginx")) info.getTechnologies().add("Nginx");
        if (lower.contains("apache")) info.getTechnologies().add("Apache");
    }
}
