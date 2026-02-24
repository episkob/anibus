package it.r2u.anibus.service;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.model.PortRegistry;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Enhanced service detection with multiple probes and protocol analysis.
 * Performs deep inspection of services for accurate identification.
 */
public class EnhancedServiceDetector {

    private static final int TIMEOUT = 500;  // Longer timeout for service detection

    public PortScanResult detectService(String host, int port) {
        try (Socket socket = new Socket()) {
            long start = System.nanoTime();
            socket.setSoTimeout(TIMEOUT);
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);
            long latency = (System.nanoTime() - start) / 1_000_000;

            // Grab banner
            String banner = grabEnhancedBanner(socket, host, port);
            
            // Get service info from registry
            String serviceName = PortRegistry.getServiceName(port);
            String protocol = detectProtocol(port, banner);
            String version = extractVersion(banner);
            
            // Enhanced service detection
            if (banner != null && !banner.isEmpty()) {
                serviceName = enhanceServiceName(serviceName, banner, port);
                protocol = enhanceProtocol(protocol, banner);
                
                // Detect security services (Cloudflare, WAF, CDN)
                String securityLayer = detectSecurityService(banner);
                if (securityLayer != null) {
                    serviceName = serviceName + " [" + securityLayer + "]";
                }
            }

            return new PortScanResult(port, serviceName, banner, protocol, latency, version, "Open", "Service Detection");
        } catch (IOException e) {
            return null;  // Port closed or service not responding
        }
    }

    private String grabEnhancedBanner(Socket socket, String host, int port) {
        try {
            // Try protocol-specific probes
            if (isHttpPort(port)) {
                return grabHttpBanner(socket, host);
            } else if (isSshPort(port)) {
                return grabSshBanner(socket);
            } else if (isSmtpPort(port)) {
                return grabSmtpBanner(socket);
            } else if (isFtpPort(port)) {
                return grabFtpBanner(socket);
            } else if (isMysqlPort(port)) {
                return grabMysqlBanner(socket);
            } else {
                return grabGenericBanner(socket);
            }
        } catch (IOException e) {
            return "";
        }
    }

    private String grabHttpBanner(Socket socket, String host) throws IOException {
        OutputStream out = socket.getOutputStream();
        String request = "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Anibus/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.UTF_8));
        out.flush();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        int lineCount = 0;
        // Read more headers to capture security service indicators
        while ((line = reader.readLine()) != null && lineCount < 30) {
            sb.append(line).append("  ");
            lineCount++;
            if (line.isEmpty()) break;  // End of headers
        }
        return sanitize(sb.toString());
    }

    private String grabSshBanner(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String banner = reader.readLine();
        return banner != null ? sanitize(banner) : "";
    }

    private String grabSmtpBanner(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        int lineCount = 0;
        while ((line = reader.readLine()) != null && lineCount < 5) {
            sb.append(line).append("  ");
            lineCount++;
            if (!line.startsWith("220-")) break;
        }
        return sanitize(sb.toString());
    }

    private String grabFtpBanner(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        String banner = reader.readLine();
        return banner != null ? sanitize(banner) : "";
    }

    private String grabMysqlBanner(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] buffer = new byte[512];
        int read = in.read(buffer, 0, buffer.length);
        if (read > 0) {
            String data = new String(buffer, 0, read, StandardCharsets.UTF_8);
            return sanitize(data);
        }
        return "";
    }

    private String grabGenericBanner(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        byte[] buffer = new byte[1024];
        int read = in.read(buffer, 0, buffer.length);
        return read > 0 ? sanitize(new String(buffer, 0, read, StandardCharsets.UTF_8)) : "";
    }

    private String enhanceServiceName(String baseName, String banner, int port) {
        String lower = banner.toLowerCase();
        
        // Web servers
        if (lower.contains("nginx")) return "Nginx";
        if (lower.contains("apache")) return "Apache";
        if (lower.contains("microsoft-iis")) return "IIS";
        if (lower.contains("lighttpd")) return "Lighttpd";
        if (lower.contains("caddy")) return "Caddy";
        if (lower.contains("tomcat")) return "Apache Tomcat";
        
        // Databases
        if (lower.contains("mysql")) return "MySQL";
        if (lower.contains("postgresql")) return "PostgreSQL";
        if (lower.contains("mongodb")) return "MongoDB";
        if (lower.contains("redis")) return "Redis";
        if (lower.contains("cassandra")) return "Cassandra";
        if (lower.contains("elasticsearch")) return "Elasticsearch";
        
        // SSH
        if (lower.contains("openssh")) return "OpenSSH";
        
        // FTP
        if (lower.contains("filezilla")) return "FileZilla FTP";
        if (lower.contains("proftpd")) return "ProFTPD";
        if (lower.contains("vsftpd")) return "vsftpd";
        
        // Mail
        if (lower.contains("postfix")) return "Postfix SMTP";
        if (lower.contains("sendmail")) return "Sendmail";
        if (lower.contains("exim")) return "Exim";
        
        return baseName != null ? baseName : "Unknown";
    }
    
    /**
     * Detects security services, CDN, and WAF from HTTP headers and banners.
     * Returns a descriptive string if security layer detected, null otherwise.
     */
    private String detectSecurityService(String banner) {
        if (banner == null || banner.isEmpty()) return null;
        
        String lower = banner.toLowerCase();
        
        // Cloudflare detection
        if (lower.contains("cloudflare") || 
            lower.contains("cf-ray") || 
            lower.contains("__cflb") || 
            lower.contains("__cfduid") ||
            lower.contains("cf-cache-status")) {
            return "Cloudflare CDN/WAF";
        }
        
        // Akamai detection
        if (lower.contains("akamai") || 
            lower.contains("akamaighost")) {
            return "Akamai CDN";
        }
        
        // Imperva/Incapsula detection
        if (lower.contains("incapsula") || 
            lower.contains("imperva") ||
            lower.contains("visid_incap")) {
            return "Imperva/Incapsula WAF";
        }
        
        // Sucuri detection
        if (lower.contains("sucuri") || 
            lower.contains("x-sucuri-")) {
            return "Sucuri WAF";
        }
        
        // AWS WAF/CloudFront detection
        if (lower.contains("cloudfront") || 
            lower.contains("x-amz-cf-") ||
            lower.contains("x-amzn-")) {
            return "AWS CloudFront/WAF";
        }
        
        // Azure Front Door detection
        if (lower.contains("azure") && lower.contains("frontdoor")) {
            return "Azure Front Door";
        }
        
        // Fastly detection
        if (lower.contains("fastly")) {
            return "Fastly CDN";
        }
        
        // StackPath detection
        if (lower.contains("stackpath")) {
            return "StackPath CDN";
        }
        
        // KeyCDN detection
        if (lower.contains("keycdn")) {
            return "KeyCDN";
        }
        
        // BunnyCDN detection
        if (lower.contains("bunnycdn") || lower.contains("b-cdn")) {
            return "BunnyCDN";
        }
        
        // Varnish Cache detection
        if (lower.contains("varnish")) {
            return "Varnish Cache";
        }
        
        // ModSecurity detection
        if (lower.contains("mod_security") || lower.contains("modsecurity")) {
            return "ModSecurity WAF";
        }
        
        // F5 BIG-IP detection
        if (lower.contains("big-ip") || lower.contains("f5")) {
            return "F5 BIG-IP";
        }
        
        // Barracuda WAF detection
        if (lower.contains("barracuda")) {
            return "Barracuda WAF";
        }
        
        // Fortinet FortiWeb detection
        if (lower.contains("fortinet") || lower.contains("fortiweb")) {
            return "Fortinet FortiWeb WAF";
        }
        
        // Radware detection
        if (lower.contains("radware")) {
            return "Radware DefensePro";
        }
        
        // Wallarm detection
        if (lower.contains("wallarm")) {
            return "Wallarm WAF";
        }
        
        // Reblaze detection
        if (lower.contains("reblaze") || lower.contains("rbz")) {
            return "Reblaze WAF";
        }
        
        // Vercel detection
        if (lower.contains("vercel")) {
            return "Vercel Edge Network";
        }
        
        // Netlify detection
        if (lower.contains("netlify")) {
            return "Netlify CDN";
        }
        
        // Google Cloud CDN/Armor detection
        if (lower.contains("gws") || lower.contains("google")) {
            if (lower.contains("cloud") || lower.contains("cdn")) {
                return "Google Cloud CDN";
            }
        }
        
        // Arbor Networks detection
        if (lower.contains("arbor")) {
            return "Arbor DDoS Protection";
        }
        
        // Palo Alto detection
        if (lower.contains("palo alto") || lower.contains("pan-")) {
            return "Palo Alto Networks";
        }
        
        // Squid Proxy detection
        if (lower.contains("squid")) {
            return "Squid Proxy";
        }
        
        // Nginx Plus detection
        if (lower.contains("nginx") && lower.contains("plus")) {
            return "Nginx Plus";
        }
        
        // Cloudflare alternative check for server header
        if (lower.contains("server:") && lower.contains("cloudflare")) {
            return "Cloudflare";
        }
        
        return null;
    }

    private String enhanceProtocol(String baseProtocol, String banner) {
        String lower = banner.toLowerCase();
        
        if (lower.contains("http/2")) return "HTTP/2";
        if (lower.contains("http/1.1")) return "HTTP/1.1";
        if (lower.contains("http")) return "HTTP";
        if (lower.contains("ssh-2.0")) return "SSH 2.0";
        if (lower.contains("ssh-1.")) return "SSH 1.x";
        if (lower.contains("ftp")) return "FTP";
        if (lower.contains("smtp")) return "SMTP";
        if (lower.contains("pop3")) return "POP3";
        if (lower.contains("imap")) return "IMAP";
        
        return baseProtocol != null ? baseProtocol : "TCP";
    }

    private String detectProtocol(int port, String banner) {
        return PortRegistry.getProtocol(port, banner);
    }

    private String extractVersion(String banner) {
        return VersionExtractor.extract(banner);
    }

    private boolean isHttpPort(int port) {
        return port == 80 || port == 443 || port == 8080 || port == 8443
                || port == 8000 || port == 8888 || port == 3000 || port == 9090;
    }

    private boolean isSshPort(int port) {
        return port == 22;
    }

    private boolean isSmtpPort(int port) {
        return port == 25 || port == 587 || port == 465;
    }

    private boolean isFtpPort(int port) {
        return port == 21;
    }

    private boolean isMysqlPort(int port) {
        return port == 3306;
    }

    private String sanitize(String s) {
        if (s == null) return "";
        return s.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "")
                .replaceAll("\\s+", " ")
                .trim();
    }
}
