package it.r2u.anibus;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PortScannerService {

    private final int TIMEOUT = 200;

    private final String[] ENCRYPTION_KEYWORDS = {
            "starttls", "tls", "ssl", "https", "smtps", "imaps", "pop3s",
            "aes", "rsa", "sha", "gcm", "ecdhe", "dhe"
    };

    /* ── Parse port range ────────────────────────────── */
    public int[] parsePortsRange(String portsRange) {
        Pattern pattern = Pattern.compile("(\\d+)-(\\d+)");
        Matcher matcher = pattern.matcher(portsRange);
        if (matcher.find()) {
            try {
                int startPort = Integer.parseInt(matcher.group(1));
                int endPort   = Integer.parseInt(matcher.group(2));
                return new int[]{startPort, endPort};
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /* ── Port open check (returns latency in ms, -1 = closed) ── */
    public long measurePortLatency(String host, int port) {
        try (Socket socket = new Socket()) {
            long start = System.nanoTime();
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);
            long elapsed = (System.nanoTime() - start) / 1_000_000;
            return elapsed;
        } catch (IOException e) {
            return -1;
        }
    }

    public boolean isPortOpen(String host, int port) {
        return measurePortLatency(host, port) >= 0;
    }

    /* ── Banner grabbing (improved: sends probe for HTTP) ── */
    public String getBanner(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(TIMEOUT);
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);

            // For HTTP ports, send a HEAD request to get useful headers
            if (isHttpPort(port)) {
                return grabHttpHeaders(socket, host);
            }

            // For SMTP/FTP/POP3/IMAP — just read the greeting
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[2048];
            int read = in.read(buffer, 0, buffer.length);
            if (read > 0) {
                return sanitize(new String(buffer, 0, read, StandardCharsets.UTF_8));
            }
        } catch (IOException ignored) {
        }
        return "";
    }

    /* ── HTTP header grab ────────────────────────────── */
    private String grabHttpHeaders(Socket socket, String host) throws IOException {
        OutputStream out = socket.getOutputStream();
        String request = "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.UTF_8));
        out.flush();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        int lineCount = 0;
        while ((line = reader.readLine()) != null && lineCount < 20) {
            sb.append(line).append("  ");
            lineCount++;
        }
        return sanitize(sb.toString());
    }

    private boolean isHttpPort(int port) {
        return port == 80 || port == 443 || port == 8080 || port == 8443
                || port == 8000 || port == 8888 || port == 3000 || port == 9090;
    }

    /* ── Version extraction from banner ──────────────── */
    public String extractVersion(String banner) {
        if (banner == null || banner.isEmpty()) return "";

        // SSH: SSH-2.0-OpenSSH_8.4p1
        Matcher m = Pattern.compile("SSH-[\\d.]+-([\\w._-]+)").matcher(banner);
        if (m.find()) return m.group(1);

        // Apache: Apache/2.4.52
        m = Pattern.compile("(?i)(Apache|nginx|lighttpd|IIS)[/ ]?([\\d.]+)").matcher(banner);
        if (m.find()) return m.group(1) + "/" + m.group(2);

        // ProFTPD: ProFTPD 1.3.6  or  220 (vsFTPd 3.0.5)
        m = Pattern.compile("(?i)(ProFTPD|vsFTPd|Pure-FTPd|FileZilla)[/ ]?([\\d.]+)").matcher(banner);
        if (m.find()) return m.group(1) + " " + m.group(2);

        // Postfix: Postfix
        m = Pattern.compile("(?i)(Postfix|Exim|Sendmail|Dovecot)[/ ]?([\\d.]*)").matcher(banner);
        if (m.find()) {
            String ver = m.group(2);
            return m.group(1) + (ver.isEmpty() ? "" : " " + ver);
        }

        // Generic: Server: xxx or X-Powered-By: xxx
        m = Pattern.compile("(?i)(?:Server|X-Powered-By):\\s*(.+?)(?:\\s{2}|$)").matcher(banner);
        if (m.find()) return m.group(1).trim();

        return "";
    }

    /* ── Expanded service map ────────────────────────── */
    public String getServiceName(int port) {
        switch (port) {
            case 20:   return "FTP-DATA";
            case 21:   return "FTP";
            case 22:   return "SSH";
            case 23:   return "Telnet";
            case 25:   return "SMTP";
            case 53:   return "DNS";
            case 67:   return "DHCP Server";
            case 68:   return "DHCP Client";
            case 69:   return "TFTP";
            case 80:   return "HTTP";
            case 110:  return "POP3";
            case 111:  return "RPCBind";
            case 119:  return "NNTP";
            case 123:  return "NTP";
            case 135:  return "MSRPC";
            case 137:  return "NetBIOS-NS";
            case 138:  return "NetBIOS-DGM";
            case 139:  return "NetBIOS-SSN";
            case 143:  return "IMAP";
            case 161:  return "SNMP";
            case 162:  return "SNMP Trap";
            case 389:  return "LDAP";
            case 443:  return "HTTPS";
            case 445:  return "SMB";
            case 465:  return "SMTPS";
            case 514:  return "Syslog";
            case 515:  return "LPD/LPR";
            case 587:  return "SMTP Submission";
            case 636:  return "LDAPS";
            case 993:  return "IMAPS";
            case 995:  return "POP3S";
            case 1080: return "SOCKS";
            case 1433: return "MS SQL";
            case 1434: return "MS SQL Browser";
            case 1521: return "Oracle DB";
            case 1723: return "PPTP";
            case 2049: return "NFS";
            case 2082: return "cPanel";
            case 2083: return "cPanel SSL";
            case 2181: return "ZooKeeper";
            case 3000: return "Dev Server";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 5672: return "AMQP";
            case 5900: return "VNC";
            case 6379: return "Redis";
            case 6443: return "Kubernetes API";
            case 8000: return "HTTP Alt";
            case 8080: return "HTTP Proxy";
            case 8443: return "HTTPS Alt";
            case 8888: return "HTTP Alt";
            case 9090: return "Prometheus";
            case 9200: return "Elasticsearch";
            case 9300: return "ES Transport";
            case 11211: return "Memcached";
            case 27017: return "MongoDB";
            default:   return "Port " + port;
        }
    }

    /* ── Protocol & encryption detection ─────────────── */
    public String getProtocolAndEncryption(int port, String banner) {
        String lower = banner.toLowerCase();

        switch (port) {
            case 22:   return "TCP (SSH)";
            case 443:  return "TCP (HTTPS/TLS)";
            case 465:  return "TCP (SMTPS/TLS)";
            case 636:  return "TCP (LDAPS/TLS)";
            case 993:  return "TCP (IMAPS/TLS)";
            case 995:  return "TCP (POP3S/TLS)";
            case 2083: return "TCP (cPanel/TLS)";
            case 3389: return "TCP (RDP/TLS)";
            case 8443: return "TCP (HTTPS/TLS)";
        }

        for (String kw : ENCRYPTION_KEYWORDS) {
            if (lower.contains(kw)) {
                if (kw.equals("starttls")) return "TCP (STARTTLS)";
                return "TCP (Encrypted: " + kw.toUpperCase() + ")";
            }
        }

        switch (port) {
            case 21:  return "TCP (FTP)";
            case 23:  return "TCP (Telnet)";
            case 25:  return "TCP (SMTP)";
            case 53:  return "TCP (DNS)";
            case 80:  return "TCP (HTTP)";
            case 110: return "TCP (POP3)";
            case 143: return "TCP (IMAP)";
            case 389: return "TCP (LDAP)";
            case 445: return "TCP (SMB)";
            default:  return "TCP";
        }
    }

    /* ── Helper ──────────────────────────────────────── */
    private String sanitize(String s) {
        if (s == null) return "";
        // Remove control chars and excessive whitespace, keep printable
        return s.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]", "").trim();
    }
}