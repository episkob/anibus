package it.r2u.anibus;

/**
 * Static lookup tables for port → service name and protocol/encryption info.
 */
public class PortRegistry {

    private static final String[] ENCRYPTION_KEYWORDS = {
        "starttls", "tls", "ssl", "https", "smtps", "imaps", "pop3s",
        "aes", "rsa", "sha", "gcm", "ecdhe", "dhe"
    };

    public static String getServiceName(int port) {
        switch (port) {
            case 20:    return "FTP-DATA";
            case 21:    return "FTP";
            case 22:    return "SSH";
            case 23:    return "Telnet";
            case 25:    return "SMTP";
            case 53:    return "DNS";
            case 67:    return "DHCP Server";
            case 68:    return "DHCP Client";
            case 69:    return "TFTP";
            case 80:    return "HTTP";
            case 110:   return "POP3";
            case 111:   return "RPCBind";
            case 119:   return "NNTP";
            case 123:   return "NTP";
            case 135:   return "MSRPC";
            case 137:   return "NetBIOS-NS";
            case 138:   return "NetBIOS-DGM";
            case 139:   return "NetBIOS-SSN";
            case 143:   return "IMAP";
            case 161:   return "SNMP";
            case 162:   return "SNMP Trap";
            case 389:   return "LDAP";
            case 443:   return "HTTPS";
            case 445:   return "SMB";
            case 465:   return "SMTPS";
            case 514:   return "Syslog";
            case 515:   return "LPD/LPR";
            case 587:   return "SMTP Submission";
            case 636:   return "LDAPS";
            case 993:   return "IMAPS";
            case 995:   return "POP3S";
            case 1080:  return "SOCKS";
            case 1433:  return "MS SQL";
            case 1434:  return "MS SQL Browser";
            case 1521:  return "Oracle DB";
            case 1723:  return "PPTP";
            case 2049:  return "NFS";
            case 2082:  return "cPanel";
            case 2083:  return "cPanel SSL";
            case 2181:  return "ZooKeeper";
            case 3000:  return "Dev Server";
            case 3306:  return "MySQL";
            case 3389:  return "RDP";
            case 5432:  return "PostgreSQL";
            case 5672:  return "AMQP";
            case 5900:  return "VNC";
            case 6379:  return "Redis";
            case 6443:  return "Kubernetes API";
            case 8000:  return "HTTP Alt";
            case 8080:  return "HTTP Proxy";
            case 8443:  return "HTTPS Alt";
            case 8888:  return "HTTP Alt";
            case 9090:  return "Prometheus";
            case 9200:  return "Elasticsearch";
            case 9300:  return "ES Transport";
            case 11211: return "Memcached";
            case 27017: return "MongoDB";
            default:    return "Port " + port;
        }
    }

    public static String getProtocol(int port, String banner) {
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

        String lower = (banner == null) ? "" : banner.toLowerCase();
        for (String kw : ENCRYPTION_KEYWORDS) {
            if (lower.contains(kw)) {
                return kw.equals("starttls") ? "TCP (STARTTLS)" : "TCP (Encrypted: " + kw.toUpperCase() + ")";
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
}
