package it.r2u.anibus.service.network;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * SSL/TLS deep audit.
 * Performs a real TLS handshake to inspect:
 *  - Protocol version (TLSv1, TLSv1.1, TLSv1.2, TLSv1.3)
 *  - Negotiated cipher suite (flags weak/obsolete ones)
 *  - Full certificate chain (expiry, issuer, self-signed, SANs)
 *  - Supported protocols by probing with restricted SSLContext
 */
public class SslTlsAuditor {

    private static final int TIMEOUT_MS = 8000;
    private static final int DEFAULT_PORT = 443;
    private static final DateTimeFormatter DATE_FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneId.systemDefault());

    /** Cipher suites considered weak or obsolete. */
    private static final List<String> WEAK_CIPHERS = List.of(
        "NULL", "EXPORT", "RC4", "DES", "3DES", "MD5", "anon",
        "ADH", "AECDH", "PSK_WITH_RC4", "_RC4_", "_DES_"
    );

    /** Protocol versions considered insecure. */
    private static final List<String> INSECURE_PROTOCOLS = List.of("SSLv2", "SSLv3", "TLSv1", "TLSv1.1");

    public enum CertRisk { CRITICAL, HIGH, MEDIUM, LOW, OK }

    public record CertInfo(
        String subject,
        String issuer,
        Date   notBefore,
        Date   notAfter,
        boolean selfSigned,
        boolean expired,
        boolean expiresSoon,   // within 30 days
        int     daysUntilExpiry,
        List<String> subjectAltNames,
        CertRisk risk,
        String finding
    ) {}

    public record AuditResult(
        String host,
        int    port,
        boolean connected,
        String negotiatedProtocol,
        String negotiatedCipher,
        boolean weakCipher,
        boolean insecureProtocol,
        List<String> supportedProtocols,
        @SuppressWarnings("MismatchedQueryAndUpdateOfCollection") List<CertInfo> chain,
        List<String> findings,
        // Extended fields
        boolean hstsPresent,
        String  hstsHeader,
        String  alpnProtocol,
        boolean chainTrusted,
        String  ocspUrl
    ) {
        public String overallRisk() {
            if (!connected) return "UNKNOWN";
            if (chain.stream().anyMatch(c -> c.risk() == CertRisk.CRITICAL)) return "CRITICAL";
            if (chain.stream().anyMatch(c -> c.risk() == CertRisk.HIGH)) return "HIGH";
            if (insecureProtocol || weakCipher) return "HIGH";
            if (!chainTrusted) return "HIGH";
            if (!hstsPresent) return "MEDIUM";
            if (chain.stream().anyMatch(c -> c.risk() == CertRisk.MEDIUM)) return "MEDIUM";
            return "OK";
        }
    }

    /**
     * Performs a full TLS audit of the given host.
     *
     * @param host hostname or IP
     * @param port TLS port (use 0 for default 443)
     * @return AuditResult with all findings
     */
    public AuditResult audit(String host, int port) {
        if (host == null || host.isBlank()) {
            return errorResult(host, port, "Empty host");
        }
        int effectivePort = (port <= 0) ? DEFAULT_PORT : port;
        return doAudit(host.trim(), effectivePort);
    }

    private AuditResult doAudit(String host, int port) {
        try {
            List<String> findings = new ArrayList<>();
            List<CertInfo> chain = new ArrayList<>();
            List<String> supportedProtos = new ArrayList<>();

            // Primary handshake — captures negotiated cipher + protocol + cert chain
            SSLContext ctx = buildTrustAllContext();
            SSLSocketFactory factory = ctx.getSocketFactory();

            String negotiatedProto;
            String negotiatedCipher;
            boolean weakCipher;
            boolean insecureProto;
            String  alpnProtocol;    // assigned in all branches of inner try/catch
            X509Certificate[] certs;

            try (SSLSocket ssl = (SSLSocket) factory.createSocket()) {
                ssl.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
                ssl.setSoTimeout(TIMEOUT_MS);
                ssl.startHandshake();

                SSLSession session = ssl.getSession();
                negotiatedProto  = session.getProtocol();
                negotiatedCipher = session.getCipherSuite();

                // ALPN: Java 9+ SSLSocket.getApplicationProtocol()
                try {
                    String ap = ssl.getApplicationProtocol();
                    alpnProtocol = (ap != null) ? ap : "";
                } catch (UnsupportedOperationException ignored) {
                    alpnProtocol = "";
                }

                final String finalCipher = negotiatedCipher;
                weakCipher    = WEAK_CIPHERS.stream()
                    .anyMatch(w -> finalCipher.toUpperCase().contains(w.toUpperCase()));
                insecureProto = INSECURE_PROTOCOLS.contains(negotiatedProto);

                certs = (X509Certificate[]) session.getPeerCertificates();
            }

            // Analyse certificate chain
            String ocspUrl = "";
            for (X509Certificate cert : certs) {
                CertInfo ci = analyseCert(cert);
                chain.add(ci);
                if (ocspUrl.isEmpty()) ocspUrl = extractOcspUrl(cert);
            }

            // Probe which protocol versions the server accepts
            for (String proto : new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}) {
                if (probeProtocol(host, port, proto)) supportedProtos.add(proto);
            }

            // HSTS check via plain HTTP GET
            boolean hstsPresent = false;
            String  hstsHeader  = "";
            try {
                HttpURLConnection http = (HttpURLConnection)
                    URI.create("https://" + host + ":" + port + "/").toURL().openConnection();
                http.setConnectTimeout(TIMEOUT_MS);
                http.setReadTimeout(TIMEOUT_MS);
                http.setInstanceFollowRedirects(false);
                http.setRequestProperty("User-Agent", "Anibus-SSLAudit/1.0");
                http.connect();
                String hsts = http.getHeaderField("Strict-Transport-Security");
                if (hsts != null && !hsts.isBlank()) {
                    hstsPresent = true;
                    hstsHeader  = hsts;
                }
                http.disconnect();
            } catch (IOException | IllegalArgumentException ignored) { }

            // Chain trust: attempt with system default TrustManager
            boolean chainTrusted = probeChainTrust(host, port);

            // Build findings list
            if (insecureProto)
                findings.add("[HIGH] Negotiated insecure protocol: " + negotiatedProto);
            if (weakCipher)
                findings.add("[HIGH] Weak cipher suite negotiated: " + negotiatedCipher);
            for (String p : supportedProtos) {
                if (INSECURE_PROTOCOLS.contains(p))
                    findings.add("[MEDIUM] Server accepts deprecated protocol: " + p);
            }
            if (!hstsPresent)
                findings.add("[MEDIUM] HSTS header missing (Strict-Transport-Security)");
            if (!chainTrusted)
                findings.add("[HIGH] Certificate chain NOT trusted by default JVM trust store");
            if (!ocspUrl.isEmpty())
                findings.add("[INFO] OCSP Responder URL: " + ocspUrl);
            chain.forEach(c -> { if (!c.finding().isEmpty()) findings.add(c.finding()); });

            return new AuditResult(host, port, true,
                negotiatedProto, negotiatedCipher, weakCipher, insecureProto,
                List.copyOf(supportedProtos), List.copyOf(chain), List.copyOf(findings),
                hstsPresent, hstsHeader, alpnProtocol, chainTrusted, ocspUrl);

        } catch (IOException | GeneralSecurityException e) {
            return errorResult(host, port, "Connection failed: " + e.getMessage());
        }
    }

    private CertInfo analyseCert(X509Certificate cert) {
        String subject = cert.getSubjectX500Principal().getName();
        String issuer  = cert.getIssuerX500Principal().getName();
        boolean selfSigned = subject.equals(issuer);

        Date notAfter  = cert.getNotAfter();
        Date notBefore = cert.getNotBefore();
        long now = System.currentTimeMillis();
        long msUntilExpiry = notAfter.getTime() - now;
        int daysUntilExpiry = (int) (msUntilExpiry / 86_400_000L);
        boolean expired     = daysUntilExpiry < 0;
        boolean expiresSoon = !expired && daysUntilExpiry <= 30;

        List<String> sans = new ArrayList<>();
        try {
            var sanCollection = cert.getSubjectAlternativeNames();
            if (sanCollection != null) {
                for (var san : sanCollection) {
                    if (san.size() >= 2) sans.add(san.get(1).toString());
                }
            }
        } catch (GeneralSecurityException ignored) { }

        CertRisk risk;
        String finding;
        if (expired) {
            risk    = CertRisk.CRITICAL;
            finding = "[CRITICAL] Certificate EXPIRED on " + DATE_FMT.format(notAfter.toInstant());
        } else if (selfSigned) {
            risk    = CertRisk.HIGH;
            finding = "[HIGH] Self-signed certificate (no trusted CA)";
        } else if (expiresSoon) {
            risk    = CertRisk.MEDIUM;
            finding = "[MEDIUM] Certificate expires in " + daysUntilExpiry + " day(s)";
        } else {
            risk    = CertRisk.OK;
            finding = "";
        }

        return new CertInfo(subject, issuer, notBefore, notAfter,
            selfSigned, expired, expiresSoon, daysUntilExpiry, sans, risk, finding);
    }

    private boolean probeProtocol(String host, int port, String proto) {
        try {
            SSLContext ctx = buildTrustAllContext();
            SSLSocketFactory factory = ctx.getSocketFactory();
            try (SSLSocket ssl = (SSLSocket) factory.createSocket()) {
                ssl.setEnabledProtocols(new String[]{proto});
                ssl.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
                ssl.setSoTimeout(TIMEOUT_MS);
                ssl.startHandshake();
                return true;
            }
        } catch (IOException | GeneralSecurityException ignored) {
            return false;
        }
    }

    private SSLContext buildTrustAllContext() throws GeneralSecurityException {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                @Override public void checkClientTrusted(X509Certificate[] c, String a) { }
                @Override public void checkServerTrusted(X509Certificate[] c, String a) { }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new java.security.SecureRandom());
        return ctx;
    }

    private boolean probeChainTrust(String host, int port) {
        try (SSLSocket ssl = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            ssl.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            ssl.setSoTimeout(TIMEOUT_MS);
            ssl.startHandshake();
            return true;
        } catch (IOException ignored) {
            return false;
        }
    }

    /** Extracts the OCSP Responder URL from the certificate's AIA extension (OID 1.3.6.1.5.5.7.48.1). */
    private String extractOcspUrl(X509Certificate cert) {
        try {
            byte[] aia = cert.getExtensionValue("1.3.6.1.5.5.7.1.1"); // id-pe-authorityInfoAccess
            if (aia == null) return "";
            // Simple heuristic: look for "http" in the extension bytes
            String raw = new String(aia, java.nio.charset.StandardCharsets.ISO_8859_1);
            int idx = raw.indexOf("http");
            if (idx < 0) return "";
            int end = raw.indexOf('\0', idx);
            return end < 0 ? raw.substring(idx) : raw.substring(idx, end);
        } catch (Exception ignored) {
            return "";
        }
    }

    private AuditResult errorResult(String host, int port, String msg) {
        return new AuditResult(host, port <= 0 ? DEFAULT_PORT : port, false,
            "N/A", "N/A", false, false, List.of(), List.of(),
            List.of("[ERROR] " + msg),
            false, "", "", false, "");
    }

    public static String formatReport(AuditResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== SSL/TLS AUDIT: ").append(r.host()).append(":").append(r.port())
          .append("  [").append(r.overallRisk()).append("] ===\n\n");

        if (!r.connected()) {
            sb.append("  Connection failed\n");
            r.findings().forEach(f -> sb.append("  ").append(f).append("\n"));
            return sb.toString();
        }

        sb.append("  Protocol : ").append(r.negotiatedProtocol())
          .append(r.insecureProtocol() ? "  ⚠ INSECURE" : "  ✓").append("\n");
        sb.append("  Cipher   : ").append(r.negotiatedCipher())
          .append(r.weakCipher() ? "  ⚠ WEAK" : "  ✓").append("\n");

        if (!r.alpnProtocol().isBlank()) {
            sb.append("  ALPN     : ").append(r.alpnProtocol()).append("\n");
        }
        sb.append("  HSTS     : ").append(r.hstsPresent()
            ? "✓ present  (" + r.hstsHeader() + ")"
            : "✗ missing").append("\n");
        sb.append("  Chain    : ").append(r.chainTrusted()
            ? "✓ trusted by JVM trust store"
            : "✗ NOT trusted (self-signed or unknown CA)").append("\n");
        if (!r.ocspUrl().isBlank()) {
            sb.append("  OCSP URL : ").append(r.ocspUrl()).append("\n");
        }

        if (!r.supportedProtocols().isEmpty()) {
            sb.append("  Accepts  : ").append(String.join(", ", r.supportedProtocols())).append("\n");
        }

        if (!r.chain().isEmpty()) {
            sb.append("\n  Certificate chain (").append(r.chain().size()).append(" cert(s)):\n");
            int idx = 0;
            for (CertInfo c : r.chain()) {
                sb.append("  [").append(idx++).append("] ").append(c.subject()).append("\n");
                sb.append("      Issuer : ").append(c.issuer()).append("\n");
                sb.append("      Valid  : ")
                  .append(DATE_FMT.format(c.notBefore().toInstant()))
                  .append(" → ")
                  .append(DATE_FMT.format(c.notAfter().toInstant()));
                if (c.expired())     sb.append("  !! EXPIRED");
                else if (c.expiresSoon()) sb.append("  (expires soon)");
                sb.append("\n");
                if (c.selfSigned()) sb.append("      [SELF-SIGNED]\n");
                if (!c.subjectAltNames().isEmpty()) {
                    sb.append("      SANs   : ").append(String.join(", ", c.subjectAltNames())).append("\n");
                }
            }
        }

        if (!r.findings().isEmpty()) {
            sb.append("\n  Findings:\n");
            r.findings().forEach(f -> sb.append("  ").append(f).append("\n"));
        } else {
            sb.append("\n  No security issues found.\n");
        }
        return sb.toString();
    }
}
