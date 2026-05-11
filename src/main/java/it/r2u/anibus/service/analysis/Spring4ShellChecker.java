package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Spring4Shell Checker — CVE-2022-22965
 *
 * Sends Spring Framework RCE-specific probes (class.module.classLoader binding,
 * tomcatlog-based probes) to common Spring MVC paths and detects:
 * - 400 responses with Spring-specific error bodies (unexpected binding)
 * - Presence of Spring error attributes in JSON/HTML error pages
 *
 * NOTE: Actual exploitation writes a JSP shell. This checker only performs
 * safe, non-destructive probes to detect the vulnerable binding mechanism.
 */
public class Spring4ShellChecker {

    public record Spring4ShellFinding(
        String url,
        String probe,
        int responseCode,
        String indicator,
        String note
    ) {}

    // Safe probes: attempt to bind class.module.classLoader — Spring will error specifically
    private static final String[] PROBE_PARAMS = {
        "class.module.classLoader.DefaultAssertionStatus=true",
        "class.module.classLoader.resources.dirContext.docBase=/tmp",
        "class.module.classLoader.URLs[0]=jar:file:///tmp/a.jar!/",
        "class.classLoader.DefaultAssertionStatus=true"
    };

    // Common Spring MVC endpoint paths
    private static final String[] PATHS = {
        "/", "/login", "/index", "/home", "/api", "/app",
        "/actuator/health", "/api/v1/", "/rest/"
    };

    // Response body indicators of Spring binding error (not a generic 400)
    private static final String[] SPRING_INDICATORS = {
        "Spring Framework",
        "org.springframework",
        "BindException",
        "PropertyAccessException",
        "ClassLoader",
        "DefaultAssertionStatus",
        "whitelabel error",
        "Whitelabel Error Page"
    };

    private final int timeoutMs;

    public Spring4ShellChecker(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    public Spring4ShellChecker() {
        this(6000);
    }

    public List<Spring4ShellFinding> scan(String baseUrl) {
        List<Spring4ShellFinding> findings = new ArrayList<>();
        // Baseline: get normal response to distinguish Spring-specific errors
        int baseline = getCode(baseUrl);
        if (baseline < 0) return findings;

        outer:
        for (String path : PATHS) {
            String url = baseUrl.replaceAll("/+$", "") + path;
            for (String param : PROBE_PARAMS) {
                Spring4ShellFinding f = probe(url, param, baseline);
                if (f != null) {
                    findings.add(f);
                    break outer;
                }
            }
        }
        return findings;
    }

    private Spring4ShellFinding probe(String url, String param, int baseline) {
        try {
            String fullUrl = url.contains("?") ? url + "&" + param : url + "?" + param;
            HttpURLConnection conn = (HttpURLConnection)
                URI.create(fullUrl).toURL().openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            conn.setInstanceFollowRedirects(false);

            int code = conn.getResponseCode();
            String body = readBody(conn, code);

            // Spring4Shell triggers a 400 with specific Spring error body
            if (code == 400 && baseline != 400) {
                for (String ind : SPRING_INDICATORS) {
                    if (body.toLowerCase().contains(ind.toLowerCase())) {
                        return new Spring4ShellFinding(url, param, code, ind,
                            "Spring classLoader binding probed — 400 with Spring error body, "
                            + "may be vulnerable to CVE-2022-22965");
                    }
                }
            }
            // 500 with Spring stack trace is also suspicious
            if (code == 500 && baseline < 500) {
                for (String ind : SPRING_INDICATORS) {
                    if (body.toLowerCase().contains(ind.toLowerCase())) {
                        return new Spring4ShellFinding(url, param, code, ind,
                            "Spring 500 error after classLoader probe (baseline was "
                            + baseline + ")");
                    }
                }
            }
        } catch (IOException | IllegalArgumentException ignored) {
        }
        return null;
    }

    private int getCode(String url) {
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

    public static String formatReport(List<Spring4ShellFinding> findings, String target) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("   SPRING4SHELL CHECK (CVE-2022-22965) — ").append(target).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (findings.isEmpty()) {
            sb.append("  ✓ No Spring4Shell indicators detected.\n");
            sb.append("  Note: Requires Spring MVC on Tomcat with JDK 9+ for exploitation.\n");
        } else {
            sb.append(String.format(
                "  ⚠ POSSIBLE Spring4Shell — %d indicator(s):\n\n", findings.size()));
            for (Spring4ShellFinding f : findings) {
                sb.append(String.format("  URL       : %s\n", f.url()));
                sb.append(String.format("  Probe     : %s\n", f.probe()));
                sb.append(String.format("  HTTP      : %d\n", f.responseCode()));
                sb.append(String.format("  Indicator : %s\n", f.indicator()));
                sb.append(String.format("  Note      : %s\n\n", f.note()));
            }
            sb.append("  CVE  : CVE-2022-22965\n");
            sb.append("  PoC  : https://www.exploit-db.com/search?cve=CVE-2022-22965\n");
        }
        return sb.toString();
    }
}
