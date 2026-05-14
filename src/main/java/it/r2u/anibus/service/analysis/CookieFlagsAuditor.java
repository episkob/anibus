package it.r2u.anibus.service.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Cookie flags auditor.
 *
 * <p>Parses raw {@code Set-Cookie} response headers and reports cookies whose
 * security flags are missing or weak (no {@code Secure}, no {@code HttpOnly},
 * missing/weak {@code SameSite}, overly broad {@code Domain}/{@code Path}, etc.).</p>
 *
 * <p>Stateless — no network calls. Callers must supply the {@code Set-Cookie}
 * header values they have already collected.</p>
 */
public final class CookieFlagsAuditor {

    public enum Severity { INFO, LOW, MEDIUM, HIGH }

    /**
     * Audit finding for a single cookie.
     *
     * @param name        cookie name
     * @param secure      true if {@code Secure} flag was present
     * @param httpOnly    true if {@code HttpOnly} flag was present
     * @param sameSite    "Strict" / "Lax" / "None" / "(absent)"
     * @param domain      explicit Domain attribute or {@code null}
     * @param path        Path attribute or "/"
     * @param secureContext true if the cookie was observed on an HTTPS response
     * @param issues      list of human-readable issues (empty if cookie is healthy)
     * @param severity    worst severity among {@link #issues}
     */
    public record CookieFinding(
        String name,
        boolean secure,
        boolean httpOnly,
        String sameSite,
        String domain,
        String path,
        boolean secureContext,
        List<String> issues,
        Severity severity
    ) {}

    private CookieFlagsAuditor() { /* no instances */ }

    /**
     * Audits a batch of {@code Set-Cookie} header values.
     *
     * @param setCookieHeaders raw header values (e.g. {@code "JSESSIONID=abc; Path=/; HttpOnly"})
     * @param httpsContext     true if these cookies were received over HTTPS
     * @return one {@link CookieFinding} per cookie (order preserved)
     */
    public static List<CookieFinding> audit(List<String> setCookieHeaders, boolean httpsContext) {
        List<CookieFinding> out = new ArrayList<>();
        if (setCookieHeaders == null || setCookieHeaders.isEmpty()) return out;

        for (String header : setCookieHeaders) {
            if (header == null || header.isBlank()) continue;
            out.add(parseAndAudit(header.trim(), httpsContext));
        }
        return out;
    }

    private static CookieFinding parseAndAudit(String header, boolean httpsContext) {
        String[] parts = header.split(";");
        String nameValue = parts[0].trim();
        int eq = nameValue.indexOf('=');
        String name = eq > 0 ? nameValue.substring(0, eq).trim() : nameValue;

        boolean secure = false;
        boolean httpOnly = false;
        String sameSite = "(absent)";
        String domain = null;
        String path = "/";

        for (int i = 1; i < parts.length; i++) {
            String attr = parts[i].trim();
            String lower = attr.toLowerCase(Locale.ROOT);
            if (lower.equals("secure"))           secure = true;
            else if (lower.equals("httponly"))    httpOnly = true;
            else if (lower.startsWith("samesite=")) sameSite = attr.substring("samesite=".length()).trim();
            else if (lower.startsWith("domain="))   domain   = attr.substring("domain=".length()).trim();
            else if (lower.startsWith("path="))     path     = attr.substring("path=".length()).trim();
        }

        List<String> issues = new ArrayList<>();
        Severity worst = Severity.INFO;
        boolean authLike = isAuthCookieName(name);

        if (!secure && httpsContext) {
            issues.add("Missing Secure flag (cookie can leak over HTTP)");
            worst = max(worst, authLike ? Severity.HIGH : Severity.MEDIUM);
        }
        if (!httpOnly) {
            issues.add("Missing HttpOnly flag (JavaScript can read this cookie)");
            worst = max(worst, authLike ? Severity.HIGH : Severity.MEDIUM);
        }
        if ("(absent)".equals(sameSite)) {
            issues.add("Missing SameSite attribute (CSRF risk; browsers default to Lax)");
            worst = max(worst, authLike ? Severity.MEDIUM : Severity.LOW);
        } else if ("none".equalsIgnoreCase(sameSite) && !secure) {
            issues.add("SameSite=None requires Secure flag (browsers will reject this cookie)");
            worst = max(worst, Severity.HIGH);
        }
        if (domain != null && domain.startsWith(".") && domain.chars().filter(c -> c == '.').count() <= 1) {
            issues.add("Overly broad Domain '" + domain + "' (cookie shared with all subdomains)");
            worst = max(worst, Severity.LOW);
        }

        return new CookieFinding(name, secure, httpOnly, sameSite, domain, path,
                httpsContext, List.copyOf(issues), worst);
    }

    private static boolean isAuthCookieName(String name) {
        if (name == null) return false;
        String n = name.toLowerCase(Locale.ROOT);
        return n.contains("session")
            || n.contains("sess")
            || n.contains("auth")
            || n.contains("token")
            || n.contains("jwt")
            || n.contains("sid")
            || n.equals("phpsessid")
            || n.equals("jsessionid")
            || n.equals("connect.sid")
            || n.equals("asp.net_sessionid");
    }

    private static Severity max(Severity a, Severity b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    /** Formats a human-readable report. */
    public static String formatReport(List<CookieFinding> findings) {
        StringBuilder sb = new StringBuilder("=== COOKIE FLAGS AUDIT ===\n");
        if (findings == null || findings.isEmpty()) {
            sb.append("  No Set-Cookie headers observed.\n");
            return sb.toString();
        }
        for (CookieFinding f : findings) {
            sb.append("\n  [").append(f.severity()).append("] ").append(f.name()).append("\n");
            sb.append("    Secure   : ").append(f.secure()).append("\n");
            sb.append("    HttpOnly : ").append(f.httpOnly()).append("\n");
            sb.append("    SameSite : ").append(f.sameSite()).append("\n");
            if (f.domain() != null) sb.append("    Domain   : ").append(f.domain()).append("\n");
            sb.append("    Path     : ").append(f.path()).append("\n");
            if (!f.issues().isEmpty()) {
                sb.append("    Issues   :\n");
                for (String issue : f.issues()) {
                    sb.append("      - ").append(issue).append("\n");
                }
            }
        }
        sb.append("\n  Total: ").append(findings.size()).append(" cookie(s)\n");
        return sb.toString();
    }
}
