package it.r2u.anibus.service.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts CSRF / anti-forgery tokens from HTML response bodies.
 *
 * <p>Looks for the three idiomatic places where web frameworks expose CSRF tokens:</p>
 * <ul>
 *   <li>{@code <meta name="csrf-token" content="...">} (Rails / Laravel / Django patterns)</li>
 *   <li>{@code <input type="hidden" name="csrf_token" value="...">} inside forms</li>
 *   <li>{@code <meta name="_csrf">} + {@code <meta name="_csrf_header">} (Spring Security)</li>
 * </ul>
 *
 * <p>Stateless — pure HTML parsing, no network. Callers that already have the
 * response body (PassiveReconService, JavaScriptSecurityAnalyzer auth crawler)
 * can use {@link #extract(String)} to recover a token they should attach to
 * subsequent state-changing requests.</p>
 */
public final class CsrfTokenExtractor {

    /** Common token-bearing parameter / meta names (case-insensitive match). */
    private static final List<String> KNOWN_NAMES = List.of(
        "csrf-token",
        "csrf_token",
        "csrftoken",
        "csrfmiddlewaretoken",
        "_csrf",
        "_csrf_token",
        "_token",
        "authenticity_token",       // Rails
        "anti-forgery-token",
        "__requestverificationtoken" // ASP.NET
    );

    /** Header name used by Spring Security when {@code _csrf_header} meta is absent. */
    public static final String DEFAULT_HEADER_NAME = "X-CSRF-Token";

    /** Result of an extraction attempt. */
    public record CsrfToken(
        String tokenName,
        String tokenValue,
        String headerName,
        Source source
    ) {
        public enum Source { META_TAG, HIDDEN_INPUT, COOKIE_HINT }
    }

    private static final Pattern META_PATTERN = Pattern.compile(
        "<meta\\s+[^>]*name\\s*=\\s*[\"']([^\"']+)[\"'][^>]*content\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern META_REVERSE_PATTERN = Pattern.compile(
        "<meta\\s+[^>]*content\\s*=\\s*[\"']([^\"']+)[\"'][^>]*name\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern INPUT_PATTERN = Pattern.compile(
        "<input\\s+[^>]*name\\s*=\\s*[\"']([^\"']+)[\"'][^>]*value\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern INPUT_REVERSE_PATTERN = Pattern.compile(
        "<input\\s+[^>]*value\\s*=\\s*[\"']([^\"']*)[\"'][^>]*name\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>",
        Pattern.CASE_INSENSITIVE
    );

    private CsrfTokenExtractor() { /* no instances */ }

    /**
     * Searches the given HTML for a CSRF token.
     *
     * @return first matching {@link CsrfToken}, or {@code null} if none found
     */
    public static CsrfToken extract(String html) {
        if (html == null || html.isBlank()) return null;

        // 1. Spring Security pair: _csrf + _csrf_header
        String springToken = findMeta(html, "_csrf");
        if (springToken != null) {
            String headerName = findMeta(html, "_csrf_header");
            return new CsrfToken("_csrf", springToken,
                headerName != null ? headerName : DEFAULT_HEADER_NAME,
                CsrfToken.Source.META_TAG);
        }

        // 2. Generic <meta name="csrf-token" content="...">
        Matcher m = META_PATTERN.matcher(html);
        while (m.find()) {
            String name = m.group(1).trim();
            String value = m.group(2).trim();
            if (matchesKnownName(name) && !value.isBlank()) {
                return new CsrfToken(name, value, DEFAULT_HEADER_NAME, CsrfToken.Source.META_TAG);
            }
        }
        m = META_REVERSE_PATTERN.matcher(html);
        while (m.find()) {
            String value = m.group(1).trim();
            String name = m.group(2).trim();
            if (matchesKnownName(name) && !value.isBlank()) {
                return new CsrfToken(name, value, DEFAULT_HEADER_NAME, CsrfToken.Source.META_TAG);
            }
        }

        // 3. Hidden form input
        m = INPUT_PATTERN.matcher(html);
        while (m.find()) {
            String name = m.group(1).trim();
            String value = m.group(2).trim();
            if (matchesKnownName(name) && !value.isBlank()) {
                return new CsrfToken(name, value, null, CsrfToken.Source.HIDDEN_INPUT);
            }
        }
        m = INPUT_REVERSE_PATTERN.matcher(html);
        while (m.find()) {
            String value = m.group(1).trim();
            String name = m.group(2).trim();
            if (matchesKnownName(name) && !value.isBlank()) {
                return new CsrfToken(name, value, null, CsrfToken.Source.HIDDEN_INPUT);
            }
        }

        return null;
    }

    /** Returns all distinct CSRF-style names found in the HTML (for debugging / reporting). */
    public static List<String> listCandidateNames(String html) {
        List<String> names = new ArrayList<>();
        if (html == null || html.isBlank()) return names;
        Matcher m = META_PATTERN.matcher(html);
        while (m.find()) {
            String name = m.group(1).trim();
            if (matchesKnownName(name) && !names.contains(name)) names.add(name);
        }
        m = INPUT_PATTERN.matcher(html);
        while (m.find()) {
            String name = m.group(1).trim();
            if (matchesKnownName(name) && !names.contains(name)) names.add(name);
        }
        return names;
    }

    private static String findMeta(String html, String exactName) {
        Matcher m = META_PATTERN.matcher(html);
        while (m.find()) {
            if (m.group(1).trim().equalsIgnoreCase(exactName)) {
                String v = m.group(2).trim();
                if (!v.isBlank()) return v;
            }
        }
        m = META_REVERSE_PATTERN.matcher(html);
        while (m.find()) {
            if (m.group(2).trim().equalsIgnoreCase(exactName)) {
                String v = m.group(1).trim();
                if (!v.isBlank()) return v;
            }
        }
        return null;
    }

    private static boolean matchesKnownName(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        for (String known : KNOWN_NAMES) {
            if (lower.equals(known) || lower.contains(known)) return true;
        }
        return lower.contains("csrf") || lower.contains("xsrf");
    }
}
