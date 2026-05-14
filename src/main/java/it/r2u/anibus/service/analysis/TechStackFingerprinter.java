package it.r2u.anibus.service.analysis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tech Stack Fingerprinter 2.0.
 *
 * Identifies CMS, frameworks, JS libraries and CDNs from passive evidence
 * (HTTP headers + HTML body). No active probing — purely string/regex match.
 *
 * Inputs are taken from {@link PassiveReconService.PassiveReconResult} plus
 * the raw HTML, so this stage runs after passive recon at no additional
 * network cost.
 */
public class TechStackFingerprinter {

    public record TechFinding(
        String name,
        String category,
        String version,
        String evidence
    ) {}

    /** Signature record: a name, what category it belongs to, and how to match it. */
    private record Sig(String name, String category, Pattern pattern, boolean isHeader, String headerName) {}

    private static final List<Sig> SIGNATURES = buildSignatures();

    private static List<Sig> buildSignatures() {
        List<Sig> s = new ArrayList<>();
        // ── Server / framework headers ────────────────────────────────────
        s.add(new Sig("Nginx",      "Web Server", Pattern.compile("(?i)nginx/?([0-9.]+)?"),         true,  "server"));
        s.add(new Sig("Apache",     "Web Server", Pattern.compile("(?i)apache(?:/([0-9.]+))?"),     true,  "server"));
        s.add(new Sig("LiteSpeed",  "Web Server", Pattern.compile("(?i)litespeed"),                 true,  "server"));
        s.add(new Sig("Caddy",      "Web Server", Pattern.compile("(?i)caddy"),                     true,  "server"));
        s.add(new Sig("IIS",        "Web Server", Pattern.compile("(?i)microsoft-iis/?([0-9.]+)?"), true,  "server"));
        s.add(new Sig("PHP",        "Language",   Pattern.compile("(?i)php/?([0-9.]+)?"),           true,  "x-powered-by"));
        s.add(new Sig("ASP.NET",    "Framework",  Pattern.compile("(?i)asp\\.net"),                 true,  "x-powered-by"));
        s.add(new Sig("Express",    "Framework",  Pattern.compile("(?i)express"),                   true,  "x-powered-by"));
        s.add(new Sig("Cloudflare", "CDN/WAF",    Pattern.compile("(?i)cloudflare"),                true,  "server"));
        s.add(new Sig("Fastly",     "CDN",        Pattern.compile("(?i)fastly"),                    true,  "server"));
        s.add(new Sig("Akamai",     "CDN",        Pattern.compile("(?i)akamai"),                    true,  "server"));
        s.add(new Sig("Varnish",    "Cache",      Pattern.compile("(?i)varnish"),                   true,  "via"));

        // ── CMS / frameworks in body ──────────────────────────────────────
        s.add(new Sig("WordPress",  "CMS",        Pattern.compile("(?i)/wp-content/|/wp-includes/|wp-json"), false, null));
        s.add(new Sig("Joomla",     "CMS",        Pattern.compile("(?i)/components/com_|joomla"),    false, null));
        s.add(new Sig("Drupal",     "CMS",        Pattern.compile("(?i)drupal-settings-json|/sites/default/files"), false, null));
        s.add(new Sig("Magento",    "E-Commerce", Pattern.compile("(?i)mage/cookies|/skin/frontend/|magento"), false, null));
        s.add(new Sig("Shopify",    "E-Commerce", Pattern.compile("(?i)cdn\\.shopify\\.com|shopify\\."), false, null));
        s.add(new Sig("Bitrix",     "CMS",        Pattern.compile("(?i)/bitrix/|bx-core"),           false, null));
        s.add(new Sig("Ghost",      "CMS",        Pattern.compile("(?i)content=\"ghost\\s"),         false, null));
        s.add(new Sig("Strapi",     "Headless CMS", Pattern.compile("(?i)strapi"),                   false, null));

        // ── JS frameworks ─────────────────────────────────────────────────
        s.add(new Sig("React",      "JS Framework", Pattern.compile("(?i)react(?:-dom)?(?:[.@-]([0-9.]+))?\\.(?:min\\.)?js"), false, null));
        s.add(new Sig("Vue.js",     "JS Framework", Pattern.compile("(?i)vue(?:[.@-]([0-9.]+))?\\.(?:min\\.)?js|__vue__"), false, null));
        s.add(new Sig("Angular",    "JS Framework", Pattern.compile("(?i)ng-version=\"([0-9.]+)\"|angular(?:[.@-]([0-9.]+))?\\.js"), false, null));
        s.add(new Sig("Svelte",     "JS Framework", Pattern.compile("(?i)svelte[.@-]([0-9.]+)|svelte-"), false, null));
        s.add(new Sig("Next.js",    "JS Framework", Pattern.compile("(?i)/_next/static/|__NEXT_DATA__"), false, null));
        s.add(new Sig("Nuxt.js",    "JS Framework", Pattern.compile("(?i)__NUXT__|/_nuxt/"),         false, null));
        s.add(new Sig("jQuery",     "JS Library",   Pattern.compile("(?i)jquery[.@-]?([0-9.]+)?\\.(?:min\\.)?js"), false, null));
        s.add(new Sig("Bootstrap",  "CSS Framework", Pattern.compile("(?i)bootstrap[.@-]?([0-9.]+)?\\.(?:min\\.)?(?:js|css)"), false, null));
        s.add(new Sig("Tailwind CSS","CSS Framework", Pattern.compile("(?i)tailwind(?:[.@-]([0-9.]+))?"), false, null));

        // ── Analytics ─────────────────────────────────────────────────────
        s.add(new Sig("Google Analytics", "Analytics", Pattern.compile("(?i)google-analytics\\.com|gtag\\(|GA_MEASUREMENT_ID"), false, null));
        s.add(new Sig("Yandex Metrika",   "Analytics", Pattern.compile("(?i)mc\\.yandex\\.ru/metrika|ym\\([0-9]+,"), false, null));
        s.add(new Sig("Hotjar",           "Analytics", Pattern.compile("(?i)static\\.hotjar\\.com|hj\\("), false, null));

        // ── Languages / runtimes via cookies ──────────────────────────────
        s.add(new Sig("Java",       "Language", Pattern.compile("(?i)jsessionid="),   true, "set-cookie"));
        s.add(new Sig("PHP",        "Language", Pattern.compile("(?i)phpsessid="),    true, "set-cookie"));
        s.add(new Sig("ASP.NET",    "Framework", Pattern.compile("(?i)asp\\.net_sessionid="), true, "set-cookie"));
        s.add(new Sig("Django",     "Framework", Pattern.compile("(?i)csrftoken=|sessionid="), true, "set-cookie"));
        s.add(new Sig("Laravel",    "Framework", Pattern.compile("(?i)laravel_session="), true, "set-cookie"));
        return List.copyOf(s);
    }

    /**
     * Fingerprint a target based on headers and HTML body.
     *
     * @param headers      response headers (lowercase keys recommended)
     * @param htmlBody     raw HTML/JS payload (may be null)
     * @param metaGenerator value parsed from {@code <meta name="generator">} (may be null)
     * @return distinct list of detected technologies
     */
    public List<TechFinding> fingerprint(Map<String, String> headers, String htmlBody, String metaGenerator) {
        Map<String, TechFinding> byKey = new LinkedHashMap<>();

        Map<String, String> lower = new LinkedHashMap<>();
        if (headers != null) {
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (e.getKey() == null) continue;
                lower.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue() == null ? "" : e.getValue());
            }
        }

        for (Sig sig : SIGNATURES) {
            String haystack;
            if (sig.isHeader()) {
                haystack = lower.getOrDefault(sig.headerName(), "");
            } else {
                haystack = htmlBody == null ? "" : htmlBody;
            }
            if (haystack.isEmpty()) continue;
            Matcher m = sig.pattern().matcher(haystack);
            if (!m.find()) continue;
            String version = null;
            for (int g = 1; g <= m.groupCount(); g++) {
                if (m.group(g) != null && !m.group(g).isBlank()) { version = m.group(g); break; }
            }
            String evidence = sig.isHeader()
                ? ("header " + sig.headerName() + ": " + truncate(haystack, 80))
                : ("body match: " + truncate(m.group(), 80));
            byKey.putIfAbsent(sig.name(), new TechFinding(sig.name(), sig.category(), version, evidence));
        }

        if (metaGenerator != null && !metaGenerator.isBlank()) {
            byKey.putIfAbsent("meta:generator",
                new TechFinding(metaGenerator, "CMS/Builder (meta)", null, "<meta name=generator>"));
        }

        return new ArrayList<>(new LinkedHashSet<>(byKey.values()));
    }

    public static String formatReport(List<TechFinding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("      TECH STACK FINGERPRINT\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");
        if (findings == null || findings.isEmpty()) {
            sb.append("  No technologies fingerprinted from passive evidence.\n");
            return sb.toString();
        }
        Map<String, List<TechFinding>> grouped = new LinkedHashMap<>();
        for (TechFinding f : findings) {
            grouped.computeIfAbsent(f.category(), k -> new ArrayList<>()).add(f);
        }
        for (Map.Entry<String, List<TechFinding>> e : grouped.entrySet()) {
            sb.append("  ── ").append(e.getKey()).append(" ──\n");
            for (TechFinding f : e.getValue()) {
                sb.append("    • ").append(f.name());
                if (f.version() != null) sb.append(" v").append(f.version());
                sb.append("    [").append(f.evidence()).append("]\n");
            }
        }
        return sb.toString();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
