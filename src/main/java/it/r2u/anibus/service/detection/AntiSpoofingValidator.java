package it.r2u.anibus.service.detection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cross-validates server identity claims against behavioral fingerprints.
 * <p>
 * Detects discrepancies between what a server <em>claims</em> (Server header,
 * banner text) and what it <em>does</em> (ETag format, header ordering, algorithm
 * lists, version plausibility). Such mismatches indicate that the server identity
 * has been deliberately spoofed, obfuscated, or is behind a proxy that is altering
 * responses.
 */
public final class AntiSpoofingValidator {

    private AntiSpoofingValidator() { }

    // -------------------------------------------------------------------------
    // Result type
    // -------------------------------------------------------------------------

    /**
     * Outcome of a validation run.
     *
     * @param confidence       0–100 confidence that the claimed identity is genuine
     * @param likelyTrueServer best guess at the real server, or {@code null} if unknown
     * @param confidence          0–100 confidence that the claimed identity is genuine
     * @param likelyTrueServer    best guess at the real server, or {@code null} if unknown
     * @param inconsistenciesFound {@code true} when contradictions were detected
     * @param formatted           pre-built analysis text ready for the scan banner
     */
    public record ValidationResult(
            int confidence,
            String likelyTrueServer,
            boolean inconsistenciesFound,
            String formatted
    ) {
        public boolean hasInconsistencies() { return inconsistenciesFound; }
        public String format() { return formatted; }
    }

    // -------------------------------------------------------------------------
    // Primary entry point — compare banner claim vs. behavioral fingerprint
    // -------------------------------------------------------------------------

    /**
     * Compares the server identity claimed by the banner/Server header against
     * the identity inferred by passive behavioral fingerprinting (header order,
     * ETag format, etc.).
     *
     * @param claimedByBanner    service name extracted from the Server header or greeting
     * @param claimedByBehavior  service name inferred by {@code PassiveFingerprinter}
     * @param rawBanner          raw banner / header block for version plausibility checks
     * @return validation result (check {@link ValidationResult#hasInconsistencies()})
     */
    public static ValidationResult compareServerClaims(
            String claimedByBanner,
            String claimedByBehavior,
            String rawBanner) {

        int confidence = 60;

        if (claimedByBanner == null || claimedByBehavior == null) {
            return new ValidationResult(confidence, null, false,
                    "[ANTI-SPOOF ANALYSIS] confidence=" + confidence + "%");
        }

        List<String> inconsistencies = new ArrayList<>();
        List<String> verified        = new ArrayList<>();

        // Normalize: "Apache Tomcat" vs "Tomcat" → still a match
        String bannerLower   = claimedByBanner.toLowerCase();
        String behaviorLower = claimedByBehavior.toLowerCase();
        boolean agree = bannerLower.contains(behaviorLower)
                || behaviorLower.contains(bannerLower);

        String likelyTrue;
        if (agree) {
            verified.add("Server header '" + claimedByBanner
                    + "' confirmed by behavioral fingerprint (" + claimedByBehavior + ")");
            confidence += 25;
            likelyTrue = claimedByBanner;
        } else {
            inconsistencies.add("Server header claims '" + claimedByBanner
                    + "' but HTTP behavioral fingerprint indicates '"
                    + claimedByBehavior + "'"
                    + " — server identity may be spoofed or behind a proxy");
            confidence -= 20;
            likelyTrue = claimedByBehavior + " (disguised as " + claimedByBanner + ")";
        }

        // Version plausibility — does this version number actually exist?
        if (rawBanner != null) {
            String issue = checkVersionPlausibility(rawBanner);
            if (issue != null) {
                inconsistencies.add(issue);
                confidence -= 20;
            }
        }

        confidence = Math.max(0, Math.min(100, confidence));
        StringBuilder csSb = new StringBuilder("[ANTI-SPOOF ANALYSIS]");
        csSb.append(" confidence=").append(confidence).append("%");
        if (likelyTrue != null) csSb.append(" | likely=").append(likelyTrue);
        verified.forEach(c -> csSb.append("\n  \u2713 ").append(c));
        inconsistencies.forEach(i -> csSb.append("\n  \u26a0 INCONSISTENCY: ").append(i));
        return new ValidationResult(confidence, likelyTrue, !inconsistencies.isEmpty(), csSb.toString());
    }

    // -------------------------------------------------------------------------
    // HTTP-level validation (header evidence: ETag, Keep-Alive, X-Powered-By)
    // -------------------------------------------------------------------------

    /**
     * Validates HTTP server identity using response header evidence independent of
     * the Server header itself.  Called when {@code PassiveFingerprinter} is not
     * available and raw headers are accessible directly.
     *
     * @param serverHeader  value of the {@code Server:} response header (may be null)
     * @param etag          value of the {@code ETag:} response header (may be null)
     * @param xPoweredBy    value of {@code X-Powered-By:} (may be null)
     * @param keepAlive     value of {@code Keep-Alive:} (may be null)
     * @return validation result
     */
    public static ValidationResult validateHttpEvidence(
            String serverHeader,
            String etag,
            String xPoweredBy,
            String keepAlive) {

        List<String> inconsistencies = new ArrayList<>();
        List<String> verified        = new ArrayList<>();
        int          confidence      = 50;
        String       likelyTrue      = parseClaimed(serverHeader);

        String etagServer = analyzeEtag(etag);
        if (etagServer != null && likelyTrue != null) {
            if (serverMatch(likelyTrue, etagServer)) {
                verified.add("ETag format (" + etag + ") is consistent with " + likelyTrue);
                confidence += 15;
            } else {
                inconsistencies.add("Server header claims '" + likelyTrue
                        + "' but ETag format matches " + etagServer);
                confidence -= 20;
                likelyTrue = etagServer;
            }
        }

        // X-Powered-By: ASP.NET always means IIS / Windows
        if (xPoweredBy != null && xPoweredBy.toLowerCase().contains("asp.net")) {
            if (likelyTrue != null
                    && !likelyTrue.toLowerCase().contains("iis")
                    && !likelyTrue.toLowerCase().contains("microsoft")) {
                inconsistencies.add("X-Powered-By: " + xPoweredBy
                        + " reveals IIS/Windows stack, but Server header claims '"
                        + likelyTrue + "'");
                confidence -= 25;
                likelyTrue = "IIS (reverse-proxied behind " + likelyTrue + ")";
            } else {
                verified.add("X-Powered-By confirms ASP.NET/Windows stack");
                confidence += 10;
            }
        }

        // Keep-Alive: timeout=5, max=100 is an Apache httpd signature
        if (keepAlive != null
                && keepAlive.contains("timeout=5")
                && keepAlive.contains("max=100")) {
            if (likelyTrue != null && !likelyTrue.toLowerCase().contains("apache")) {
                inconsistencies.add("Keep-Alive 'timeout=5, max=100' is an Apache httpd"
                        + " fingerprint, but Server header claims '" + likelyTrue + "'");
                confidence -= 15;
                if (likelyTrue.equals(parseClaimed(serverHeader))) {
                    likelyTrue = "Apache httpd (disguised as " + likelyTrue + ")";
                }
            } else {
                verified.add("Keep-Alive pattern is consistent with Apache httpd");
                confidence += 10;
            }
        }

        // nginx characteristically does NOT send a Keep-Alive header
        if (likelyTrue != null && likelyTrue.toLowerCase().contains("nginx")) {
            if (keepAlive == null) {
                verified.add("Absence of Keep-Alive header is consistent with nginx");
                confidence += 10;
            } else {
                inconsistencies.add("nginx typically omits Keep-Alive, but this server sends it"
                        + " — may not be genuine nginx");
                confidence -= 10;
            }
        }

        // Version plausibility check on the Server header itself
        if (serverHeader != null) {
            String issue = checkVersionPlausibility(serverHeader);
            if (issue != null) {
                inconsistencies.add(issue);
                confidence -= 20;
            }
        }

        confidence = Math.max(0, Math.min(100, confidence));
        StringBuilder httpSb = new StringBuilder("[ANTI-SPOOF ANALYSIS]");
        httpSb.append(" confidence=").append(confidence).append("%");
        if (likelyTrue != null) httpSb.append(" | likely=").append(likelyTrue);
        verified.forEach(c -> httpSb.append("\n  \u2713 ").append(c));
        inconsistencies.forEach(i -> httpSb.append("\n  \u26a0 INCONSISTENCY: ").append(i));
        return new ValidationResult(confidence, likelyTrue, !inconsistencies.isEmpty(), httpSb.toString());
    }

    // -------------------------------------------------------------------------
    // Version plausibility
    // -------------------------------------------------------------------------

    /**
     * Checks whether the version number in a Server header is within the known
     * release range for that product.  Returns a warning string if implausible,
     * or {@code null} if the version looks realistic.
     */
    public static String checkVersionPlausibility(String serverHeader) {
        if (serverHeader == null) return null;
        String lower = serverHeader.toLowerCase();

        // nginx: 0.x.x to 1.27.x as of 2025 (2.x does not exist)
        Matcher m = Pattern.compile("nginx/(\\d+)\\.(\\d+)").matcher(lower);
        if (m.find()) {
            int major = Integer.parseInt(m.group(1));
            int minor = Integer.parseInt(m.group(2));
            if (major > 1 || (major == 1 && minor > 32)) {
                return "nginx/" + major + "." + minor
                        + " does not exist — likely a spoofed Server header";
            }
        }

        // Apache: 1.3.x and 2.0.x–2.4.x; 2.5 is development-only
        m = Pattern.compile("apache/(\\d+)\\.(\\d+)").matcher(lower);
        if (m.find()) {
            int major = Integer.parseInt(m.group(1));
            int minor = Integer.parseInt(m.group(2));
            if (major == 2 && minor > 5) {
                return "Apache/" + major + "." + minor
                        + " does not exist — spoofed version";
            }
            if (major == 1 && minor > 3) {
                return "Apache/1." + minor + " does not exist — spoofed version";
            }
            if (major > 2) {
                return "Apache/" + major + ".x major version does not exist";
            }
        }

        // IIS: 5.0, 5.1, 6.0, 7.0, 7.5, 8.0, 8.5, 10.0 — nothing above 10
        m = Pattern.compile("microsoft-iis/(\\d+)").matcher(lower);
        if (m.find()) {
            int major = Integer.parseInt(m.group(1));
            if (major > 10) {
                return "IIS/" + major + " does not exist — spoofed Server header";
            }
        }

        // LiteSpeed: 4.x–7.x as of 2025
        m = Pattern.compile("litespeed/(\\d+)").matcher(lower);
        if (m.find()) {
            int major = Integer.parseInt(m.group(1));
            if (major > 8) {
                return "LiteSpeed/" + major + " seems implausible — possible spoof";
            }
        }

        return null;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String parseClaimed(String serverHeader) {
        if (serverHeader == null) return null;
        String lower = serverHeader.toLowerCase();
        if (lower.contains("nginx"))            return "nginx";
        if (lower.contains("apache"))           return "Apache";
        if (lower.contains("microsoft-iis"))    return "IIS";
        if (lower.contains("lighttpd"))         return "Lighttpd";
        if (lower.contains("caddy"))            return "Caddy";
        if (lower.contains("openresty"))        return "OpenResty";
        if (lower.contains("litespeed"))        return "LiteSpeed";
        if (lower.contains("tomcat"))           return "Tomcat";
        return serverHeader.split("/")[0].trim();
    }

    /**
     * Infers the web server from the ETag value format:
     * <ul>
     *   <li>Apache: {@code "inode-size-mtime"} — three hex segments separated by dashes</li>
     *   <li>nginx:  {@code "timestamp-size"}   — two hex segments separated by a dash</li>
     *   <li>IIS:    colon-separated or uppercase hex</li>
     * </ul>
     */
    private static String analyzeEtag(String etag) {
        if (etag == null) return null;
        if (etag.matches("\"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+\""))   return "Apache";
        if (etag.matches("\"[0-9a-f]+-[0-9a-f]+\""))              return "nginx";
        if (etag.matches("\"[0-9A-F:]+\"") || etag.contains(":")) return "IIS";
        return null;
    }

    private static boolean serverMatch(String s1, String s2) {
        String a = s1.toLowerCase();
        String b = s2.toLowerCase();
        return a.equals(b) || a.contains(b) || b.contains(a);
    }
}
