package it.r2u.anibus.service.analysis;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JWT analyzer: extracts and inspects JWT tokens found in raw text (JS sources, headers, responses).
 * Detects: alg:none, expired tokens, missing expiry, weak algorithm labels.
 */
public class JwtAnalyzer {

    /** Pattern matching a compact JWT (three base64url segments). */
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*"
    );

    public enum JwtRisk { CRITICAL, HIGH, MEDIUM, LOW, INFO }

    /** Result for one discovered JWT. */
    public record JwtFinding(
        String token,
        String algorithm,
        boolean noneAlg,
        boolean expiredOrMissing,
        long expTimestamp,
        String headerJson,
        String payloadJson,
        JwtRisk risk,
        String finding
    ) {
        /** Truncated token for display (first 40 chars + …). */
        public String shortToken() {
            return token.length() > 40 ? token.substring(0, 40) + "…" : token;
        }
    }

    /**
     * Scans arbitrary text for JWT tokens and analyzes each one.
     *
     * @param text Any string (JS source, HTTP response body, etc.)
     * @return Deduplicated list of findings
     */
    public List<JwtFinding> analyzeFromText(String text) {
        List<JwtFinding> findings = new ArrayList<>();
        if (text == null || text.isBlank()) return findings;

        Matcher m = JWT_PATTERN.matcher(text);
        List<String> seen = new ArrayList<>();
        while (m.find()) {
            String token = m.group();
            if (seen.contains(token)) continue;
            seen.add(token);
            JwtFinding f = analyze(token);
            if (f != null) findings.add(f);
        }
        return findings;
    }

    private JwtFinding analyze(String token) {
        String[] parts = token.split("\\.", 3);
        if (parts.length < 2) return null;

        String headerJson  = decodeSegment(parts[0]);
        String payloadJson = decodeSegment(parts[1]);
        if (headerJson == null || payloadJson == null) return null;

        String alg = extractStringField(headerJson, "alg");
        boolean noneAlg = alg != null && alg.equalsIgnoreCase("none");

        long exp = extractLongField(payloadJson, "exp");
        long now = System.currentTimeMillis() / 1000;
        boolean expiredOrMissing = (exp == Long.MIN_VALUE) || (exp < now);

        JwtRisk risk;
        String finding;

        if (noneAlg) {
            risk    = JwtRisk.CRITICAL;
            finding = "Algorithm is 'none' — signature is not verified, token can be forged freely";
        } else if (expiredOrMissing && exp != Long.MIN_VALUE) {
            risk    = JwtRisk.HIGH;
            finding = "Token is expired (exp=" + exp + ") but may still be accepted by vulnerable services";
        } else if (exp == Long.MIN_VALUE) {
            risk    = JwtRisk.MEDIUM;
            finding = "No 'exp' claim — token never expires";
        } else if (alg != null && (alg.equalsIgnoreCase("HS256") || alg.equalsIgnoreCase("HS384"))) {
            risk    = JwtRisk.LOW;
            finding = "HMAC algorithm " + alg + " — verify that the secret is sufficiently long (≥32 bytes)";
        } else {
            risk    = JwtRisk.INFO;
            finding = "Token appears structurally valid (alg=" + alg + ")";
        }

        return new JwtFinding(token, alg, noneAlg, expiredOrMissing, exp,
                              headerJson, payloadJson, risk, finding);
    }

    private String decodeSegment(String b64url) {
        try {
            // Pad to multiple of 4
            String padded = b64url + "==".substring(0, (4 - b64url.length() % 4) % 4);
            byte[] bytes = Base64.getUrlDecoder().decode(padded);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private String extractStringField(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private long extractLongField(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)");
        Matcher m = p.matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : Long.MIN_VALUE;
    }

    /** Formats a human-readable JWT report. */
    public static String formatReport(List<JwtFinding> findings, String source) {
        StringBuilder sb = new StringBuilder("=== JWT ANALYSIS");
        if (source != null && !source.isBlank()) sb.append(": ").append(source);
        sb.append(" ===\n");

        if (findings == null || findings.isEmpty()) {
            sb.append("  No JWT tokens found.\n");
            return sb.toString();
        }

        sb.append("  Found ").append(findings.size()).append(" JWT token(s):\n");
        for (JwtFinding f : findings) {
            sb.append("\n  [").append(f.risk()).append("] ").append(f.shortToken()).append("\n");
            sb.append("    alg    : ").append(f.algorithm() != null ? f.algorithm() : "n/a").append("\n");
            sb.append("    header : ").append(f.headerJson()).append("\n");
            sb.append("    payload: ").append(
                f.payloadJson().length() > 200 ? f.payloadJson().substring(0, 200) + "…" : f.payloadJson()
            ).append("\n");
            sb.append("    ⚠  ").append(f.finding()).append("\n");
        }
        return sb.toString();
    }
}
