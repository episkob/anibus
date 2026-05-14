package it.r2u.anibus.service.analysis;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
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

    private static final Pattern TOKEN_STORAGE_PATTERN = Pattern.compile(
        "(?:localStorage|sessionStorage)\\s*\\.\\s*(?:setItem|getItem)\\s*\\(\\s*['\"](access_token|id_token|refresh_token|jwt|token)['\"]",
        Pattern.CASE_INSENSITIVE
    );

    public enum JwtRisk { CRITICAL, HIGH, MEDIUM, LOW, INFO }

    /** Result for one discovered JWT. */
    public record JwtFinding(
        String token,
        String algorithm,
        String kid,
        boolean suspiciousKid,
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

        Matcher storageMatcher = TOKEN_STORAGE_PATTERN.matcher(text);
        while (storageMatcher.find()) {
            String key = storageMatcher.group(1).toLowerCase(Locale.ROOT);
            String syntheticToken = "[storage-key:" + key + "]";
            if (seen.contains(syntheticToken)) {
                continue;
            }
            seen.add(syntheticToken);
            findings.add(new JwtFinding(
                    syntheticToken,
                    "N/A",
                    null,
                    false,
                    false,
                    false,
                    Long.MIN_VALUE,
                    "{}",
                    "{}",
                    JwtRisk.MEDIUM,
                    "Token-like value is stored in localStorage/sessionStorage under key '" + key + "'"
            ));
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
        String kid = extractStringField(headerJson, "kid");
        boolean suspiciousKid = isSuspiciousKid(kid);
        boolean noneAlg = alg != null && alg.equalsIgnoreCase("none");

        long exp = extractLongField(payloadJson, "exp");
        long now = System.currentTimeMillis() / 1000;
        boolean expiredOrMissing = (exp == Long.MIN_VALUE) || (exp < now);

        JwtRisk risk;
        String finding;

        if (noneAlg) {
            risk    = JwtRisk.CRITICAL;
            finding = "Algorithm is 'none' — signature is not verified, token can be forged freely";
        } else if (suspiciousKid) {
            risk    = JwtRisk.HIGH;
            finding = "Suspicious 'kid' header value (possible path traversal/SQL injection): " + kid;
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

        return new JwtFinding(token, alg, kid, suspiciousKid, noneAlg, expiredOrMissing, exp,
                              headerJson, payloadJson, risk, finding);
    }

    private boolean isSuspiciousKid(String kid) {
        if (kid == null || kid.isBlank()) {
            return false;
        }
        String normalized = kid.toLowerCase(Locale.ROOT);
        return normalized.contains("../")
                || normalized.contains("..\\")
                || normalized.contains("%2e%2e")
                || normalized.contains("'")
                || normalized.contains("\"")
                || normalized.contains("--")
                || normalized.contains(" union ")
                || normalized.contains(" select ")
                || normalized.contains(" or ")
                || normalized.contains(";");
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

    /**
     * Compares two JWTs (typically an access token and a refresh token) and
     * reports findings about their relative TTL. A refresh-token TTL much
     * shorter than the access-token TTL, or both being very long-lived,
     * is a misconfiguration that increases blast radius if a token leaks.
     */
    public List<String> compareTokenPair(String accessToken, String refreshToken) {
        List<String> notes = new ArrayList<>();
        if (accessToken == null || refreshToken == null) return notes;
        long accessExp  = expOf(accessToken);
        long refreshExp = expOf(refreshToken);
        if (accessExp == Long.MIN_VALUE || refreshExp == Long.MIN_VALUE) {
            notes.add("[INFO] One of the tokens has no 'exp' — cannot compare TTLs.");
            return notes;
        }
        long now = System.currentTimeMillis() / 1000;
        long accessTtl  = accessExp  - now;
        long refreshTtl = refreshExp - now;
        notes.add("Access TTL  : " + humanTtl(accessTtl));
        notes.add("Refresh TTL : " + humanTtl(refreshTtl));
        if (refreshTtl < accessTtl) {
            notes.add("[HIGH] Refresh-token TTL is SHORTER than access-token TTL — broken refresh model.");
        }
        if (accessTtl > 24L * 3600) {
            notes.add("[MEDIUM] Access-token TTL exceeds 24 h — leaked access tokens have long usefulness window.");
        }
        if (refreshTtl > 90L * 24 * 3600) {
            notes.add("[MEDIUM] Refresh-token TTL exceeds 90 days — consider rotating refresh tokens.");
        }
        if (Math.abs(refreshTtl - accessTtl) < 60) {
            notes.add("[LOW] Refresh and access tokens have nearly identical TTL — refresh provides no real value.");
        }
        return notes;
    }

    private long expOf(String token) {
        if (token == null) return Long.MIN_VALUE;
        String[] parts = token.split("\\.");
        if (parts.length < 2) return Long.MIN_VALUE;
        String payload = decodeSegment(parts[1]);
        if (payload == null) return Long.MIN_VALUE;
        return extractLongField(payload, "exp");
    }

    private String humanTtl(long seconds) {
        if (seconds < 0)     return "EXPIRED";
        if (seconds < 60)    return seconds + "s";
        if (seconds < 3600)  return (seconds / 60) + "m";
        if (seconds < 86400) return (seconds / 3600) + "h";
        return (seconds / 86400) + "d";
    }

    /**
     * Returns a tampered clone of the input JWT with one claim overridden
     * (e.g. <code>role=admin</code> or <code>sub=1</code>). The signature is
     * left untouched — use this output only to PROBE a target endpoint for
     * misconfigured verification (alg:none accepted, weak HMAC, no signature
     * check at all). The function does NOT re-sign or attempt to forge a
     * valid signature; it is a detection helper, not a weaponized exploit.
     *
     * @return the tampered token, or null if the input is not a valid JWT
     */
    public String cloneWithClaim(String token, String claim, String value) {
        if (token == null || claim == null || value == null) return null;
        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;
        String payload = decodeSegment(parts[1]);
        if (payload == null) return null;

        // Replace existing claim or insert new one. Use simple regex (no JSON lib per project convention).
        String tampered;
        Pattern existing = Pattern.compile("(\"" + Pattern.quote(claim) + "\"\\s*:\\s*)(\"[^\"]*\"|[^,\\}\\s]+)");
        Matcher m = existing.matcher(payload);
        if (m.find()) {
            tampered = m.replaceFirst(m.group(1) + "\"" + Matcher.quoteReplacement(value) + "\"");
        } else if (payload.trim().endsWith("}")) {
            int close = payload.lastIndexOf('}');
            String body = payload.substring(0, close).trim();
            String comma = body.endsWith("{") ? "" : ",";
            tampered = body + comma + "\"" + claim + "\":\"" + value + "\"}";
        } else {
            return null;
        }

        String b64 = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(tampered.getBytes(StandardCharsets.UTF_8));
        String sig = parts.length >= 3 ? parts[2] : "";
        return parts[0] + "." + b64 + "." + sig;
    }

    /**
     * Analyzes a JWKS (JSON Web Key Set) document for common misconfigurations:
     * duplicate <code>kid</code> values (kid-injection / key-confusion surface),
     * advertised <code>alg=none</code>, HMAC keys exposed in a public JWKS
     * (RS→HS algorithm-confusion risk) and short RSA moduli.
     *
     * <p>Returns a list of severity-tagged advisory strings; an empty list means
     * no obvious issues were detected.
     */
    public List<String> analyzeJwks(String jwksJson) {
        List<String> notes = new ArrayList<>();
        if (jwksJson == null || jwksJson.isBlank()) return notes;
        Matcher kids = Pattern.compile("\"kid\"\\s*:\\s*\"([^\"]+)\"").matcher(jwksJson);
        List<String> seen = new ArrayList<>();
        while (kids.find()) {
            String kid = kids.group(1);
            if (seen.contains(kid)) {
                notes.add("[HIGH] Duplicate kid in JWKS: " + kid
                        + " — enables kid-confusion / key-pinning bypass.");
            } else {
                seen.add(kid);
            }
            if (isSuspiciousKid(kid)) {
                notes.add("[HIGH] Suspicious kid value in JWKS (possible injection): " + kid);
            }
        }
        Matcher algs = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]+)\"").matcher(jwksJson);
        while (algs.find()) {
            String a = algs.group(1);
            if (a.equalsIgnoreCase("none")) {
                notes.add("[CRITICAL] JWKS advertises alg=none — server should never accept unsigned JWTs.");
            } else if (a.equalsIgnoreCase("HS256") || a.equalsIgnoreCase("HS384")
                    || a.equalsIgnoreCase("HS512")) {
                notes.add("[MEDIUM] JWKS exposes HMAC key (alg=" + a
                        + ") — algorithm-confusion (RS→HS) possible if the server doesn't pin alg.");
            }
        }
        Matcher ns = Pattern.compile("\"n\"\\s*:\\s*\"([^\"]+)\"").matcher(jwksJson);
        while (ns.find()) {
            int approxBits = ns.group(1).length() * 6; // base64url → ~6 bits per char
            if (approxBits > 0 && approxBits < 2048) {
                notes.add("[HIGH] RSA modulus in JWKS appears < 2048 bits (~"
                        + approxBits + " bits) — factorable in practice.");
            }
        }
        return notes;
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
            if (f.kid() != null && !f.kid().isBlank()) {
                sb.append("    kid    : ").append(f.kid()).append("\n");
            }
            sb.append("    header : ").append(f.headerJson()).append("\n");
            sb.append("    payload: ").append(
                f.payloadJson().length() > 200 ? f.payloadJson().substring(0, 200) + "…" : f.payloadJson()
            ).append("\n");
            sb.append("    ⚠  ").append(f.finding()).append("\n");
        }
        return sb.toString();
    }
}
