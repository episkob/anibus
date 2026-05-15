package it.r2u.anibus.service.network;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Weak TLS Policy Checker — applies explicit, configurable policy rules to an
 * {@link SslTlsAuditor.AuditResult} and returns a ranked list of violations.
 *
 * <p>Policies are expressed as an {@link EnumSet}; the caller may pass any
 * subset.  The convenience method {@link #defaultPolicy()} returns the full
 * strict set recommended for production systems.
 */
public class WeakTlsPolicyChecker {

    // ── Policy rules ───────────────────────────────────────────────────────────

    public enum TlsPolicy {
        /** TLS 1.0 must not be accepted. */
        NO_TLS10,
        /** TLS 1.1 must not be accepted. */
        NO_TLS11,
        /** Negotiated cipher suite must not be on the known-weak list. */
        NO_WEAK_CIPHERS,
        /** Certificate must not be self-signed. */
        NO_SELF_SIGNED,
        /** Certificate must not be expired. */
        NO_EXPIRED_CERT,
        /** Server must send a valid HSTS header. */
        REQUIRE_HSTS,
        /** Certificate chain must be trusted by the JVM's default trust store. */
        REQUIRE_TRUSTED_CHAIN,
        /** At least TLS 1.2 must be negotiated. */
        REQUIRE_TLS12_OR_HIGHER
    }

    // ── Violation ──────────────────────────────────────────────────────────────

    public record PolicyViolation(
            TlsPolicy rule,
            String    severity,   // CRITICAL | HIGH | MEDIUM | LOW
            String    description
    ) {}

    // ── Known-weak cipher substrings ───────────────────────────────────────────
    private static final List<String> WEAK_CIPHER_SUBSTRINGS = List.of(
            "NULL", "ANON", "EXPORT", "DES", "RC4", "RC2",
            "MD5", "SHA1"          // SHA-1 in cipher = HMAC-SHA1, still considered weak
    );

    // ── Public API ─────────────────────────────────────────────────────────────

    /** Returns the recommended strict policy containing all rules. */
    public static Set<TlsPolicy> defaultPolicy() {
        return EnumSet.allOf(TlsPolicy.class);
    }

    /**
     * Evaluates an {@link SslTlsAuditor.AuditResult} against {@code policies}
     * and returns a list of violated rules, sorted by severity (CRITICAL first).
     *
     * @param result   the TLS audit result to check
     * @param policies set of policy rules to enforce
     * @return list of violations (empty if compliant)
     */
    public static List<PolicyViolation> checkPolicy(SslTlsAuditor.AuditResult result,
                                                     Set<TlsPolicy> policies) {
        List<PolicyViolation> violations = new ArrayList<>();
        if (result == null || !result.connected()) {
            violations.add(new PolicyViolation(null, "HIGH",
                    "TLS connection could not be established — policy evaluation skipped"));
            return violations;
        }

        String proto  = result.negotiatedProtocol() != null ? result.negotiatedProtocol() : "";
        String cipher = result.negotiatedCipher()    != null ? result.negotiatedCipher()    : "";

        for (TlsPolicy policy : policies) {
            switch (policy) {

                case NO_TLS10 -> {
                    if (proto.contains("TLSv1") && !proto.contains("TLSv1.") ||
                        proto.equals("TLSv1")   || proto.equals("TLS 1.0")) {
                        violations.add(new PolicyViolation(TlsPolicy.NO_TLS10, "HIGH",
                                "TLS 1.0 is negotiated — deprecated since RFC 8996 (2021)"));
                    }
                    // also check supported list
                    if (result.supportedProtocols() != null) {
                        for (String sp : result.supportedProtocols()) {
                            if ("TLSv1".equals(sp) || "TLS 1.0".equals(sp)) {
                                violations.add(new PolicyViolation(TlsPolicy.NO_TLS10, "HIGH",
                                        "Server supports TLS 1.0 in protocol list"));
                                break;
                            }
                        }
                    }
                }

                case NO_TLS11 -> {
                    if (proto.contains("TLSv1.1") || proto.equals("TLS 1.1")) {
                        violations.add(new PolicyViolation(TlsPolicy.NO_TLS11, "HIGH",
                                "TLS 1.1 is negotiated — deprecated since RFC 8996 (2021)"));
                    }
                    if (result.supportedProtocols() != null) {
                        for (String sp : result.supportedProtocols()) {
                            if ("TLSv1.1".equals(sp) || "TLS 1.1".equals(sp)) {
                                violations.add(new PolicyViolation(TlsPolicy.NO_TLS11, "HIGH",
                                        "Server supports TLS 1.1 in protocol list"));
                                break;
                            }
                        }
                    }
                }

                case NO_WEAK_CIPHERS -> {
                    if (result.weakCipher()) {
                        violations.add(new PolicyViolation(TlsPolicy.NO_WEAK_CIPHERS, "HIGH",
                                "Negotiated cipher suite is flagged weak: " + cipher));
                    } else {
                        // secondary check: substring match on our own list
                        String cipherUpper = cipher.toUpperCase();
                        for (String weak : WEAK_CIPHER_SUBSTRINGS) {
                            if (cipherUpper.contains(weak)) {
                                violations.add(new PolicyViolation(TlsPolicy.NO_WEAK_CIPHERS, "HIGH",
                                        "Cipher contains weak component '" + weak + "': " + cipher));
                                break;
                            }
                        }
                    }
                }

                case NO_SELF_SIGNED -> {
                    if (result.chain() != null && !result.chain().isEmpty()) {
                        SslTlsAuditor.CertInfo leaf = result.chain().get(0);
                        if (leaf.subject() != null && leaf.subject().equals(leaf.issuer())) {
                            violations.add(new PolicyViolation(TlsPolicy.NO_SELF_SIGNED, "HIGH",
                                    "Certificate is self-signed (subject == issuer): " + leaf.subject()));
                        }
                    }
                }

                case NO_EXPIRED_CERT -> {
                    if (result.chain() != null) {
                        for (SslTlsAuditor.CertInfo cert : result.chain()) {
                            if (cert.expired()) {
                                violations.add(new PolicyViolation(TlsPolicy.NO_EXPIRED_CERT, "CRITICAL",
                                        "Certificate is expired: " + cert.subject()));
                            }
                        }
                    }
                }

                case REQUIRE_HSTS -> {
                    if (!result.hstsPresent()) {
                        violations.add(new PolicyViolation(TlsPolicy.REQUIRE_HSTS, "MEDIUM",
                                "HSTS header (Strict-Transport-Security) is absent"));
                    }
                }

                case REQUIRE_TRUSTED_CHAIN -> {
                    if (!result.chainTrusted()) {
                        violations.add(new PolicyViolation(TlsPolicy.REQUIRE_TRUSTED_CHAIN, "HIGH",
                                "Certificate chain is not trusted by the JVM default trust store"));
                    }
                }

                case REQUIRE_TLS12_OR_HIGHER -> {
                    boolean tls12plus = proto.contains("TLSv1.2") || proto.contains("TLSv1.3")
                            || proto.contains("TLS 1.2") || proto.contains("TLS 1.3");
                    if (!tls12plus) {
                        violations.add(new PolicyViolation(TlsPolicy.REQUIRE_TLS12_OR_HIGHER, "HIGH",
                                "Negotiated protocol does not meet TLS 1.2+ requirement: " + proto));
                    }
                }
            }
        }

        // Sort: CRITICAL → HIGH → MEDIUM → LOW
        violations.sort((a, b) -> severityOrder(a.severity()) - severityOrder(b.severity()));
        return violations;
    }

    /** Convenience: run with the default (strict) policy. */
    public static List<PolicyViolation> checkPolicy(SslTlsAuditor.AuditResult result) {
        return checkPolicy(result, defaultPolicy());
    }

    // ── Reporting ──────────────────────────────────────────────────────────────

    /** Formats the policy check results into a human-readable report. */
    public static String formatReport(List<PolicyViolation> violations, String host) {
        StringBuilder sb = new StringBuilder();
        sb.append("TLS Policy Report — ").append(host).append(System.lineSeparator());
        sb.append("─".repeat(60)).append(System.lineSeparator());

        if (violations.isEmpty()) {
            sb.append("✅ All TLS policy rules passed.").append(System.lineSeparator());
            return sb.toString().trim();
        }

        sb.append(String.format("⚠ %d policy violation(s) detected:%n%n", violations.size()));
        for (PolicyViolation v : violations) {
            String icon = switch (v.severity()) {
                case "CRITICAL" -> "[CRITICAL]";
                case "HIGH"     -> "[HIGH]    ";
                case "MEDIUM"   -> "[MEDIUM]  ";
                default         -> "[LOW]     ";
            };
            String rule = v.rule() != null ? v.rule().name() : "CONNECTION";
            sb.append(String.format("  %s [%s]%n", icon, rule));
            sb.append("     ").append(v.description()).append(System.lineSeparator());
            sb.append(System.lineSeparator());
        }

        long critical = violations.stream().filter(v -> "CRITICAL".equals(v.severity())).count();
        long high     = violations.stream().filter(v -> "HIGH".equals(v.severity())).count();
        long medium   = violations.stream().filter(v -> "MEDIUM".equals(v.severity())).count();
        sb.append(String.format("Summary: %d CRITICAL  %d HIGH  %d MEDIUM%n",
                critical, high, medium));
        return sb.toString().trim();
    }

    // ── internals ──────────────────────────────────────────────────────────────

    private static int severityOrder(String s) {
        return switch (s) {
            case "CRITICAL" -> 0;
            case "HIGH"     -> 1;
            case "MEDIUM"   -> 2;
            default         -> 3;
        };
    }
}
