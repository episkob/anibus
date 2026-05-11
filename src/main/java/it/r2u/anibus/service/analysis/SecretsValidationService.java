package it.r2u.anibus.service.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import it.r2u.anibus.model.LeakInfo;

/**
 * Validates discovered secrets/keys against known provider formats.
 *
 * <p>All checks are purely structural (regex). No network call is made,
 * so there is zero risk of inadvertently transmitting the secret.
 *
 * <p>Supported providers: AWS, GitHub, Stripe, Telegram, Slack, Google, JWT, Generic.
 */
public class SecretsValidationService {

    /** A single validation verdict for one candidate value. */
    public record ValidationResult(
        String value,
        String provider,
        String keyType,
        boolean valid,
        String matchedPattern,
        String advice
    ) {}

    // ── Pattern definitions ──────────────────────────────────────────────────

    private static final List<Rule> RULES = List.of(
        new Rule("AWS",      "Access Key ID",
            Pattern.compile("AKIA[0-9A-Z]{16}"),
            "Rotate immediately via IAM console. Check CloudTrail for unauthorized activity."),

        new Rule("AWS",      "Secret Access Key",
            Pattern.compile("[0-9a-zA-Z/+]{40}"),
            "Only flag if co-located with an Access Key ID. Rotate via IAM."),

        new Rule("GitHub",   "Personal Access Token (classic)",
            Pattern.compile("ghp_[A-Za-z0-9]{36}"),
            "Revoke at github.com/settings/tokens and audit recent API activity."),

        new Rule("GitHub",   "Fine-grained PAT",
            Pattern.compile("github_pat_[A-Za-z0-9_]{82}"),
            "Revoke at github.com/settings/tokens/granular."),

        new Rule("GitHub",   "App Token",
            Pattern.compile("ghs_[A-Za-z0-9]{36}"),
            "Revoke GitHub App installation token via GitHub App settings."),

        new Rule("GitHub",   "OAuth Token",
            Pattern.compile("gho_[A-Za-z0-9]{36}"),
            "Revoke OAuth token via github.com/settings/applications."),

        new Rule("Stripe",   "Live Secret Key",
            Pattern.compile("sk_live_[0-9a-zA-Z]{24,}"),
            "CRITICAL: rotate immediately at dashboard.stripe.com/apikeys."),

        new Rule("Stripe",   "Test Secret Key",
            Pattern.compile("sk_test_[0-9a-zA-Z]{24,}"),
            "Rotate test key — should not appear in production code."),

        new Rule("Stripe",   "Restricted Key",
            Pattern.compile("rk_live_[0-9a-zA-Z]{24,}"),
            "Rotate at dashboard.stripe.com/apikeys."),

        new Rule("Telegram", "Bot Token",
            Pattern.compile("\\d{8,10}:[A-Za-z0-9_-]{35}"),
            "Revoke via @BotFather /revoke command."),

        new Rule("Slack",    "Bot/App Token",
            Pattern.compile("xox[baprs]-[0-9]+-[0-9A-Za-z-]+"),
            "Revoke at api.slack.com/apps under OAuth & Permissions."),

        new Rule("Google",   "API Key",
            Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"),
            "Restrict or rotate at console.cloud.google.com/apis/credentials."),

        new Rule("Google",   "Service Account Key (JSON field)",
            Pattern.compile("\"private_key\"\\s*:\\s*\"-----BEGIN"),
            "Remove from code, rotate key in GCP IAM."),

        new Rule("JWT",      "JSON Web Token",
            Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*"),
            "Tokens should not persist in source code. Check exp and aud claims."),

        new Rule("Generic",  "Private Key (PEM)",
            Pattern.compile("-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "Remove private key material from source/config immediately."),

        new Rule("Generic",  "Generic High-Entropy Token",
            Pattern.compile("[A-Za-z0-9+/]{40,}={0,2}"),
            "Possible base64 secret. Review context to determine provider.")
    );

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Validates all non-placeholder LeakInfo values against known secret patterns.
     *
     * @param leaks List of LeakInfo from JS/source map analysis
     * @return Validation results for matched entries (one per rule that matched)
     */
    public List<ValidationResult> validate(List<LeakInfo> leaks) {
        List<ValidationResult> out = new ArrayList<>();
        if (leaks == null || leaks.isEmpty()) {
            return out;
        }
        for (LeakInfo leak : leaks) {
            if (leak.isPlaceholder()) {
                continue;
            }
            String value = leak.getValue();
            if (value == null || value.isBlank()) {
                continue;
            }
            validateValue(value, out);
        }
        return out;
    }

    /**
     * Validates raw candidate strings (e.g., scraped from console text).
     *
     * @param candidates raw string values to check
     * @return matched validation results
     */
    public List<ValidationResult> validateRaw(List<String> candidates) {
        List<ValidationResult> out = new ArrayList<>();
        for (String candidate : candidates) {
            if (candidate == null || candidate.isBlank()) {
                continue;
            }
            validateValue(candidate, out);
        }
        return out;
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private void validateValue(String value, List<ValidationResult> out) {
        boolean anyMatched = false;
        for (Rule rule : RULES) {
            if (rule.pattern().matcher(value).find()) {
                // Skip generic high-entropy if a more specific rule already matched
                if (anyMatched && "Generic".equals(rule.provider())
                        && "Generic High-Entropy Token".equals(rule.keyType())) {
                    continue;
                }
                out.add(new ValidationResult(
                    truncate(value, 80),
                    rule.provider(),
                    rule.keyType(),
                    true,
                    rule.pattern().pattern(),
                    rule.advice()
                ));
                anyMatched = true;
            }
        }
    }

    private static String truncate(String s, int max) {
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max) + "…";
    }

    // ── Report formatter ─────────────────────────────────────────────────────

    public static String formatReport(List<ValidationResult> results, String source) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("      SECRETS VALIDATION — ").append(source).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (results.isEmpty()) {
            sb.append("  No secrets matched known provider patterns.\n");
            return sb.toString();
        }

        long confirmed = results.stream().filter(ValidationResult::valid).count();
        sb.append(String.format(Locale.ROOT,
            "  Matched: %d result(s) across %d unique providers\n\n",
            confirmed,
            results.stream().map(ValidationResult::provider).distinct().count()));

        String currentProvider = null;
        for (ValidationResult r : results.stream()
                .sorted((a, b) -> a.provider().compareToIgnoreCase(b.provider()))
                .toList()) {
            if (!r.provider().equals(currentProvider)) {
                currentProvider = r.provider();
                sb.append("  ── ").append(currentProvider).append(" ──\n");
            }
            sb.append("  [").append(r.keyType()).append("]\n");
            sb.append("    Value  : ").append(r.value()).append("\n");
            sb.append("    Status : ").append(r.valid() ? "✓ FORMAT VALID" : "? Partial match").append("\n");
            sb.append("    Advice : ").append(r.advice()).append("\n\n");
        }
        return sb.toString();
    }

    // ── Internal rule record ─────────────────────────────────────────────────

    private record Rule(String provider, String keyType, Pattern pattern, String advice) {}
}
