package it.r2u.anibus.service.analysis;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import it.r2u.anibus.model.LeakInfo;

/**
 * Heuristic executive-summary generator for the JS Analysis module.
 *
 * <p>Takes a list of {@link LeakInfo} findings and produces a short, human-readable
 * narrative (English or Russian) that summarises:
 * <ul>
 *   <li>total / placeholder count</li>
 *   <li>distribution by priority bucket (critical / high / medium / low)</li>
 *   <li>top finding types by frequency</li>
 *   <li>top 3 highest-risk individual findings (via {@link LeakInfo#riskScore()})</li>
 *   <li>concrete, action-oriented recommendations tailored to the types found</li>
 * </ul>
 *
 * <p>No external LLM is used — all output is generated locally from rules.
 * The class is intentionally minimal so it can be unit-tested offline.
 */
public final class AiSummaryGenerator {

    /** Output language. */
    public enum Lang { EN, RU }

    private AiSummaryGenerator() {}

    /** Generates the executive summary in the requested language. */
    public static String generate(List<LeakInfo> findings, Lang lang) {
        if (findings == null) findings = List.of();
        StringBuilder sb = new StringBuilder();

        // ── 1. Headline ─────────────────────────────────────────────────────
        int total = findings.size();
        long real = findings.stream().filter(f -> !f.isPlaceholder()).count();
        long placeholders = total - real;
        int critical = countAtLeast(findings, 8);
        int high     = countBucket(findings, 6, 8);
        int medium   = countBucket(findings, 4, 6);
        int low      = countBucket(findings, 1, 4);

        if (lang == Lang.RU) {
            sb.append("=== AI Executive Summary (JS Analysis) ===\n");
            sb.append("Всего находок: ").append(total)
              .append(" (реальных: ").append(real)
              .append(", плейсхолдеров: ").append(placeholders).append(")\n");
            sb.append("Распределение: критичных=").append(critical)
              .append(", высоких=").append(high)
              .append(", средних=").append(medium)
              .append(", низких=").append(low).append("\n");
        } else {
            sb.append("=== AI Executive Summary (JS Analysis) ===\n");
            sb.append("Total findings: ").append(total)
              .append(" (real: ").append(real)
              .append(", placeholders: ").append(placeholders).append(")\n");
            sb.append("By severity: critical=").append(critical)
              .append(", high=").append(high)
              .append(", medium=").append(medium)
              .append(", low=").append(low).append("\n");
        }

        if (total == 0) {
            sb.append(lang == Lang.RU
                ? "Никаких подозрительных строк не обнаружено. Это не означает, что приложение безопасно — рекомендуется provести активный скан.\n"
                : "No suspicious strings discovered. This does not mean the app is safe — consider an active scan.\n");
            return sb.toString();
        }

        // ── 2. Top types ────────────────────────────────────────────────────
        Map<String, Integer> byType = new LinkedHashMap<>();
        for (LeakInfo f : findings) {
            byType.merge(f.getType() == null ? "(unknown)" : f.getType(), 1, Integer::sum);
        }
        List<Map.Entry<String, Integer>> topTypes = byType.entrySet().stream()
                .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
                .limit(5)
                .toList();
        sb.append(lang == Lang.RU ? "\nЧастые категории:\n" : "\nMost frequent categories:\n");
        for (Map.Entry<String, Integer> e : topTypes) {
            sb.append("  • ").append(e.getKey()).append(" — ").append(e.getValue()).append("\n");
        }

        // ── 3. Top risk findings ────────────────────────────────────────────
        List<LeakInfo> topRisk = new ArrayList<>(findings);
        topRisk.sort(Comparator.comparingDouble(LeakInfo::riskScore).reversed());
        sb.append(lang == Lang.RU ? "\nТоп-3 по риску:\n" : "\nTop 3 highest-risk findings:\n");
        for (int i = 0; i < Math.min(3, topRisk.size()); i++) {
            LeakInfo f = topRisk.get(i);
            sb.append("  ").append(i + 1).append(". [risk=").append(String.format(Locale.ROOT, "%.1f", f.riskScore()))
              .append("] ").append(f.getType());
            if (f.getService() != null && !f.getService().isBlank()) {
                sb.append(" @").append(f.getService());
            }
            sb.append(": ").append(truncate(f.getValue(), 60)).append("\n");
        }

        // ── 4. Recommendations ──────────────────────────────────────────────
        sb.append(lang == Lang.RU ? "\nРекомендации:\n" : "\nRecommendations:\n");
        List<String> recs = buildRecommendations(byType.keySet(), critical, placeholders, lang);
        for (String r : recs) sb.append("  → ").append(r).append("\n");

        return sb.toString();
    }

    /** Default English summary. */
    public static String generate(List<LeakInfo> findings) {
        return generate(findings, Lang.EN);
    }

    private static int countAtLeast(List<LeakInfo> findings, int minPriority) {
        return (int) findings.stream().filter(f -> f.getPriority() >= minPriority).count();
    }

    private static int countBucket(List<LeakInfo> findings, int minIncl, int maxExcl) {
        return (int) findings.stream()
                .filter(f -> f.getPriority() >= minIncl && f.getPriority() < maxExcl)
                .count();
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private static List<String> buildRecommendations(java.util.Set<String> types, int critical,
                                                     long placeholders, Lang lang) {
        List<String> out = new ArrayList<>();
        boolean hasKey = types.stream().anyMatch(t -> t != null && t.toLowerCase(Locale.ROOT).contains("key"));
        boolean hasToken = types.stream().anyMatch(t -> t != null && t.toLowerCase(Locale.ROOT).contains("token"));
        boolean hasPwd = types.stream().anyMatch(t -> t != null
                && (t.toLowerCase(Locale.ROOT).contains("password") || t.toLowerCase(Locale.ROOT).contains("secret")));
        boolean hasUrl = types.stream().anyMatch(t -> t != null
                && (t.toLowerCase(Locale.ROOT).contains("url") || t.toLowerCase(Locale.ROOT).contains("endpoint")));

        if (critical > 0) {
            out.add(lang == Lang.RU
                ? "Немедленно ротировать все скомпрометированные секреты с критичной приоритизацией."
                : "Immediately rotate all critically-priority secrets that may be compromised.");
        }
        if (hasKey || hasToken) {
            out.add(lang == Lang.RU
                ? "Вынести API-ключи и токены из клиентского кода — использовать прокси/BFF на сервере."
                : "Move API keys and tokens out of client-side code — use a server-side BFF/proxy instead.");
        }
        if (hasPwd) {
            out.add(lang == Lang.RU
                ? "Любой пароль в исходниках считается утечкой; запретить хранение строк password/secret в коде."
                : "Any password in source code counts as a leak; ban storing password/secret literals in code.");
        }
        if (hasUrl) {
            out.add(lang == Lang.RU
                ? "Проверить внутренние endpoint-ы на аутентификацию и rate-limit; они могут быть скрытым API."
                : "Audit internal endpoints for auth and rate-limit; they may be a hidden API surface.");
        }
        if (placeholders > 0) {
            out.add(lang == Lang.RU
                ? "Плейсхолдеры (" + placeholders + ") отфильтрованы автоматически — не считаются находками."
                : "Placeholders (" + placeholders + ") were auto-filtered and do not count as findings.");
        }
        out.add(lang == Lang.RU
            ? "Добавить SAST/secret-scan в CI, чтобы предотвратить повторное появление утечек."
            : "Add SAST / secret-scanning to CI to prevent leaks from coming back.");
        return out;
    }
}
