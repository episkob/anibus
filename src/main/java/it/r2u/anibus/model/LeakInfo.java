package it.r2u.anibus.model;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a discovered sensitive information leak (credential, API key, connection string, etc.).
 * Immutable value object — all mutations return a new instance.
 */
public final class LeakInfo {

    private static final Set<String> PLACEHOLDER_EXACT = Set.of(
            "password", "123456", "12345678", "qwerty", "test", "example",
            "placeholder", "xxx", "null", "undefined", "your_password",
            "your_api_key", "changeme", "secret", "default", "sample",
            "incorrect_password", "wrong_password", "invalid_password",
            "enter_password", "type_password", "your_secret", "my_password",
            "admin", "root", "guest", "user", "pass", "pwd"
    );

    private static final Pattern CREDENTIAL_PATTERN = Pattern.compile(
            "(?:pass(?:word)?|pwd|secret)\\s*[:=]\\s*([^|,;\\s]+)",
            Pattern.CASE_INSENSITIVE
    );

    private final String type;
    private final String value;
    private final String context;
    private final int priority;
    private final int count;
    private final String service;
    private final boolean placeholder;

    /** Full constructor — all fields explicit. */
    public LeakInfo(String type, String value, String context,
                    int priority, String service, boolean placeholder) {
        this(type, value, context, priority, service, placeholder, 1);
    }

    /** Convenience constructor — priority and placeholder inferred from type/value. */
    public LeakInfo(String type, String value, String context) {
        this(type, value, context, inferPriority(type), null, isPlaceholderValue(value), 1);
    }

    private LeakInfo(String type, String value, String context,
                     int priority, String service, boolean placeholder, int count) {
        this.type        = type;
        this.value       = value;
        this.context     = context;
        this.priority    = priority;
        this.service     = service;
        this.placeholder = placeholder;
        this.count       = count;
    }

    /** Returns an immutable copy with updated occurrence count (deduplication). */
    public LeakInfo withCount(int newCount) {
        return new LeakInfo(type, value, context, priority, service, placeholder, newCount);
    }

    /** Returns an immutable copy tagged with a microservice name. */
    public LeakInfo withService(String svc) {
        return new LeakInfo(type, value, context, priority, svc, placeholder, count);
    }

    public String  getType()        { return type; }
    public String  getValue()       { return value; }
    public String  getContext()     { return context; }
    public int     getPriority()    { return priority; }
    public int     getCount()       { return count; }
    public String  getService()     { return service; }
    public boolean isPlaceholder()  { return placeholder; }

    @Override
    public String toString() {
        return type + ": " + value;
    }

    // ── Static helpers ─────────────────────────────────────────────────────────

    /** Maps a finding-type label to a numeric priority 1–10. */
    public static int inferPriority(String type) {
        if (type == null) return 5;
        String t = type.toLowerCase();
        if (t.contains("private key") || t.contains("connection with credentials")) return 10;
        if (t.contains("access token") || t.contains("aws access key") || t.contains("jwt")) return 9;
        if (t.contains("database password") || t.contains("kv pair"))                         return 8;
        if (t.contains("api key") || t.contains("firebase") || t.contains("password"))        return 7;
        if (t.contains("public key") || t.contains("certificate")
                || t.contains("token→endpoint") || t.contains("graphql"))                     return 6;
        if (t.contains("database host") || t.contains("database configuration")
                || t.contains("orm") || t.contains("sequelize"))                              return 5;
        if (t.contains("database name") || t.contains("connection string")
                || t.contains("cloud database"))                                               return 4;
        if (t.contains("environment variable") || t.contains("connection reference"))         return 2;
        return 3;
    }

    /** Returns {@code true} when the value looks like a known placeholder / test value. */
    public static boolean isPlaceholderValue(String value) {
        if (value == null || value.isBlank()) return false;
        String v = value.toLowerCase().trim();

        // Strip "[Priority N] " prefix added by DB analyzer
        if (v.startsWith("[priority")) {
            int end = v.indexOf(']');
            if (end > 0) v = v.substring(end + 1).trim();
        }

        if (PLACEHOLDER_EXACT.contains(v)) return true;

        // Handle composite values like "Username: admin | Password: incorrect_password"
        Matcher m = CREDENTIAL_PATTERN.matcher(v);
        while (m.find()) {
            String extracted = m.group(1);
            if (extracted != null) {
                String normalized = extracted.toLowerCase()
                        .replaceAll("^[\"'`]+|[\"'`,;]+$", "");
                if (PLACEHOLDER_EXACT.contains(normalized)) return true;
                if (normalized.startsWith("incorrect_") || normalized.startsWith("wrong_")
                        || normalized.startsWith("invalid_") || normalized.startsWith("enter_")
                        || normalized.startsWith("your_") || normalized.startsWith("test_")) {
                    return true;
                }
            }
        }

        return v.startsWith("incorrect_") || v.startsWith("wrong_")
                || v.startsWith("invalid_") || v.startsWith("enter_")
                || v.startsWith("your_") || v.startsWith("test_")
                || v.length() < 3;
    }
}
