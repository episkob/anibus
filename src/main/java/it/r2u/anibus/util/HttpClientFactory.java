package it.r2u.anibus.util;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.time.Duration;

import javax.net.ssl.HttpsURLConnection;

/**
 * Centralised HTTP connection factory.
 *
 * <p>Replaces the pattern of every detector / analyzer building its own
 * {@code HttpURLConnection} with hard-coded timeouts, repeating user-agent strings,
 * and re-implementing trust-all SSL.</p>
 *
 * <p>Goals:</p>
 * <ul>
 *   <li>Single source of truth for timeouts ({@link TimeoutProfile}).</li>
 *   <li>Uniform trust-all TLS via {@link InsecureSsl}.</li>
 *   <li>Single point to wire proxy/rate-limit/retry in the future.</li>
 * </ul>
 *
 * <p>Not a {@code java.net.http.HttpClient} replacement — kept as a thin facade over
 * {@link HttpURLConnection} so existing call-sites can migrate incrementally without
 * a full async rewrite.</p>
 */
public final class HttpClientFactory {

    /** Default User-Agent string used by the scanner. */
    public static final String DEFAULT_USER_AGENT =
            "Mozilla/5.0 (compatible; Anibus-Scanner/2.2)";

    /**
     * Timeout profiles for different scan phases.
     * Centralises the previously scattered 2 s / 4 s / 5 s / 10 s magic numbers.
     */
    public enum TimeoutProfile {
        /** Fast probe (port/HTTP ping). */
        FAST(Duration.ofSeconds(2), Duration.ofSeconds(2)),
        /** Normal detection request (default). */
        NORMAL(Duration.ofSeconds(5), Duration.ofSeconds(5)),
        /** Slow analysis call (full-page download, SQL/SSRF probes). */
        SLOW(Duration.ofSeconds(10), Duration.ofSeconds(10)),
        /** Very slow operation (large source map / certificate chain walk). */
        VERY_SLOW(Duration.ofSeconds(20), Duration.ofSeconds(30));

        public final Duration connect;
        public final Duration read;
        TimeoutProfile(Duration connect, Duration read) {
            this.connect = connect;
            this.read = read;
        }
    }

    private HttpClientFactory() { /* no instances */ }

    /**
     * Opens an HTTP(S) connection with {@link TimeoutProfile#NORMAL} timeouts,
     * trust-all SSL for HTTPS, and the default User-Agent.
     *
     * @param url absolute URL
     * @return configured {@link HttpURLConnection} (caller must call {@code connect()} / read)
     */
    public static HttpURLConnection open(String url) throws IOException {
        return open(url, TimeoutProfile.NORMAL);
    }

    /**
     * Opens an HTTP(S) connection with the given timeout profile.
     */
    public static HttpURLConnection open(String url, TimeoutProfile profile) throws IOException {
        if (url == null || url.isBlank()) {
            throw new IOException("URL must not be blank");
        }
        HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
        } catch (IllegalArgumentException ex) {
            throw new IOException("Invalid URL: " + url, ex);
        }
        TimeoutProfile p = profile != null ? profile : TimeoutProfile.NORMAL;
        conn.setConnectTimeout((int) p.connect.toMillis());
        conn.setReadTimeout((int) p.read.toMillis());
        conn.setRequestProperty("User-Agent", DEFAULT_USER_AGENT);
        conn.setInstanceFollowRedirects(true);
        if (conn instanceof HttpsURLConnection https) {
            InsecureSsl.apply(https);
        }
        return conn;
    }
}
