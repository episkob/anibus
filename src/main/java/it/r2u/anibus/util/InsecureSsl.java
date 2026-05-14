package it.r2u.anibus.util;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Shared trust-all SSL utilities used by scanner detection probes.
 *
 * <p><b>Security:</b> This intentionally disables certificate verification so the scanner
 * can audit internal / self-signed / misconfigured TLS endpoints (Keycloak behind reverse
 * proxy, internal IAM portals, CTF labs, etc.). It is <i>not</i> used for outbound calls
 * that handle user data — only for read-only fingerprinting where the scanner explicitly
 * wants to see what the target presents.</p>
 *
 * <p>Replaces the duplicated TrustAllSsl / TRUST_ALL_FACTORY blocks previously inlined in
 * {@code KeycloakDetector}, {@code IdentityProviderDetector}, and {@code SqlMetadataExtractor}.</p>
 */
public final class InsecureSsl {

    /** Hostname verifier that accepts any hostname. */
    public static final HostnameVerifier ACCEPT_ALL_HOSTNAMES = (hostname, session) -> true;

    private static final SSLSocketFactory SOCKET_FACTORY;
    private static final SSLContext SSL_CONTEXT;

    static {
        try {
            TrustManager[] trustAll = {
                new X509TrustManager() {
                    @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    @Override public void checkClientTrusted(X509Certificate[] c, String a) { /* trust all */ }
                    @Override public void checkServerTrusted(X509Certificate[] c, String a) { /* trust all */ }
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new SecureRandom());
            SSL_CONTEXT = ctx;
            SOCKET_FACTORY = ctx.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException ex) {
            throw new IllegalStateException("Failed to initialise trust-all SSLContext", ex);
        }
    }

    private InsecureSsl() { /* no instances */ }

    /** @return shared {@link SSLSocketFactory} that trusts any certificate. */
    public static SSLSocketFactory socketFactory() {
        return SOCKET_FACTORY;
    }

    /** @return shared {@link SSLContext} preconfigured with trust-all manager. */
    public static SSLContext sslContext() {
        return SSL_CONTEXT;
    }

    /**
     * Applies trust-all socket factory and hostname verifier to an {@link HttpsURLConnection}.
     * No-op if {@code conn} is {@code null}.
     */
    public static void apply(HttpsURLConnection conn) {
        if (conn == null) return;
        conn.setSSLSocketFactory(SOCKET_FACTORY);
        conn.setHostnameVerifier(ACCEPT_ALL_HOSTNAMES);
    }
}
