package it.r2u.anibus.service.network.proxy;

import java.net.InetSocketAddress;
import java.net.Proxy;

/**
 * Immutable model of a single proxy node.
 * latencyMs = -1 means "not yet measured / failed".
 * countryCode = "XX" means "unknown country".
 */
public record ProxyNode(
        String host,
        int port,
        ProxyType type,
        String countryCode,
        long latencyMs
) {
    /** Convert to java.net.Proxy for use in HttpURLConnection and Socket. */
    public Proxy toJavaProxy() {
        Proxy.Type javaType = (type == ProxyType.SOCKS5) ? Proxy.Type.SOCKS : Proxy.Type.HTTP;
        return new Proxy(javaType, new InetSocketAddress(host, port));
    }

    /** Return a copy with updated latency. */
    public ProxyNode withLatency(long latencyMs) {
        return new ProxyNode(host, port, type, countryCode, latencyMs);
    }

    /** Return a copy with a resolved country code. */
    public ProxyNode withCountry(String countryCode) {
        return new ProxyNode(host, port, type, countryCode, latencyMs);
    }

    public boolean isAlive() {
        return latencyMs >= 0;
    }

    @Override
    public String toString() {
        return String.format("%s:%d [%s, country=%s, latency=%dms]",
                host, port, type, countryCode, latencyMs);
    }
}
