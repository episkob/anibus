package it.r2u.anibus.service.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import it.r2u.anibus.model.PortRegistry;
import it.r2u.anibus.model.ScanContext;
import it.r2u.anibus.service.network.VersionExtractor;
import it.r2u.anibus.service.network.proxy.ProxyConnectionFactory;

/**
 * Thin coordinator: connection probing and port-range parsing.
 * Delegates banner grabbing to BannerGrabber, version extraction
 * to VersionExtractor, and service lookup to PortRegistry.
 * 
 * This service implements the "Standard Scanning" mode which performs:
 * - Basic TCP connection probing to detect open ports
 * - Latency measurement for each connection attempt
 * - Banner grabbing from responsive services
 * - Service name and protocol identification via PortRegistry
 * - Version detection from banners when available
 */
public class PortScannerService {

    private static final int TIMEOUT = 200;
    /** Extended timeout for retry pass (stateful firewalls often drop first SYN). */
    private static final int TIMEOUT_RETRY = 800;
    /** Small jitter delay before retry to defeat naive rate-limit windows. */
    private static final int RETRY_BACKOFF_MS = 120;
    private final BannerGrabber bannerGrabber;
    private final ProxyConnectionFactory proxyFactory;
    /**
     * Stealth source port: when &gt; 0 the scanner binds the local socket to this
     * port, which can slip past basic origin-port firewall rules (e.g. allow
     * 53/80/443 source traffic). Requires privileges for ports &lt; 1024;
     * silently falls back to ephemeral on bind failure.
     */
    private volatile int stealthSourcePort = 0;
    /** When true, perform one retry pass with a longer timeout on initial failure. */
    private volatile boolean retryOnDrop = true;

    public PortScannerService() {
        this(new BannerGrabber(TIMEOUT), new ProxyConnectionFactory());
    }

    public PortScannerService(BannerGrabber bannerGrabber) {
        this(bannerGrabber, new ProxyConnectionFactory());
    }

    public PortScannerService(BannerGrabber bannerGrabber, ProxyConnectionFactory proxyFactory) {
        this.bannerGrabber  = bannerGrabber;
        this.proxyFactory   = proxyFactory;
    }

    /* -- Port-range parsing ----------------------------------- */
    public int[] parsePortsRange(String portsRange) {
        if (portsRange == null || portsRange.isBlank()) return null;
        Matcher m = Pattern.compile("(\\d+)-(\\d+)").matcher(portsRange);
        if (!m.find()) {
            Matcher single = Pattern.compile("^\\s*(\\d+)\\s*$").matcher(portsRange);
            if (!single.find()) return null;
            try {
                int port = Integer.parseInt(single.group(1));
                return (port < 1 || port > 65535) ? null : new int[]{port, port};
            } catch (NumberFormatException e) {
                return null;
            }
        }
        try {
            int start = Integer.parseInt(m.group(1));
            int end   = Integer.parseInt(m.group(2));
            return (start < 1 || end > 65535 || start > end) ? null : new int[]{start, end};
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /* -- Latency probe: returns ms, or -1 if closed ----------- */
    public long measurePortLatency(String host, int port) {
        long first = tryConnect(host, port, TIMEOUT);
        if (first >= 0 || !retryOnDrop) return first;
        // First SYN may have been dropped by a stateful firewall / rate limiter.
        // Back off briefly and retry with a longer timeout once.
        try { Thread.sleep(RETRY_BACKOFF_MS); }
        catch (InterruptedException ie) { Thread.currentThread().interrupt(); return -1; }
        return tryConnect(host, port, TIMEOUT_RETRY);
    }

    /** Single TCP-connect attempt; honours {@link #stealthSourcePort} bind hint. */
    private long tryConnect(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            int srcPort = stealthSourcePort;
            if (srcPort > 0) {
                try { socket.bind(new InetSocketAddress(srcPort)); }
                catch (IOException ignored) { /* port in use / no privilege — fall back to ephemeral */ }
            }
            long start = System.nanoTime();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return (System.nanoTime() - start) / 1_000_000;
        } catch (IOException e) {
            return -1;
        }
    }

    /** Enable/disable retry-on-drop evasion (on by default). */
    public void setRetryOnDrop(boolean enabled) { this.retryOnDrop = enabled; }

    /**
     * Set local source port for probes (0 = ephemeral, default). Try 53, 80 or 443
     * to slip past simple firewalls that allow traffic from these source ports.
     */
    public void setStealthSourcePort(int sourcePort) {
        this.stealthSourcePort = (sourcePort >= 0 && sourcePort < 65536) ? sourcePort : 0;
    }

    public boolean isPortOpen(String host, int port) {
        return measurePortLatency(host, port) >= 0;
    }

    // ── Proxy-aware variants (ScanContext overloads) ────────────────────────

    /**
     * Measure port latency routing through the proxy in {@code context}.
     * Falls back to a direct connection if proxy is disabled or absent.
     * Returns -1 if the port is closed or the proxy fails.
     */
    public long measurePortLatency(ScanContext context, int port) {
        if (!context.proxyEnabled() || context.activeProxy().isEmpty()) {
            return measurePortLatency(context.targetHost(), port);
        }
        try {
            long start = System.nanoTime();
            proxyFactory.createSocket(context, context.targetHost(), port).close();
            return (System.nanoTime() - start) / 1_000_000;
        } catch (IOException e) {
            return -1;
        }
    }

    /**
     * Check whether a port is open, routing through the proxy in {@code context}.
     */
    public boolean isPortOpen(ScanContext context, int port) {
        return measurePortLatency(context, port) >= 0;
    }

    /* -- Delegates -------------------------------------------- */
    public String getBanner(String host, int port)     { return bannerGrabber.grab(host, port); }
    public String getServiceName(int port)             { return PortRegistry.getServiceName(port); }
    public String getProtocol(int port, String banner) { return PortRegistry.getProtocol(port, banner); }
    public String extractVersion(String banner)        { return VersionExtractor.extract(banner); }
}
