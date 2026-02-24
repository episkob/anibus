package it.r2u.anibus.service;

import it.r2u.anibus.model.PortRegistry;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
    private final BannerGrabber bannerGrabber = new BannerGrabber(TIMEOUT);

    /* -- Port-range parsing ----------------------------------- */
    public int[] parsePortsRange(String portsRange) {
        Matcher m = Pattern.compile("(\\d+)-(\\d+)").matcher(portsRange);
        if (!m.find()) return null;
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
        try (Socket socket = new Socket()) {
            long start = System.nanoTime();
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);
            return (System.nanoTime() - start) / 1_000_000;
        } catch (IOException e) {
            return -1;
        }
    }

    public boolean isPortOpen(String host, int port) {
        return measurePortLatency(host, port) >= 0;
    }

    /* -- Delegates -------------------------------------------- */
    public String getBanner(String host, int port)     { return bannerGrabber.grab(host, port); }
    public String getServiceName(int port)             { return PortRegistry.getServiceName(port); }
    public String getProtocol(int port, String banner) { return PortRegistry.getProtocol(port, banner); }
    public String extractVersion(String banner)        { return VersionExtractor.extract(banner); }
}
