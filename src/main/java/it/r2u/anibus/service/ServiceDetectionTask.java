package it.r2u.anibus.service;

import it.r2u.anibus.model.PortScanResult;

import javafx.application.Platform;
import javafx.concurrent.Task;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * Enhanced scanning task that performs deep service detection with:
 * - Multiple service-specific probes
 * - Enhanced banner analysis
 * - Protocol fingerprinting
 * - Real-time service identification
 */
public class ServiceDetectionTask extends Task<Void> {

    public interface Callbacks {
        void onHostResolved(String ip);
        void onScanStarted(String ip, String hostname, int totalPorts);
        void onResult(PortScanResult result);
        void onStatus(String message);
        void onSubnetDetected(String subnet, String gateway);
        void onCompleted();
        void onCancelled();
        void onFailed(String error);
    }

    private final String host;
    private final int startPort;
    private final int endPort;
    private final int threadCount;
    private final EnhancedServiceDetector detector;
    private final SubnetScanner subnetScanner;
    private final Callbacks callbacks;
    private ExecutorService executor;

    public ServiceDetectionTask(String host, int startPort, int endPort, int threadCount,
                               EnhancedServiceDetector detector, Callbacks callbacks) {
        this.host        = host;
        this.startPort   = startPort;
        this.endPort     = endPort;
        this.threadCount = threadCount;
        this.detector    = detector;
        this.subnetScanner = new SubnetScanner();
        this.callbacks   = callbacks;
    }

    @Override
    protected Void call() throws Exception {
        int totalPorts = endPort - startPort + 1;
        try {
            InetAddress addr = InetAddress.getByName(host);
            String ip        = addr.getHostAddress();
            String hostname  = addr.getCanonicalHostName();

            Platform.runLater(() -> callbacks.onHostResolved(ip));
            
            // Detect subnet information
            detectSubnetInfo(ip);
            
            callbacks.onScanStarted(ip, hostname, totalPorts);
            callbacks.onStatus("Service Detection: Scanning " + host + " (" + ip + ") — ports " + startPort + "–" + endPort);

            CountDownLatch latch = new CountDownLatch(totalPorts);
            ThreadFactory daemon = r -> { Thread t = new Thread(r); t.setDaemon(true); return t; };
            executor = Executors.newFixedThreadPool(threadCount, daemon);

            for (int port = startPort; port <= endPort; port++) {
                if (isCancelled()) break;
                final int p = port;
                executor.submit(() -> {
                    try {
                        // Enhanced service detection
                        PortScanResult result = detector.detectService(ip, p);
                        if (result != null) {
                            Platform.runLater(() -> {
                                callbacks.onResult(result);
                                String service = result.getService();
                                // Highlight security services in status message
                                if (service.contains("[") && service.contains("]")) {
                                    callbacks.onStatus("[SECURITY] Security detected: " + service + " on port " + p);
                                } else {
                                    callbacks.onStatus("Detected: " + service + " on port " + p);
                                }
                            });
                        }
                    } finally {
                        latch.countDown();
                        updateProgress(totalPorts - latch.getCount(), totalPorts);
                    }
                });
            }
            latch.await();
        } catch (UnknownHostException e) {
            callbacks.onStatus("Error: unknown host " + host);
            throw e;
        } finally {
            shutdown();
        }
        return null;
    }

    private void detectSubnetInfo(String ip) {
        try {
            String subnet = subnetScanner.detectSubnet(ip);
            String gateway = subnetScanner.detectGateway(ip);
            if (subnet != null || gateway != null) {
                Platform.runLater(() -> callbacks.onSubnetDetected(
                    subnet != null ? subnet : "Unknown", 
                    gateway != null ? gateway : "Unknown"
                ));
            }
        } catch (Exception e) {
            // Subnet detection is optional, don't fail the scan
        }
    }

    @Override protected void succeeded() { super.succeeded(); callbacks.onCompleted(); }
    @Override protected void cancelled() { super.cancelled(); callbacks.onCancelled(); }
    @Override protected void failed()    { super.failed();    callbacks.onFailed(getException().getMessage()); }

    public void shutdown() {
        if (executor != null && !executor.isShutdown()) executor.shutdownNow();
    }
}
