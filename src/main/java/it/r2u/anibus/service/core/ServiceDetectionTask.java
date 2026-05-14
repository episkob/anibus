package it.r2u.anibus.service.core;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.detection.EnhancedServiceDetector;
import it.r2u.anibus.service.network.CloudMetadataProbe;
import it.r2u.anibus.service.network.ReverseDnsExpander;
import it.r2u.anibus.service.network.SubnetScanner;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.concurrent.Task;

/**
 * Enhanced scanning task that performs deep service detection with:
 * - Multiple service-specific probes
 * - Enhanced banner analysis
 * - Protocol fingerprinting
 * - Real-time service identification
 * - Cloud metadata probing (IMDS)
 * - /24 reverse-DNS neighbor expansion
 *
 * Uses virtual threads and a CompletableFuture pipeline so each open port
 * triggers detection independently without blocking other probes.
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

        /** Called when cloud instance-metadata findings are available. */
        default void onCloudMetadata(List<CloudMetadataProbe.MetadataResult> results) {}

        /** Called once for each live neighbor discovered in the /24 subnet. */
        default void onNeighborDiscovered(ReverseDnsExpander.NeighborInfo neighbor) {}
    }

    private final String host;
    private final int startPort;
    private final int endPort;
    private final EnhancedServiceDetector detector;
    private final SubnetScanner subnetScanner;
    private final Callbacks callbacks;
    private ExecutorService executor;

    public ServiceDetectionTask(String host, int startPort, int endPort,
                               EnhancedServiceDetector detector, Callbacks callbacks) {
        this.host          = host;
        this.startPort     = startPort;
        this.endPort       = endPort;
        this.detector      = detector;
        this.subnetScanner = new SubnetScanner();
        this.callbacks     = callbacks;
    }

    @Override
    protected Void call() throws Exception {
        int totalPorts = endPort - startPort + 1;
        try {
            InetAddress addr = InetAddress.getByName(host);
            String ip        = addr.getHostAddress();
            String hostname  = addr.getCanonicalHostName();

            Platform.runLater(() -> callbacks.onHostResolved(ip));

            // Subnet info + cloud metadata + neighbor expansion (parallel, non-blocking)
            detectSubnetInfo(ip);

            callbacks.onScanStarted(ip, hostname, totalPorts);
            callbacks.onStatus("Service Detection: Scanning " + host + " (" + ip + ") — ports " + startPort + "–" + endPort);

            CountDownLatch latch = new CountDownLatch(totalPorts);
            executor = Executors.newVirtualThreadPerTaskExecutor();

            int cancelledPorts = 0;
            for (int port = startPort; port <= endPort; port++) {
                if (isCancelled()) {
                    latch.countDown();
                    cancelledPorts++;
                    continue;
                }
                final int p = port;

                CompletableFuture
                    .supplyAsync(() -> detector.detectService(ip, p), executor)
                    .thenAcceptAsync(result -> {
                        if (result != null) {
                            Platform.runLater(() -> {
                                callbacks.onResult(result);
                                String service = result.getService();
                                if (service != null && service.contains("[") && service.contains("]")) {
                                    callbacks.onStatus("[SECURITY] Security detected: " + service + " on port " + p);
                                } else {
                                    callbacks.onStatus("Detected: " + (service != null ? service : "Unknown") + " on port " + p);
                                }
                            });
                        }
                    }, executor)
                    .whenComplete((v, err) -> {
                        latch.countDown();
                        updateProgress(totalPorts - latch.getCount(), totalPorts);
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
            // Basic subnet / gateway detection
            String subnet  = subnetScanner.detectSubnet(ip);
            String gateway = subnetScanner.detectGateway(ip);
            if (subnet != null || gateway != null) {
                Platform.runLater(() -> callbacks.onSubnetDetected(
                    subnet  != null ? subnet  : "Unknown",
                    gateway != null ? gateway : "Unknown"
                ));
            }
        } catch (Exception e) {
            // Subnet detection is optional
        }

        // Cloud metadata probe (fire-and-forget on a virtual thread)
        CompletableFuture.runAsync(() -> {
            List<CloudMetadataProbe.MetadataResult> cloud = CloudMetadataProbe.probe();
            if (!cloud.isEmpty()) {
                Platform.runLater(() -> callbacks.onCloudMetadata(cloud));
                cloud.forEach(r ->
                    callbacks.onStatus("[CLOUD] " + r.getProvider() + " metadata exposed — " +
                                       r.getFindings().size() + " finding(s)"));
            }
        });

        // /24 reverse-DNS expansion (fire-and-forget on a virtual thread)
        CompletableFuture.runAsync(() ->
            ReverseDnsExpander.expandSubnet(ip, neighbor ->
                Platform.runLater(() -> callbacks.onNeighborDiscovered(neighbor))
            )
        );
    }

    @Override protected void succeeded() { super.succeeded(); callbacks.onCompleted(); }
    @Override protected void cancelled() { super.cancelled(); callbacks.onCancelled(); }
    @Override protected void failed() {
        super.failed();
        Throwable ex = getException();
        callbacks.onFailed(ex != null ? ex.getMessage() : "Unknown error");
    }

    // Explicit wrappers help callers rely on stable API regardless of inherited-method resolution quirks.
    public ReadOnlyDoubleProperty taskProgressProperty() {
        return progressProperty();
    }

    public boolean taskIsRunning() {
        return isRunning();
    }

    public boolean requestCancel() {
        return cancel();
    }

    public void shutdown() {
        if (executor != null && !executor.isShutdown()) executor.shutdownNow();
    }
}
