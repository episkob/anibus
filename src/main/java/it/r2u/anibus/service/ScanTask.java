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
 * Background Task that scans a port range on a given host.
 * All UI updates are dispatched via the Callbacks interface.
 */
public class ScanTask extends Task<Void> {

    public interface Callbacks {
        void onHostResolved(String ip);
        void onScanStarted(String ip, String hostname, int totalPorts);
        void onResult(PortScanResult result);
        void onStatus(String message);
        void onCompleted();
        void onCancelled();
        void onFailed(String error);
    }

    private final String host;
    private final int startPort;
    private final int endPort;
    private final int threadCount;
    private final PortScannerService scanner;
    private final Callbacks callbacks;
    private ExecutorService executor;

    public ScanTask(String host, int startPort, int endPort, int threadCount,
                    PortScannerService scanner, Callbacks callbacks) {
        this.host        = host;
        this.startPort   = startPort;
        this.endPort     = endPort;
        this.threadCount = threadCount;
        this.scanner     = scanner;
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
            callbacks.onScanStarted(ip, hostname, totalPorts);
            callbacks.onStatus("Scanning " + host + " (" + ip + ") — ports " + startPort + "–" + endPort);

            CountDownLatch latch = new CountDownLatch(totalPorts);
            ThreadFactory daemon = r -> { Thread t = new Thread(r); t.setDaemon(true); return t; };
            executor = Executors.newFixedThreadPool(threadCount, daemon);

            for (int port = startPort; port <= endPort; port++) {
                if (isCancelled()) break;
                final int p = port;
                executor.submit(() -> {
                    try {
                        long latency = scanner.measurePortLatency(ip, p);
                        if (latency >= 0) {
                            String banner   = scanner.getBanner(ip, p);
                            String service  = scanner.getServiceName(p);
                            String protocol = scanner.getProtocol(p, banner);
                            String version  = scanner.extractVersion(banner);
                            Platform.runLater(() ->
                                callbacks.onResult(new PortScanResult(
                                    p, service, banner, protocol, latency, version, "Open")));
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

    @Override protected void succeeded() { super.succeeded(); callbacks.onCompleted(); }
    @Override protected void cancelled() { super.cancelled(); callbacks.onCancelled(); }
    @Override protected void failed()    { super.failed();    callbacks.onFailed(getException().getMessage()); }

    public void shutdown() {
        if (executor != null && !executor.isShutdown()) executor.shutdownNow();
    }
}
