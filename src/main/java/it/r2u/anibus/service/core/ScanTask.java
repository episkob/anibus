package it.r2u.anibus.service.core;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.analysis.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.service.analysis.JavaScriptSecurityAnalyzer.AnalysisDepth;
import javafx.application.Platform;
import javafx.beans.property.StringProperty;
import javafx.concurrent.Task;

/**
 * Background Task that scans a port range on a given host.
 *
 * Pipeline per open port (real-time, no blocking):
 *   1. TCP probe (virtual thread)
 *   2. Banner grab + service detection → result reported immediately to UI
 *   3. Parallel enrichment:
 *        - VulnerabilityScanner (in-memory CVE lookup)
 *        - JSAnalyzer on HTTP/HTTPS ports (BASIC depth)
 *      Banner is updated on the JavaFX thread once both complete.
 *
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
    private final PortScannerService scanner;
    private final Callbacks callbacks;
    private ExecutorService executor;
    private final JavaScriptSecurityAnalyzer jsAnalyzer;
    private final boolean ownsJsAnalyzer;

    public ScanTask(String host, int startPort, int endPort,
                    PortScannerService scanner, Callbacks callbacks) {
        this(host, startPort, endPort, scanner, callbacks, new JavaScriptSecurityAnalyzer(), true);
    }

    public ScanTask(String host, int startPort, int endPort,
                    PortScannerService scanner, Callbacks callbacks,
                    JavaScriptSecurityAnalyzer jsAnalyzer) {
        this(host, startPort, endPort, scanner, callbacks, jsAnalyzer, false);
    }

    private ScanTask(String host, int startPort, int endPort,
                    PortScannerService scanner, Callbacks callbacks,
                    JavaScriptSecurityAnalyzer jsAnalyzer, boolean ownsJsAnalyzer) {
        this.host        = host;
        this.startPort   = startPort;
        this.endPort     = endPort;
        this.scanner     = scanner;
        this.callbacks   = callbacks;
        this.jsAnalyzer  = jsAnalyzer;
        this.ownsJsAnalyzer = ownsJsAnalyzer;
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
            executor = Executors.newVirtualThreadPerTaskExecutor();

            for (int port = startPort; port <= endPort; port++) {
                if (isCancelled()) {
                    latch.countDown();   // account for skipped port
                    continue;
                }
                final int p = port;

                // Stage 1 → Stage 2 → Stage 3 (report) → Stage 4 (enrich, parallel)
                CompletableFuture
                    .supplyAsync(() -> scanner.measurePortLatency(ip, p), executor)
                    .thenComposeAsync(latency -> {
                        if (latency < 0) return CompletableFuture.<PortScanResult>completedFuture(null);
                        return CompletableFuture.supplyAsync(
                            () -> buildBaseResult(ip, p, latency), executor);
                    }, executor)
                    .thenComposeAsync(result -> {
                        if (result == null) return CompletableFuture.completedFuture((Void) null);
                        Platform.runLater(() -> callbacks.onResult(result));
                        return enrichConcurrently(result, ip, p);
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

    /** Stage 2: grab banner and detect service/protocol/version. */
    private PortScanResult buildBaseResult(String ip, int port, long latency) {
        String banner   = scanner.getBanner(ip, port);
        String service  = scanner.getServiceName(port);
        String protocol = scanner.getProtocol(port, banner);
        String version  = scanner.extractVersion(banner);
        return new PortScanResult(port, service, banner, protocol, latency, version, "Open", "Standard");
    }

    /**
     * Stage 4: VulnerabilityScanner and (HTTP ports) JS analysis run in parallel.
     * The banner property is updated on the JavaFX thread once both futures complete.
     */
    private CompletableFuture<Void> enrichConcurrently(PortScanResult result, String ip, int port) {
        CompletableFuture<String> vulnFuture = CompletableFuture.supplyAsync(() -> {
            List<VulnerabilityScanner.Vulnerability> vulns =
                VulnerabilityScanner.scanVulnerabilities(result.getService(), result.getBanner());
            return vulns.isEmpty() ? "" : VulnerabilityScanner.formatVulnerabilities(vulns);
        }, executor);

        boolean httpPort = port == 80 || port == 443 || port == 8080 || port == 8443
                        || port == 8000 || port == 8888 || port == 3000 || port == 5000;
        CompletableFuture<String> jsFuture = httpPort
            ? CompletableFuture.supplyAsync(() -> {
                  String scheme = (port == 443 || port == 8443) ? "https" : "http";
                  String url = scheme + "://" + ip + ":" + port;
                  try {
                      JavaScriptAnalysisResult js = jsAnalyzer.analyzeTarget(url, AnalysisDepth.BASIC);
                      if (js == null || js.getEndpoints().isEmpty()) return "";
                      return "[JS] " + js.getEndpoints().size() + " endpoint(s) discovered";
                  } catch (Exception ignored) { return ""; }
              }, executor)
            : CompletableFuture.completedFuture("");

        return CompletableFuture.allOf(vulnFuture, jsFuture).thenRun(() -> {
            String vulns = vulnFuture.join();
            String js    = jsFuture.join();
            if (vulns.isEmpty() && js.isEmpty()) return;
            String base = result.getBanner();
            StringBuilder enriched = new StringBuilder(base);
            if (!vulns.isEmpty()) enriched.append("\n").append(vulns);
            if (!js.isEmpty())    enriched.append("\n").append(js);
            Platform.runLater(() -> ((StringProperty) result.bannerProperty()).set(enriched.toString()));
        });
    }

    @Override protected void succeeded() { super.succeeded(); callbacks.onCompleted(); }
    @Override protected void cancelled() { super.cancelled(); callbacks.onCancelled(); }
    @Override protected void failed()    { super.failed();    callbacks.onFailed(getException().getMessage()); }

    public void shutdown() {
        if (executor != null && !executor.isShutdown()) executor.shutdownNow();
        if (ownsJsAnalyzer) jsAnalyzer.shutdown();
    }
}
