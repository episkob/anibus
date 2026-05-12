package it.r2u.anibus.handlers;

import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.LeakInfo;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.analysis.ParamMinerService;
import it.r2u.anibus.service.analysis.SourceMapAnalyzer;
import it.r2u.anibus.service.core.PortScannerService;
import it.r2u.anibus.service.core.ScanHistoryService;
import it.r2u.anibus.service.core.ScanSchedulerService;
import it.r2u.anibus.service.core.UdpScannerService;
import it.r2u.anibus.service.export.ScanDiffService;
import it.r2u.anibus.service.network.SubdomainEnumerationService;
import it.r2u.anibus.ui.ConsoleViewManager;
import javafx.application.Platform;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.scene.control.Alert;
import javafx.scene.control.ChoiceDialog;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.TextInputDialog;
import javafx.stage.FileChooser;

/**
 * Handles extra scan operations: UDP, subdomain enumeration, source map
 * analysis, param miner, diff mode, scheduler, SQL metadata, scan history.
 */
public class ExtraScanHandler {

    private final TextField hostTextField;
    private final TextField portsTextField;
    private final ProgressBar progressBar;
    private final TextArea consoleTextArea;
    private final ConsoleViewManager consoleViewManager;
    private final ObservableList<PortScanResult> results;
    private final Consumer<String> statusSetter;
    private final Supplier<JavaScriptAnalysisResult> lastJsResultSupplier;

    private final UdpScannerService udpScannerService;
    private final SubdomainEnumerationService subdomainEnumerationService;
    private final SourceMapAnalyzer sourceMapAnalyzer;
    private final ParamMinerService paramMinerService;
    private final ScanDiffService scanDiffService;
    private final ScanSchedulerService scanSchedulerService;
    private final ScanHistoryService scanHistoryService;
    private final PortScannerService scanner;

    /** Ports open in the previous scheduled scan — used for drift detection. */
    private Set<Integer> prevScheduledPorts = null;

    public ExtraScanHandler(
            TextField hostTextField,
            TextField portsTextField,
            ProgressBar progressBar,
            TextArea consoleTextArea,
            ConsoleViewManager consoleViewManager,
            ObservableList<PortScanResult> results,
            Consumer<String> statusSetter,
            Supplier<JavaScriptAnalysisResult> lastJsResultSupplier,
            UdpScannerService udpScannerService,
            SubdomainEnumerationService subdomainEnumerationService,
            SourceMapAnalyzer sourceMapAnalyzer,
            ParamMinerService paramMinerService,
            ScanDiffService scanDiffService,
            ScanSchedulerService scanSchedulerService,
            ScanHistoryService scanHistoryService,
            PortScannerService scanner) {
        this.hostTextField = hostTextField;
        this.portsTextField = portsTextField;
        this.progressBar = progressBar;
        this.consoleTextArea = consoleTextArea;
        this.consoleViewManager = consoleViewManager;
        this.results = results;
        this.statusSetter = statusSetter;
        this.lastJsResultSupplier = lastJsResultSupplier;
        this.udpScannerService = udpScannerService;
        this.subdomainEnumerationService = subdomainEnumerationService;
        this.sourceMapAnalyzer = sourceMapAnalyzer;
        this.paramMinerService = paramMinerService;
        this.scanDiffService = scanDiffService;
        this.scanSchedulerService = scanSchedulerService;
        this.scanHistoryService = scanHistoryService;
        this.scanner = scanner;
    }

    // ── Public scan methods ───────────────────────────────────────────────────

    public void runUdpScan() {
        String host = SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText());
        if (host.isBlank()) {
            statusSetter.accept("Enter a host or URL before UDP scan");
            return;
        }

        Task<List<PortScanResult>> task = new Task<>() {
            @Override
            protected List<PortScanResult> call() {
                return udpScannerService.scan(host, null, progress -> updateProgress(progress, 1.0));
            }
        };

        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        statusSetter.accept("Running UDP scan on " + host + "...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            List<PortScanResult> udpResults = task.getValue();
            if (udpResults == null || udpResults.isEmpty()) {
                statusSetter.accept("UDP scan completed: no responsive UDP ports detected");
                return;
            }
            results.addAll(udpResults);
            consoleViewManager.appendRawText("\n=== UDP SCAN RESULTS ===\n");
            udpResults.forEach(consoleViewManager::appendToConsole);
            statusSetter.accept("UDP scan completed: " + udpResults.size() + " result(s)");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            statusSetter.accept("UDP scan failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    public void runSubdomainEnumeration() {
        String host = SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText());
        String domain = normalizeRootDomain(host);
        if (domain == null || domain.isBlank()) {
            statusSetter.accept("Enter a valid domain for subdomain enumeration");
            return;
        }

        Task<List<SubdomainEnumerationService.SubdomainResult>> task = new Task<>() {
            @Override
            protected List<SubdomainEnumerationService.SubdomainResult> call() {
                return subdomainEnumerationService.enumerate(domain, true, p -> updateProgress(p, 1.0));
            }
        };

        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        statusSetter.accept("Enumerating subdomains for " + domain + "...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            List<SubdomainEnumerationService.SubdomainResult> found = task.getValue();
            consoleViewManager.appendRawText("\n" + SubdomainEnumerationService.formatReport(found, domain) + "\n");
            statusSetter.accept("Subdomain enumeration completed: " + found.size() + " live subdomain(s)");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            statusSetter.accept("Subdomain enumeration failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    public void runSourceMapAnalysis() {
        JavaScriptAnalysisResult lastJsResult = lastJsResultSupplier.get();
        if (lastJsResult == null || lastJsResult.getJsFiles() == null) {
            statusSetter.accept("Run JavaScript analysis first to discover JS files");
            return;
        }

        List<String> jsUrls = lastJsResult.getJsFiles().stream()
            .filter(u -> u != null && u.startsWith("http") && u.contains(".js"))
            .distinct()
            .limit(10)
            .toList();

        if (jsUrls.isEmpty()) {
            statusSetter.accept("No HTTP(S) JS files available for source map analysis");
            return;
        }

        Task<String> task = new Task<>() {
            @Override
            protected String call() {
                StringBuilder sb = new StringBuilder();
                int total = jsUrls.size();
                int idx = 0;
                for (String jsUrl : jsUrls) {
                    SourceMapAnalyzer.SourceMapResult sm = sourceMapAnalyzer.analyzeFromJsUrl(jsUrl);
                    sb.append("\n--- ").append(jsUrl).append(" ---\n");
                    sb.append(SourceMapAnalyzer.formatReport(sm)).append("\n");
                    if (sm.ok()) {
                        List<LeakInfo> leaks = SourceMapAnalyzer.extractLeaks(sm);
                        if (!leaks.isEmpty()) {
                            sb.append("Leaks from source map content: ").append(leaks.size()).append("\n");
                            var ctxAnalyzer = new it.r2u.anibus.service.analysis.SourceMapExploitContextAnalyzer();
                            var contexts = ctxAnalyzer.annotate(leaks);
                            sb.append(it.r2u.anibus.service.analysis.SourceMapExploitContextAnalyzer.formatReport(contexts));
                        }
                    }
                    idx++;
                    updateProgress(idx, total);
                }
                return sb.toString();
            }
        };

        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        statusSetter.accept("Analyzing source maps...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            consoleViewManager.appendRawText("\n=== SOURCE MAP ANALYSIS ===\n" + task.getValue() + "\n");
            statusSetter.accept("Source map analysis completed");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            statusSetter.accept("Source map analysis failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    public void runParamMiner() {
        String target = SecurityAnalysisHandler.ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) {
            statusSetter.accept("Enter a target URL for param miner");
            return;
        }

        Task<List<ParamMinerService.ParamFinding>> task = new Task<>() {
            @Override
            protected List<ParamMinerService.ParamFinding> call() {
                return paramMinerService.mine(target, true, p -> updateProgress(p, 1.0));
            }
        };

        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        statusSetter.accept("Running param miner on " + target + "...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            List<ParamMinerService.ParamFinding> findings = task.getValue();
            consoleViewManager.appendRawText("\n" + ParamMinerService.formatReport(findings, target) + "\n");
            statusSetter.accept("Param miner completed: " + findings.size() + " interesting parameter(s)");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            statusSetter.accept("Param miner failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    public void runDiffMode() {
        if (results.isEmpty()) {
            statusSetter.accept("No current scan results to compare");
            return;
        }

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select previous XML export");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("XML Files", "*.xml"));
        File oldFile = chooser.showOpenDialog(consoleTextArea.getScene().getWindow());
        if (oldFile == null) return;

        Task<ScanDiffService.DiffResult> task = new Task<>() {
            @Override
            protected ScanDiffService.DiffResult call() throws Exception {
                return scanDiffService.diffWithCurrent(oldFile, List.copyOf(results));
            }
        };

        statusSetter.accept("Computing diff against " + oldFile.getName() + "...");
        task.setOnSucceeded(ev -> {
            ScanDiffService.DiffResult diff = task.getValue();
            consoleViewManager.appendRawText("\n" + ScanDiffService.formatReport(diff) + "\n");
            statusSetter.accept("Diff mode completed");
        });
        task.setOnFailed(ev -> {
            Throwable ex = task.getException();
            statusSetter.accept("Diff mode failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    public void startScheduledScan() {
        if (scanSchedulerService.isRunning()) {
            statusSetter.accept(scanSchedulerService.statusString());
            return;
        }

        String host = SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText());
        int[] ports = scanner.parsePortsRange(portsTextField.getText());
        if (host.isBlank() || ports == null) {
            statusSetter.accept("Provide host and valid port range before scheduling");
            return;
        }

        int start = ports[0];
        int end = ports[1];
        prevScheduledPorts = null; // reset drift baseline on new schedule

        ScanSchedulerService.SchedulerOptions options = requestSchedulerOptions();
        if (options == null) {
            statusSetter.accept("Scheduler setup cancelled");
            return;
        }

        boolean legacyDefaults = options.interval().equals(java.time.Duration.ofMinutes(30))
            && options.initialDelay().isZero()
            && !options.fixedDelay()
            && options.maxRuns() == 0;

        if (legacyDefaults) {
            scanSchedulerService.schedule(java.time.Duration.ofMinutes(30),
                    () -> runScheduledTcpSnapshot(host, start, end),
                    snapshot -> Platform.runLater(() -> handleScheduledSnapshot(host, snapshot)),
                    error -> Platform.runLater(() -> statusSetter.accept("Scheduled scan failed: " + error))
            );
        } else {
            scanSchedulerService.schedule(options,
                    () -> runScheduledTcpSnapshot(host, start, end),
                    snapshot -> Platform.runLater(() -> handleScheduledSnapshot(host, snapshot)),
                    error -> Platform.runLater(() -> statusSetter.accept("Scheduled scan failed: " + error))
            );
        }

        if (legacyDefaults) {
            statusSetter.accept("Scheduled scan started (every 30 minutes)");
        } else {
            statusSetter.accept("Scheduled scan started: every " + options.interval().toMinutes() +
                " min, delay " + options.initialDelay().toSeconds() +
                " sec, mode=" + (options.fixedDelay() ? "fixed-delay" : "fixed-rate") +
                (options.maxRuns() > 0 ? ", maxRuns=" + options.maxRuns() : ", unlimited runs"));
        }
    }

    public void stopScheduledScan() {
        scanSchedulerService.cancel();
        statusSetter.accept("Scheduled scan stopped");
    }

    public void runSqlMetadataExtraction() {
        String host = hostTextField.getText().trim();
        if (host.isBlank()) { statusSetter.accept("Enter a host first"); return; }
        String targetUrl = host.startsWith("http") ? host : "http://" + host;
        statusSetter.accept("SQL Metadata Extraction — running…");
        Task<it.r2u.anibus.service.analysis.SqlMetadataExtractor.MetadataResult> task = new Task<>() {
            @Override
            protected it.r2u.anibus.service.analysis.SqlMetadataExtractor.MetadataResult call() {
                var vuln = new it.r2u.anibus.service.analysis.SQLInjectionAnalyzer.InjectionResult(
                    "' OR 1=1-- -", targetUrl, "GET", 200, 0, null, List.of("manual"), "");
                return new it.r2u.anibus.service.analysis.SqlMetadataExtractor().extract(vuln);
            }
        };
        task.setOnSucceeded(ev -> {
            var r = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + it.r2u.anibus.service.analysis.SqlMetadataExtractor.formatReport(r) + "\n");
            statusSetter.accept("SQL Metadata Extraction complete — " + r.tables().size() + " table(s) found");
        });
        task.setOnFailed(ev -> statusSetter.accept("SQL Extraction error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "sql-meta-extraction");
        t.setDaemon(true);
        t.start();
    }

    public void runShowScanHistory() {
        if (scanHistoryService == null) return;
        statusSetter.accept("Loading scan history…");
        Task<List<ScanHistoryService.HistoryEntry>> task = new Task<>() {
            @Override
            protected List<ScanHistoryService.HistoryEntry> call() {
                return scanHistoryService.list();
            }
        };
        task.setOnSucceeded(ev -> {
            List<ScanHistoryService.HistoryEntry> entries = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + ScanHistoryService.formatListReport(entries) + "\n");
            statusSetter.accept("Scan history: " + entries.size() + " entry(ies)");
        });
        task.setOnFailed(ev -> statusSetter.accept("History error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "scan-history-list");
        t.setDaemon(true);
        t.start();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private List<PortScanResult> runScheduledTcpSnapshot(String host, int startPort, int endPort) {
        List<PortScanResult> snapshot = new java.util.ArrayList<>();
        for (int port = startPort; port <= endPort; port++) {
            long latency = scanner.measurePortLatency(host, port);
            if (latency < 0) continue;
            String banner = scanner.getBanner(host, port);
            String service = scanner.getServiceName(port);
            String protocol = scanner.getProtocol(port, banner);
            String version = scanner.extractVersion(banner);
            snapshot.add(new PortScanResult(port, service, banner, protocol, latency, version, "Open", "Scheduled"));
        }
        return snapshot;
    }

    private static String buildDriftMessage(String host, Set<Integer> opened, Set<Integer> closed) {
        StringBuilder sb = new StringBuilder("\n⚠ SECURITY DRIFT DETECTED on ").append(host).append("\n");
        if (!opened.isEmpty()) sb.append("  [OPENED] ports: ").append(opened).append("\n");
        if (!closed.isEmpty()) sb.append("  [CLOSED] ports: ").append(closed).append("\n");
        return sb.toString();
    }

    private static String normalizeRootDomain(String host) {
        if (host == null || host.isBlank()) return null;
        String[] parts = host.split("\\.");
        if (parts.length < 2) return host;
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private void handleScheduledSnapshot(String host, ScanSchedulerService.ScanResults snapshot) {
        results.setAll(snapshot.results());
        consoleViewManager.clear();
        consoleViewManager.appendRawText("=== SCHEDULED SCAN ===\n");
        snapshot.results().forEach(consoleViewManager::appendToConsole);
        statusSetter.accept("Scheduled scan finished at " + snapshot.formattedTimestamp() +
                " (" + snapshot.results().size() + " open port(s))");

        java.util.Set<Integer> currentPorts = new java.util.HashSet<>();
        snapshot.results().forEach(r -> currentPorts.add(r.getPort()));
        if (prevScheduledPorts != null) {
            java.util.Set<Integer> opened = new java.util.HashSet<>(currentPorts);
            opened.removeAll(prevScheduledPorts);
            java.util.Set<Integer> closed = new java.util.HashSet<>(prevScheduledPorts);
            closed.removeAll(currentPorts);
            if (!opened.isEmpty() || !closed.isEmpty()) {
                String msg = buildDriftMessage(host, opened, closed);
                consoleViewManager.appendRawText(msg);
                Alert alert = new Alert(Alert.AlertType.WARNING);
                alert.setTitle("Security Drift Detected");
                alert.setHeaderText("Port changes detected on " + host);
                alert.setContentText(msg.strip());
                alert.show();
            }
        }
        prevScheduledPorts = currentPorts;
    }

    private ScanSchedulerService.SchedulerOptions requestSchedulerOptions() {
        if (java.awt.GraphicsEnvironment.isHeadless()
            || hostTextField == null
            || hostTextField.getScene() == null) {
            return new ScanSchedulerService.SchedulerOptions(
                java.time.Duration.ofMinutes(30),
                java.time.Duration.ZERO,
                false,
                0
            );
        }

        String intervalRaw = promptText(
                "Scheduler interval",
                "Enter interval in minutes",
                "30"
        );
        if (intervalRaw == null) return null;

        String delayRaw = promptText(
                "Scheduler delay",
                "Enter initial delay in seconds",
                "0"
        );
        if (delayRaw == null) return null;

        String maxRunsRaw = promptText(
                "Scheduler max runs",
                "Enter max runs (0 = unlimited)",
                "0"
        );
        if (maxRunsRaw == null) return null;

        ChoiceDialog<String> modeDialog = new ChoiceDialog<>("fixed-rate", List.of("fixed-rate", "fixed-delay"));
        modeDialog.setTitle("Scheduler mode");
        modeDialog.setHeaderText("Choose scheduling mode");
        modeDialog.setContentText("Mode:");
        var modeOpt = modeDialog.showAndWait();
        if (modeOpt.isEmpty()) return null;

        long intervalMinutes = parseLongOrDefault(intervalRaw, 30);
        long initialDelaySeconds = parseLongOrDefault(delayRaw, 0);
        int maxRuns = (int) parseLongOrDefault(maxRunsRaw, 0);
        boolean fixedDelay = "fixed-delay".equals(modeOpt.get());

        return new ScanSchedulerService.SchedulerOptions(
                java.time.Duration.ofMinutes(Math.max(1, intervalMinutes)),
                java.time.Duration.ofSeconds(Math.max(0, initialDelaySeconds)),
                fixedDelay,
                Math.max(0, maxRuns)
        );
    }

    private String promptText(String title, String header, String defaultValue) {
        TextInputDialog dialog = new TextInputDialog(defaultValue);
        dialog.setTitle(title);
        dialog.setHeaderText(header);
        dialog.setContentText("Value:");
        return dialog.showAndWait().orElse(null);
    }

    private long parseLongOrDefault(String value, long fallback) {
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
