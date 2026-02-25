package it.r2u.anibus;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.ExportService;
import it.r2u.anibus.service.PortScannerService;
import it.r2u.anibus.service.ScanTask;
import it.r2u.anibus.service.ServiceDetectionTask;
import it.r2u.anibus.service.EnhancedServiceDetector;
import it.r2u.anibus.ui.AlertHelper;
import it.r2u.anibus.ui.ClipboardService;
import it.r2u.anibus.ui.TableConfigurator;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;

import java.net.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * UI controller: handles FXML events and delegates work
 * to focused service/helper classes.
 */
public class AnibusController {

    /* -- FXML fields ------------------------------------------ */
    @FXML private TextField         hostTextField;
    @FXML private TextField         portsTextField;
    @FXML private Spinner<Integer>  threadSpinner;
    @FXML private Label             resolvedHostLabel;
    @FXML private Label             statusLabel;
    @FXML private Circle            networkDot;
    private Tooltip                 networkTooltip;
    @FXML private Label             resultCountLabel;
    @FXML private ProgressIndicator progressIndicator;
    @FXML private ProgressBar       progressBar;
    @FXML private Button            scanButton;
    @FXML private Button            stopButton;
    @FXML private Button            exportButton;
    @FXML private Button            clearButton;
    @FXML private ComboBox<String>  scanTypeComboBox;
    @FXML private Button            viewToggleButton;
    @FXML private ScrollPane        consoleScrollPane;
    @FXML private javafx.scene.control.TextArea consoleTextArea;

    /* -- Info card labels ------------------------------------- */
    @FXML private VBox  infoCard;
    @FXML private Label infoIpLabel;
    @FXML private Label infoHostnameLabel;
    @FXML private Label infoScanTimeLabel;
    @FXML private Label infoPortsScannedLabel;
    @FXML private Label infoOpenPortsLabel;
    @FXML private Label infoAvgLatencyLabel;
    @FXML private Label infoSubnetLabel;
    @FXML private Label infoGatewayLabel;

    /* -- Table ------------------------------------------------ */
    @FXML private TableView<PortScanResult>            resultTableView;
    @FXML private TableColumn<PortScanResult, Integer> portColumn;
    @FXML private TableColumn<PortScanResult, String>  stateColumn;
    @FXML private TableColumn<PortScanResult, String>  serviceColumn;
    @FXML private TableColumn<PortScanResult, String>  versionColumn;
    @FXML private TableColumn<PortScanResult, String>  protocolColumn;
    @FXML private TableColumn<PortScanResult, Long>    latencyColumn;
    @FXML private TableColumn<PortScanResult, String>  bannerColumn;

    /* -- State ------------------------------------------------ */
    private ScanTask                  activeScanTask;
    private ServiceDetectionTask      activeServiceDetectionTask;
    private String                    currentScanMode = "Standard Scanning";
    private Instant                   scanStartTime;
    private ScheduledExecutorService  networkMonitor;
    private boolean                   isConsoleView = false;
    private final ObservableList<PortScanResult> results  = FXCollections.observableArrayList();
    private final PortScannerService             scanner  = new PortScannerService();
    private final EnhancedServiceDetector        detector = new EnhancedServiceDetector();

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        TableConfigurator.setup(resultTableView,
                portColumn, stateColumn, serviceColumn,
                versionColumn, protocolColumn, latencyColumn, bannerColumn);
        resultTableView.setItems(results);

        scanTypeComboBox.getItems().addAll(
                "Standard Scanning",
                "Service Detection",
                "OS Fingerprinting",
                "Vulnerability Scan"
        );
        scanTypeComboBox.getSelectionModel().selectFirst();
        
        // Handle scan mode changes
        scanTypeComboBox.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            onScanModeChanged(newVal);
        });
        
        // Set initial status for default mode
        onScanModeChanged(scanTypeComboBox.getSelectionModel().getSelectedItem());

        threadSpinner.setValueFactory(
                new SpinnerValueFactory.IntegerSpinnerValueFactory(10, 500, 10, 10));

        results.addListener((javafx.collections.ListChangeListener<PortScanResult>) c -> {
            refreshResultCount();
            refreshInfoCard();
            Platform.runLater(() -> {
                boolean any = !results.isEmpty();
                exportButton.setDisable(!any);
                clearButton.setDisable(!any);
            });
        });

        networkTooltip = new Tooltip("Checking network…");
        Tooltip.install(networkDot, networkTooltip);

        setupContextMenu();
        hostTextField.focusedProperty().addListener((obs, was, is) -> { if (!is) resolveHost(); });
        refreshResultCount();
        startNetworkMonitor();
    }

    private void setupContextMenu() {
        MenuItem copyRow = new MenuItem("Copy row");
        copyRow.setOnAction(e -> copySelectedRow());
        MenuItem copyAll = new MenuItem("Copy all results");
        copyAll.setOnAction(e -> copyAllRows());
        resultTableView.setContextMenu(new ContextMenu(copyRow, new SeparatorMenuItem(), copyAll));
        
        // Context menu for resolved host label
        MenuItem copyIP = new MenuItem("Copy");
        copyIP.setOnAction(e -> copyResolvedIP());
        resolvedHostLabel.setContextMenu(new ContextMenu(copyIP));
    }

    /* -- Scan mode handling ----------------------------------- */
    private void onScanModeChanged(String mode) {
        if (mode == null) return;
        currentScanMode = mode;
        
        switch (mode) {
            case "Standard Scanning" -> {
                setStatus("Standard Scanning mode: Basic TCP port scanning with service detection");
                // Standard mode is fully functional
            }
            case "Service Detection" -> {
                setStatus("Service Detection mode: Enhanced service fingerprinting with real-time detection");
                // Service detection mode is now fully functional
            }
            case "OS Fingerprinting" -> {
                setStatus("OS Fingerprinting mode: Operating system detection (coming soon)");
                AlertHelper.show("Feature Preview", 
                    "OS Fingerprinting mode will provide:\n" +
                    "• TCP/IP stack analysis\n" +
                    "• TTL and window size detection\n" +
                    "• Operating system identification\n\n" +
                    "Currently using Standard Scanning.",
                    Alert.AlertType.INFORMATION, cssUrl());
            }
            case "Vulnerability Scan" -> {
                setStatus("Vulnerability Scan mode: Security assessment (coming soon)");
                AlertHelper.show("Feature Preview", 
                    "Vulnerability Scan mode will provide:\n" +
                    "• Known vulnerability detection\n" +
                    "• CVE database matching\n" +
                    "• Security risk assessment\n\n" +
                    "Currently using Standard Scanning.",
                    Alert.AlertType.INFORMATION, cssUrl());
            }
        }
    }

    /* -- Network status --------------------------------------- */
    private enum NetworkStatus { INTERNET, LOCAL_ONLY, NONE }

    private void startNetworkMonitor() {
        networkMonitor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "network-monitor");
            t.setDaemon(true);
            return t;
        });
        // Check immediately, then every 5 seconds
        networkMonitor.scheduleWithFixedDelay(() -> {
            NetworkStatus status = detectNetworkStatus();
            Platform.runLater(() -> applyNetworkDot(status));
        }, 0, 5, TimeUnit.SECONDS);
    }

    private NetworkStatus detectNetworkStatus() {
        // Try a lightweight TCP probe to a well-known public DNS server
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("8.8.8.8", 53), 2000);
            return NetworkStatus.INTERNET;
        } catch (Exception ignored) {}
        // Fall back: check whether any non-loopback interface is up
        try {
            var ifaces = NetworkInterface.getNetworkInterfaces();
            if (ifaces != null) {
                while (ifaces.hasMoreElements()) {
                    NetworkInterface iface = ifaces.nextElement();
                    if (!iface.isLoopback() && iface.isUp()) {
                        var addrs = iface.getInetAddresses();
                        while (addrs.hasMoreElements()) {
                            InetAddress addr = addrs.nextElement();
                            if (!addr.isLoopbackAddress() && !addr.isLinkLocalAddress())
                                return NetworkStatus.LOCAL_ONLY;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return NetworkStatus.NONE;
    }

    private void applyNetworkDot(NetworkStatus status) {
        if (networkDot == null) return;
        networkDot.getStyleClass().removeAll("network-dot-green", "network-dot-yellow", "network-dot-red");
        switch (status) {
            case INTERNET -> {
                networkDot.getStyleClass().add("network-dot-green");
                if (networkTooltip != null) networkTooltip.setText("Internet: connected");
            }
            case LOCAL_ONLY -> {
                networkDot.getStyleClass().add("network-dot-yellow");
                if (networkTooltip != null) networkTooltip.setText("Network: local only (no internet)");
            }
            case NONE -> {
                networkDot.getStyleClass().add("network-dot-red");
                if (networkTooltip != null) networkTooltip.setText("Network: no connection");
            }
        }
    }

    /* -- DNS resolve ------------------------------------------ */
    private String sanitizeHost(String input) {
        if (input == null || input.isEmpty()) return input;
        
        String cleaned = input.trim();
        
        // Remove http:// or https:// prefix
        if (cleaned.toLowerCase().startsWith("https://")) {
            cleaned = cleaned.substring(8);
        } else if (cleaned.toLowerCase().startsWith("http://")) {
            cleaned = cleaned.substring(7);
        }
        
        // Remove path, query params, and fragments (keep only hostname/IP)
        int slashIndex = cleaned.indexOf('/');
        if (slashIndex != -1) {
            cleaned = cleaned.substring(0, slashIndex);
        }
        
        // Remove port number from hostname if present (e.g., example.com:8080)
        int colonIndex = cleaned.indexOf(':');
        if (colonIndex != -1) {
            // Check if it's not an IPv6 address
            if (!cleaned.contains("[") && !cleaned.contains("]")) {
                cleaned = cleaned.substring(0, colonIndex);
            }
        }
        
        return cleaned.trim();
    }
    
    private String checkSSL(String host) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                socket.connect(new InetSocketAddress(host, 443), 2000);
                socket.startHandshake();
                return " [SSL/TLS ✓]";
            }
        } catch (Exception e) {
            return " [SSL/TLS ✗]";
        }
    }
    
    private void resolveHost() {
        String host = sanitizeHost(hostTextField.getText());
        if (host.isEmpty()) { resolvedHostLabel.setText(""); return; }
        
        // Update text field with sanitized host
        if (!host.equals(hostTextField.getText().trim())) {
            Platform.runLater(() -> hostTextField.setText(host));
        }
        
        final String finalHost = host;
        new Thread(() -> {
            try {
                String ip = InetAddress.getByName(finalHost).getHostAddress();
                String sslStatus = checkSSL(finalHost);
                Platform.runLater(() -> resolvedHostLabel.setText("Resolved: " + ip + sslStatus));
            } catch (UnknownHostException ex) {
                Platform.runLater(() -> resolvedHostLabel.setText("Unable to resolve host"));
            }
        }).start();
    }

    /* -- Result count ----------------------------------------- */
    private void refreshResultCount() {
        Platform.runLater(() -> {
            int n = results.size();
            if (resultCountLabel != null)
                resultCountLabel.setText(n == 0 ? "No open ports" : n == 1 ? "1 open port" : n + " open ports");
        });
    }

    /* -- Info card -------------------------------------------- */
    private void refreshInfoCard() {
        Platform.runLater(() -> {
            if (infoOpenPortsLabel != null) infoOpenPortsLabel.setText(String.valueOf(results.size()));
            if (infoAvgLatencyLabel != null && !results.isEmpty()) {
                double avg = results.stream().mapToLong(PortScanResult::getLatency).average().orElse(0);
                infoAvgLatencyLabel.setText(String.format("%.0f ms", avg));
            }
        });
    }

    private void showInfoCard(String ip, String hostname, int totalPorts) {
        Platform.runLater(() -> {
            infoCard.setVisible(true);
            infoCard.setManaged(true);
            infoIpLabel.setText(ip);
            infoHostnameLabel.setText(hostname);
            infoPortsScannedLabel.setText(String.valueOf(totalPorts));
            infoOpenPortsLabel.setText("0");
            infoAvgLatencyLabel.setText("-");
            infoScanTimeLabel.setText("scanning");
            if (infoSubnetLabel != null) infoSubnetLabel.setText("-");
            if (infoGatewayLabel != null) infoGatewayLabel.setText("-");
        });
    }

    private void finalizeScanTime() {
        if (scanStartTime == null) return;
        long s = Duration.between(scanStartTime, Instant.now()).getSeconds();
        String elapsed = s < 60 ? s + "s" : (s / 60) + "m " + (s % 60) + "s";
        Platform.runLater(() -> infoScanTimeLabel.setText(elapsed));
    }

    /* -- Status ----------------------------------------------- */
    private void setStatus(String msg) {
        Platform.runLater(() -> { if (statusLabel != null) statusLabel.setText(msg); });
    }

    /* -- Scan start ------------------------------------------- */
    @FXML
    protected void onScanButtonClick() {
        results.clear();
        String host      = sanitizeHost(hostTextField.getText());
        String portsRange = portsTextField.getText().trim();

        if (host.isEmpty() || portsRange.isEmpty()) {
            AlertHelper.show("Missing input", "Please enter both hostname and port range.",
                    Alert.AlertType.WARNING, cssUrl());
            return;
        }
        
        // Update text field with sanitized host
        if (!host.equals(hostTextField.getText().trim())) {
            hostTextField.setText(host);
        }

        int[] ports = scanner.parsePortsRange(portsRange);
        if (ports == null) {
            AlertHelper.show("Invalid range", "Use format start-end (1-65535), e.g. 1-1024 or 1-65535.",
                    Alert.AlertType.ERROR, cssUrl());
            return;
        }

        scanButton.setDisable(true);
        stopButton.setDisable(false);
        progressIndicator.setVisible(true);
        progressBar.setVisible(true);
        progressBar.setProgress(0);
        
        // Show mode-specific status
        String modePrefix = "Service Detection".equals(currentScanMode) ? 
            "🔍 Service Detection: " : "⚡ Standard Scan: ";
        setStatus(modePrefix + "Resolving " + host + "...");
        scanStartTime = Instant.now();

        // Choose task based on current scan mode
        if ("Service Detection".equals(currentScanMode)) {
            startServiceDetectionScan(host, ports);
        } else {
            startStandardScan(host, ports);
        }
    }

    private void startStandardScan(String host, int[] ports) {
        final String finalHost = host;
        activeScanTask = new ScanTask(host, ports[0], ports[1], threadSpinner.getValue(), scanner,
                new ScanTask.Callbacks() {
                    public void onHostResolved(String ip)                    { 
                        String sslStatus = checkSSL(finalHost);
                        resolvedHostLabel.setText("Resolved: " + ip + sslStatus); 
                    }
                    public void onScanStarted(String ip, String hn, int tot) { showInfoCard(ip, hn, tot); }
                    public void onResult(PortScanResult r)                   { results.add(r); appendToConsole(r); }
                    public void onStatus(String msg)                         { setStatus(msg); }
                    public void onCompleted() { finalizeScanTime(); setStatus("⚡ Standard Scan complete — " + results.size() + " open port(s) found"); resetUI(); }
                    public void onCancelled() { finalizeScanTime(); setStatus("⚡ Standard Scan stopped by user"); resetUI(); }
                    public void onFailed(String err) { finalizeScanTime(); setStatus("⚡ Standard Scan failed: " + err); resetUI(); }
                });

        progressBar.progressProperty().bind(activeScanTask.progressProperty());
        new Thread(activeScanTask).start();
    }

    private void startServiceDetectionScan(String host, int[] ports) {
        final String finalHost = host;
        activeServiceDetectionTask = new ServiceDetectionTask(host, ports[0], ports[1], threadSpinner.getValue(), detector,
                new ServiceDetectionTask.Callbacks() {
                    public void onHostResolved(String ip) { 
                        String sslStatus = checkSSL(finalHost);
                        Platform.runLater(() -> resolvedHostLabel.setText("Resolved: " + ip + sslStatus)); 
                    }
                    public void onScanStarted(String ip, String hn, int tot) { 
                        showInfoCard(ip, hn, tot); 
                    }
                    public void onResult(PortScanResult r) { 
                        Platform.runLater(() -> {
                            results.add(r);
                            appendToConsole(r);
                        }); 
                    }
                    public void onStatus(String msg) { 
                        setStatus(msg); 
                    }
                    public void onSubnetDetected(String subnet, String gateway) {
                        Platform.runLater(() -> {
                            if (infoSubnetLabel != null) infoSubnetLabel.setText(subnet);
                            if (infoGatewayLabel != null) infoGatewayLabel.setText(gateway);
                        });
                    }
                    public void onCompleted() { 
                        finalizeScanTime(); 
                        setStatus("🔍 Service Detection complete — " + results.size() + " service(s) detected with enhanced details"); 
                        resetUI(); 
                    }
                    public void onCancelled() { 
                        finalizeScanTime(); 
                        setStatus("🔍 Service Detection stopped by user"); 
                        resetUI(); 
                    }
                    public void onFailed(String err) { 
                        finalizeScanTime(); 
                        setStatus("🔍 Service Detection failed: " + err); 
                        resetUI(); 
                    }
                });

        progressBar.progressProperty().bind(activeServiceDetectionTask.progressProperty());
        new Thread(activeServiceDetectionTask).start();
    }

    /* -- Scan stop -------------------------------------------- */
    @FXML
    protected void onStopButtonClick() {
        if (activeScanTask != null && activeScanTask.isRunning()) {
            activeScanTask.cancel();
        }
        if (activeServiceDetectionTask != null && activeServiceDetectionTask.isRunning()) {
            activeServiceDetectionTask.cancel();
        }
    }

    /* -- Export ----------------------------------------------- */
    @FXML
    protected void onExportClick() {
        new ExportService(results, resultTableView.getScene().getWindow(), cssUrl(), this::setStatus)
                .promptAndExport();
    }

    /* -- Clear ------------------------------------------------ */
    @FXML
    protected void onClearClick() {
        results.clear();
        if (consoleTextArea != null) {
            consoleTextArea.clear();
        }
        infoCard.setVisible(false);
        infoCard.setManaged(false);
        setStatus("Results cleared");
    }

    /* -- About ------------------------------------------------ */
    @FXML
    protected void onAboutClick() {
        String version = "1.1.0";
        try (var in = getClass().getResourceAsStream("app.properties")) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);
                version = props.getProperty("app.version", version);
            }
        } catch (Exception ignored) {}
        AlertHelper.show("About Anibus",
                "Anibus Design System  \u203a  Version: " + version + "\n\nAuthor: Iaroslav Tsymbaliuk\n\nPosition: Intern (2025\u20132026) @ r2u",
                Alert.AlertType.INFORMATION, cssUrl());
    }

    /* -- Clipboard -------------------------------------------- */
    private void copySelectedRow() {
        PortScanResult sel = resultTableView.getSelectionModel().getSelectedItem();
        if (sel == null) return;
        ClipboardService.copy(ClipboardService.formatRow(sel));
        setStatus("Copied to clipboard");
    }

    private void copyAllRows() {
        if (results.isEmpty()) return;
        ClipboardService.copy(ClipboardService.formatAll(results));
        setStatus("All results copied to clipboard");
    }

    private void copyResolvedIP() {
        String text = resolvedHostLabel.getText();
        if (text == null || text.isEmpty()) return;
        // Extract IP from "Resolved: 172.217.23.163 [SSL/TLS ✓]" format
        String ip = text.replace("Resolved:", "").trim();
        // Remove SSL status if present
        int sslIndex = ip.indexOf("[SSL/TLS");
        if (sslIndex != -1) {
            ip = ip.substring(0, sslIndex).trim();
        }
        if (!ip.isEmpty()) {
            ClipboardService.copy(ip);
            setStatus("IP address copied to clipboard");
        }
    }

    /* -- UI helpers ------------------------------------------- */
    private void resetUI() {
        Platform.runLater(() -> {
            scanButton.setDisable(false);
            stopButton.setDisable(true);
            progressIndicator.setVisible(false);
            progressBar.setVisible(false);
            progressBar.progressProperty().unbind();
        });
    }

    private java.net.URL cssUrl() {
        return getClass().getResource("anibus-style.css");
    }

    /* -- View Toggle ------------------------------------------ */
    @FXML
    protected void onViewToggleClick() {
        isConsoleView = !isConsoleView;
        Platform.runLater(() -> {
            if (isConsoleView) {
                resultTableView.setVisible(false);
                consoleScrollPane.setVisible(true);
                viewToggleButton.setText("Table View");
                // Populate console with current results
                updateConsoleWithAllResults();
            } else {
                resultTableView.setVisible(true);
                consoleScrollPane.setVisible(false);
                viewToggleButton.setText("Console View");
            }
        });
    }
    
    private void updateConsoleWithAllResults() {
        if (consoleTextArea == null) return;
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        sb.append("  ANIBUS SCAN RESULTS\n");
        sb.append("═══════════════════════════════════════════════════════════════════════\n\n");
        
        if (results.isEmpty()) {
            sb.append("  No open ports found.\n\n");
        } else {
            for (PortScanResult result : results) {
                sb.append(formatConsoleResult(result));
            }
        }
        
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        sb.append(String.format("  Total: %d open port%s\n", results.size(), results.size() == 1 ? "" : "s"));
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        
        consoleTextArea.setText(sb.toString());
    }
    
    private void appendToConsole(PortScanResult result) {
        if (consoleTextArea == null || !isConsoleView) return;
        Platform.runLater(() -> {
            String current = consoleTextArea.getText();
            if (current.isEmpty() || !current.contains("ANIBUS SCAN RESULTS")) {
                // First result - add header
                consoleTextArea.setText(
                    "═══════════════════════════════════════════════════════════════════════\n" +
                    "  ANIBUS SCAN RESULTS\n" +
                    "═══════════════════════════════════════════════════════════════════════\n\n" +
                    formatConsoleResult(result)
                );
            } else {
                // Append to existing results
                consoleTextArea.appendText(formatConsoleResult(result));
            }
            // Auto-scroll to bottom
            consoleTextArea.setScrollTop(Double.MAX_VALUE);
        });
    }
    
    private String formatConsoleResult(PortScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("┌─ Port: %d (%s)\n", result.getPort(), result.getState()));
        sb.append(String.format("│  Service:  %s\n", result.getService() != null && !result.getService().isEmpty() ? result.getService() : "unknown"));
        if (result.getVersion() != null && !result.getVersion().isEmpty()) {
            sb.append(String.format("│  Version:  %s\n", result.getVersion()));
        }
        if (result.getProtocol() != null && !result.getProtocol().isEmpty()) {
            sb.append(String.format("│  Protocol: %s\n", result.getProtocol()));
        }
        sb.append(String.format("│  Latency:  %d ms\n", result.getLatency()));
        if (result.getBanner() != null && !result.getBanner().isEmpty()) {
            // Show full banner without truncation, with proper indentation for wrapped lines
            String banner = result.getBanner();
            sb.append(String.format("│  Banner:   %s\n", banner));
        }
        sb.append("└─────────────────────────────────────────────────────────────────────\n\n");
        return sb.toString();
    }

    public void shutdownExecutor() {
        if (activeScanTask != null) activeScanTask.shutdown();
        if (activeServiceDetectionTask != null) activeServiceDetectionTask.shutdown();
        if (networkMonitor != null && !networkMonitor.isShutdown()) networkMonitor.shutdownNow();
    }
}
