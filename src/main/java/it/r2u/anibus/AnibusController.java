package it.r2u.anibus;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.network.NetworkStatusMonitor;
import it.r2u.anibus.service.ExportService;
import it.r2u.anibus.service.PortScannerService;
import it.r2u.anibus.service.ScanTask;
import it.r2u.anibus.service.ServiceDetectionTask;
import it.r2u.anibus.service.EnhancedServiceDetector;
import it.r2u.anibus.ui.AlertHelper;
import it.r2u.anibus.ui.ClipboardService;
import it.r2u.anibus.ui.ConsoleViewManager;
import it.r2u.anibus.ui.InfoCardManager;
import it.r2u.anibus.ui.TableConfigurator;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;

import java.util.Properties;

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
    private final ObservableList<PortScanResult> results  = FXCollections.observableArrayList();
    private final PortScannerService             scanner  = new PortScannerService();
    private final EnhancedServiceDetector        detector = new EnhancedServiceDetector();
    
    /* -- Helper classes --------------------------------------- */
    private HostResolver           hostResolver;
    private NetworkStatusMonitor   networkStatusMonitor;
    private ConsoleViewManager     consoleViewManager;
    private InfoCardManager        infoCardManager;

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        // Initialize helper classes
        hostResolver = new HostResolver();
        networkStatusMonitor = new NetworkStatusMonitor(networkDot, new Tooltip("Checking network…"));
        consoleViewManager = new ConsoleViewManager(consoleTextArea);
        infoCardManager = new InfoCardManager(infoCard, infoIpLabel, infoHostnameLabel,
                infoScanTimeLabel, infoPortsScannedLabel, infoOpenPortsLabel, infoAvgLatencyLabel);
        
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
            infoCardManager.refreshInfoCard(results);
            Platform.runLater(() -> {
                boolean any = !results.isEmpty();
                exportButton.setDisable(!any);
                clearButton.setDisable(!any);
            });
        });

        setupContextMenu();
        hostTextField.focusedProperty().addListener((obs, was, is) -> { 
            if (!is) {
                String host = hostResolver.sanitizeHost(hostTextField.getText());
                if (!host.isEmpty()) {
                    if (!host.equals(hostTextField.getText().trim())) {
                        hostTextField.setText(host);
                    }
                    hostResolver.resolveHostAsync(host, resolvedHostLabel, null);
                } else {
                    resolvedHostLabel.setText("");
                }
            }
        });
        refreshResultCount();
        networkStatusMonitor.start();
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

    /* -- Result count ----------------------------------------- */
    private void refreshResultCount() {
        Platform.runLater(() -> {
            int n = results.size();
            if (resultCountLabel != null)
                resultCountLabel.setText(n == 0 ? "No open ports" : n == 1 ? "1 open port" : n + " open ports");
        });
    }

    /* -- Status ----------------------------------------------- */
    private void setStatus(String msg) {
        Platform.runLater(() -> { if (statusLabel != null) statusLabel.setText(msg); });
    }

    /* -- Scan start ------------------------------------------- */
    @FXML
    protected void onScanButtonClick() {
        results.clear();
        String host      = hostResolver.sanitizeHost(hostTextField.getText());
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
        infoCardManager.startScanTime();

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
                        String sslStatus = hostResolver.checkSSL(finalHost);
                        resolvedHostLabel.setText("Resolved: " + ip + sslStatus); 
                    }
                    public void onScanStarted(String ip, String hn, int tot) { infoCardManager.showInfoCard(ip, hn, tot); }
                    public void onResult(PortScanResult r)                   { results.add(r); consoleViewManager.appendToConsole(r); }
                    public void onStatus(String msg)                         { setStatus(msg); }
                    public void onCompleted() { infoCardManager.finalizeScanTime(); setStatus("⚡ Standard Scan complete — " + results.size() + " open port(s) found"); resetUI(); }
                    public void onCancelled() { infoCardManager.finalizeScanTime(); setStatus("⚡ Standard Scan stopped by user"); resetUI(); }
                    public void onFailed(String err) { infoCardManager.finalizeScanTime(); setStatus("⚡ Standard Scan failed: " + err); resetUI(); }
                });

        progressBar.progressProperty().bind(activeScanTask.progressProperty());
        new Thread(activeScanTask).start();
    }

    private void startServiceDetectionScan(String host, int[] ports) {
        final String finalHost = host;
        activeServiceDetectionTask = new ServiceDetectionTask(host, ports[0], ports[1], threadSpinner.getValue(), detector,
                new ServiceDetectionTask.Callbacks() {
                    public void onHostResolved(String ip) { 
                        String sslStatus = hostResolver.checkSSL(finalHost);
                        Platform.runLater(() -> resolvedHostLabel.setText("Resolved: " + ip + sslStatus)); 
                    }
                    public void onScanStarted(String ip, String hn, int tot) { 
                        infoCardManager.showInfoCard(ip, hn, tot); 
                    }
                    public void onResult(PortScanResult r) { 
                        Platform.runLater(() -> {
                            results.add(r);
                            consoleViewManager.appendToConsole(r);
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
                        infoCardManager.finalizeScanTime(); 
                        setStatus("🔍 Service Detection complete — " + results.size() + " service(s) detected with enhanced details"); 
                        resetUI(); 
                    }
                    public void onCancelled() { 
                        infoCardManager.finalizeScanTime(); 
                        setStatus("🔍 Service Detection stopped by user"); 
                        resetUI(); 
                    }
                    public void onFailed(String err) { 
                        infoCardManager.finalizeScanTime(); 
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
        consoleViewManager.toggle();
        Platform.runLater(() -> {
            if (consoleViewManager.isConsoleView()) {
                resultTableView.setVisible(false);
                consoleScrollPane.setVisible(true);
                viewToggleButton.setText("Table View");
                // Populate console with current results
                consoleViewManager.updateConsoleWithAllResults(results);
            } else {
                resultTableView.setVisible(true);
                consoleScrollPane.setVisible(false);
                viewToggleButton.setText("Console View");
            }
        });
    }
    
    public void shutdownExecutor() {
        if (activeScanTask != null) activeScanTask.shutdown();
        if (activeServiceDetectionTask != null) activeServiceDetectionTask.shutdown();
        networkStatusMonitor.stop();
    }
}
