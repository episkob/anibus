package it.r2u.anibus;

import it.r2u.anibus.coordinator.*;
import it.r2u.anibus.handlers.*;
import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.network.NetworkStatusMonitor;
import it.r2u.anibus.service.EnhancedServiceDetector;
import it.r2u.anibus.service.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.service.PortScannerService;
import it.r2u.anibus.service.SQLInjectionAnalyzer;
import it.r2u.anibus.ui.AlertHelper;
import it.r2u.anibus.ui.ConsoleViewManager;
import it.r2u.anibus.ui.InfoCardManager;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;

import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Refactored UI controller following SOLID principles.
 * Delegates responsibilities to specialized handlers and coordinators.
 * 
 * Responsibilities (Single Responsibility Principle):
 * - FXML event handling
 * - Initialization and dependency wiring
 * - UI component management
 * 
 * Business logic extracted to:
 * - ScanCoordinator: Scan orchestration
 * - Action Handlers: Specific operations (clipboard, export, traceroute)
 * - Strategy implementations: Scan type logic
 */
public class AnibusController {

    /* -- FXML fields ------------------------------------------ */
    @FXML private TextField         hostTextField;
    @FXML private TextField         portsTextField;
    @FXML private Spinner<Integer>  threadSpinner;
    @FXML private Label             resolvedHostLabel;
    @FXML private Label             statusLabel;
    @FXML private Circle            networkDot;
    @FXML private Label             resultCountLabel;
    @FXML private ProgressBar       progressBar;
    @FXML private Button            scanButton;
    @FXML private Button            stopButton;
    @FXML private Button            exportButton;
    @FXML private Button            clearButton;
    @FXML private ComboBox<String>  scanTypeComboBox;
    @FXML private TextArea          consoleTextArea;
    @FXML private VBox              infoCard;
    @FXML private Label             infoIpLabel;
    @FXML private Label             infoHostnameLabel;
    @FXML private Label             infoScanTimeLabel;
    @FXML private Label             infoPortsScannedLabel;
    @FXML private Label             infoOpenPortsLabel;
    @FXML private Label             infoAvgLatencyLabel;

    /* -- JavaScript Analysis FXML fields ---------------------- */
    @FXML private TextField         jsTargetUrlField;
    @FXML private Button            jsAnalyzeButton;
    @FXML private Button            jsStopButton;
    @FXML private ProgressBar       jsProgressBar;
    @FXML private VBox              jsResultsCard;
    @FXML private Label             jsEndpointsLabel;
    @FXML private Label             jsDataStructuresLabel;
    @FXML private Label             jsDbSchemasLabel;
    @FXML private Label             jsSensitiveInfoLabel;
    @FXML private Label             jsArchitectureLabel;
    @FXML private Button            jsExportButton;
    @FXML private Button            jsClearButton;
    @FXML private CheckBox           jsInjectionCheckBox;
    
    /* -- Unified Console FXML fields ------------------------- */
    @FXML private Label             consoleHeaderLabel;

    /* -- State ------------------------------------------------ */
    private final ObservableList<PortScanResult> results = FXCollections.observableArrayList();
    private Task<Void> jsAnalysisTask;
    private JavaScriptAnalysisResult lastJsAnalysisResult;
    private boolean scanningInProgress = false;
    private boolean jsAnalysisInProgress = false;
    private boolean isJsAnalysisMode = false; // Track current console mode
    
    /* -- Core services (Dependency Injection candidates) ------ */
    private PortScannerService     scanner;
    private EnhancedServiceDetector detector;
    private HostResolver           hostResolver;
    private NetworkStatusMonitor   networkStatusMonitor;
    private ConsoleViewManager     consoleViewManager;
    private InfoCardManager        infoCardManager;
    private JavaScriptSecurityAnalyzer jsAnalyzer;
    private SQLInjectionAnalyzer injectionAnalyzer;
    
    /* -- Coordinators and Handlers (SOLID refactoring) -------- */
    private ScanCoordinator        scanCoordinator;
    private ScanActionHandler      scanActionHandler;
    private ClipboardActionHandler clipboardHandler;
    private ExportActionHandler    exportHandler;
    private TracerouteActionHandler tracerouteHandler;

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        initializeCoreServices();
        initializeCoordinatorsAndHandlers();
        setupUI();
        setupEventHandlers();
        startBackgroundServices();
    }
    
    /**
     * Initialize core business services.
     */
    private void initializeCoreServices() {
        scanner = new PortScannerService();
        detector = new EnhancedServiceDetector();
        hostResolver = new HostResolver();
        jsAnalyzer = new JavaScriptSecurityAnalyzer();
        injectionAnalyzer = new SQLInjectionAnalyzer();
        
        // Create and configure UI managers
        Tooltip networkTooltip = new Tooltip("Checking network");
        Tooltip.install(networkDot, networkTooltip);
        networkStatusMonitor = new NetworkStatusMonitor(networkDot, networkTooltip);
        
        consoleViewManager = new ConsoleViewManager(consoleTextArea);
        infoCardManager = new InfoCardManager(
            infoCard, infoIpLabel, infoHostnameLabel,
            infoScanTimeLabel, infoPortsScannedLabel, 
            infoOpenPortsLabel, infoAvgLatencyLabel
        );
    }
    
    /**
     * Initialize coordinators and action handlers (SOLID refactoring).
     */
    private void initializeCoordinatorsAndHandlers() {
        // Setup scan coordinator with strategies
        scanCoordinator = new ScanCoordinator();
        scanCoordinator.registerStrategy("Standard Scanning", 
            new StandardScanStrategy(scanner));
        scanCoordinator.registerStrategy("Service Detection", 
            new ServiceDetectionStrategy(detector));
        scanCoordinator.setActiveStrategy("Standard Scanning");
        
        // Create action handlers
        scanActionHandler = new ScanActionHandler(
            scanCoordinator,
            scanner,
            hostResolver,
            results,
            consoleViewManager,
            infoCardManager,
            this::setStatus,
            new ScanActionHandler.UIComponents(
                hostTextField, scanButton, stopButton, 
                progressBar, resolvedHostLabel
            ),
            cssUrl()
        );
        
        clipboardHandler = new ClipboardActionHandler(this::setStatus);
        exportHandler = new ExportActionHandler(this::setStatus, cssUrl());
        tracerouteHandler = new TracerouteActionHandler(this::setStatus);
    }
    
    /**
     * Setup UI components and bindings.
     */
    private void setupUI() {
        // Bind managed property to visible
        infoCard.managedProperty().bind(infoCard.visibleProperty());
        jsResultsCard.managedProperty().bind(jsResultsCard.visibleProperty());
        
        // Setup console view
        consoleViewManager.setConsoleView(true);
        consoleTextArea.textProperty().addListener((obs, oldText, newText) -> adjustConsoleHeight());
        consoleTextArea.setPrefRowCount(2);
        
        // Setup scan type combo box
        scanTypeComboBox.getItems().addAll("Standard Scanning", "Service Detection");
        scanTypeComboBox.getSelectionModel().selectFirst();
        
        // Setup thread spinner
        threadSpinner.setValueFactory(
            new SpinnerValueFactory.IntegerSpinnerValueFactory(10, 500, 10, 10));
        threadSpinner.setTooltip(new Tooltip("Number of concurrent scanning threads"));
        
        // Setup context menus
        setupConsoleContextMenu();
        setupResolvedHostContextMenu();
    }
    
    /**
     * Setup event handlers and listeners.
     */
    private void setupEventHandlers() {
        // Scan mode changes
        scanTypeComboBox.getSelectionModel().selectedItemProperty()
            .addListener((obs, oldVal, newVal) -> onScanModeChanged(newVal));
        onScanModeChanged(scanTypeComboBox.getSelectionModel().getSelectedItem());
        
        // Monitor scan button state to detect scanning completion
        scanButton.disableProperty().addListener((obs, wasDisabled, isDisabled) -> {
            if (scanningInProgress && !isDisabled) {
                // Scanning has completed, re-enable JS analysis
                scanningInProgress = false;
                enableJsAnalysisControls();
            }
        });
        
        // Results list changes
        results.addListener((javafx.collections.ListChangeListener<PortScanResult>) c -> {
            refreshResultCount();
            infoCardManager.refreshInfoCard(results);
            Platform.runLater(() -> {
                boolean hasResults = !results.isEmpty();
                exportButton.setDisable(!hasResults);
                clearButton.setDisable(!hasResults);
            });
        });
        
        // Host field focus lost
        hostTextField.focusedProperty().addListener((obs, was, nowFocused) -> {
            if (!nowFocused) {
                handleHostFieldFocusLost();
            }
        });
    }
    
    /**
     * Start background services.
     */
    private void startBackgroundServices() {
        refreshResultCount();
        networkStatusMonitor.start();
    }

    /* -- Context menus ---------------------------------------- */
    private void setupConsoleContextMenu() {
        MenuItem copyAll = new MenuItem("Copy all console output");
        copyAll.setOnAction(e -> clipboardHandler.copyConsoleOutput(consoleTextArea));
        
        MenuItem copyResults = new MenuItem("Copy results only");
        copyResults.setOnAction(e -> clipboardHandler.copyAllResults(results));
        
        MenuItem runTraceroute = new MenuItem("Run Traceroute...");
        runTraceroute.setOnAction(e -> tracerouteHandler.runTraceroute(
            hostTextField.getText(), consoleTextArea));
        
        consoleTextArea.setContextMenu(new ContextMenu(
            copyAll, copyResults, new SeparatorMenuItem(), runTraceroute));
    }
    
    private void setupResolvedHostContextMenu() {
        MenuItem copyIP = new MenuItem("Copy");
        copyIP.setOnAction(e -> clipboardHandler.copyResolvedIP(resolvedHostLabel));
        resolvedHostLabel.setContextMenu(new ContextMenu(copyIP));
    }

    /* -- Event handlers --------------------------------------- */
    private void onScanModeChanged(String mode) {
        if (mode == null) return;
        scanCoordinator.setActiveStrategy(mode);
        setStatus(scanCoordinator.getStrategyDescription(mode));
    }
    
    private void handleHostFieldFocusLost() {
        String originalHost = hostTextField.getText().trim();
        String sanitizedHost = hostResolver.sanitizeHost(originalHost);
        
        if (!sanitizedHost.isEmpty()) {
            if (!sanitizedHost.equals(originalHost)) {
                hostTextField.setText(sanitizedHost);
            }
            hostResolver.resolveHostAsync(sanitizedHost, resolvedHostLabel, null);
        } else {
            resolvedHostLabel.setText("");
        }
    }

    /* -- FXML button actions ---------------------------------- */
    @FXML
    protected void onScanButtonClick() {
        if (jsAnalysisInProgress) {
            setStatus("JavaScript analysis is running. Please stop it first.");
            return;
        }
        
        scanningInProgress = true;
        disableJsAnalysisControls();
        
        // Switch to port scanner mode
        switchToPortScannerMode();
        
        scanActionHandler.startScan(
            hostTextField.getText(),
            portsTextField.getText(),
            threadSpinner.getValue()
        );
    }

    @FXML
    protected void onStopButtonClick() {
        scanActionHandler.stopScan();
        scanningInProgress = false;
        enableJsAnalysisControls();
    }

    @FXML
    protected void onExportClick() {
        exportHandler.exportResults(results, consoleTextArea.getScene().getWindow());
    }

    @FXML
    protected void onClearClick() {
        if (isJsAnalysisMode) {
            // If in JS mode, clear JS results
            onJsClearClick();
        } else {
            // If in port scanner mode, clear port results
            results.clear();
            if (consoleTextArea != null) {
                consoleTextArea.clear();
            }
            infoCard.setVisible(false);
            setStatus("Results cleared");
        }
    }

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
            "Anibus Design System  ›  Version: " + version + 
            "\n\nAuthor: Iaroslav Tsymbaliuk\n\nPosition: Intern (2025–2026) @ r2u",
            Alert.AlertType.INFORMATION, cssUrl());
    }

    /* -- UI helpers ------------------------------------------- */
    private void refreshResultCount() {
        Platform.runLater(() -> {
            refreshResultCountLabel();
        });
    }

    private void setStatus(String msg) {
        Platform.runLater(() -> {
            if (statusLabel != null) statusLabel.setText(msg);
        });
    }

    private java.net.URL cssUrl() {
        return getClass().getResource("anibus-style.css");
    }
    
    /* -- JavaScript Analysis Event Handlers ------------------ */
    
    @FXML
    void onJsAnalyzeButtonClick() {
        if (scanningInProgress) {
            setStatus("Port scanning is running. Please stop it first.");
            return;
        }
        
        String targetUrl = jsTargetUrlField.getText().trim();
        
        if (targetUrl.isEmpty()) {
            setStatus("Please enter a target URL");
            return;
        }
        
        // Add protocol if missing
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
            jsTargetUrlField.setText(targetUrl);
        }
        
        jsAnalysisInProgress = true;
        disablePortScannerControls();
        
        setStatus("Starting JavaScript analysis...");
        jsAnalysisTask = createJavaScriptAnalysisTask(targetUrl);
        
        // UI updates
        jsAnalyzeButton.setDisable(true);
        jsStopButton.setDisable(false);
        jsProgressBar.setVisible(true);
        jsResultsCard.setVisible(false);
        
        // Start the task
        Thread thread = new Thread(jsAnalysisTask);
        thread.setDaemon(true);
        thread.start();
    }
    
    @FXML
    void onJsStopButtonClick() {
        if (jsAnalysisTask != null && !jsAnalysisTask.isDone()) {
            jsAnalysisTask.cancel(true);
            setStatus("JavaScript analysis stopped");
        }
        jsAnalysisInProgress = false;
        enablePortScannerControls();
        resetJsAnalysisUI();
    }
    
    @FXML
    void onJsExportClick() {
        if (lastJsAnalysisResult != null) {
            exportHandler.exportJavaScriptAnalysis(lastJsAnalysisResult);
        }
    }
    
    @FXML
    void onJsClearClick() {
        // Simply clear the unified console when in JS mode
        if (isJsAnalysisMode) {
            consoleTextArea.clear();
            clearJsAnalysisResults();
            setStatus("JavaScript analysis results cleared");
            switchToPortScannerMode();
        }
    }
    
    private Task<Void> createJavaScriptAnalysisTask(String targetUrl) {
        final boolean runInjections = jsInjectionCheckBox != null && jsInjectionCheckBox.isSelected();
        return new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                try {
                    Platform.runLater(() -> setStatus("Analyzing JavaScript files..."));
                    
                    // Always use comprehensive analysis
                    JavaScriptAnalysisResult result = jsAnalyzer.analyzeTarget(targetUrl, JavaScriptSecurityAnalyzer.AnalysisDepth.COMPREHENSIVE);
                    
                    // Run injection testing if checkbox is enabled
                    final Map<String, List<SQLInjectionAnalyzer.InjectionResult>> injectionResults;
                    if (runInjections) {
                        Platform.runLater(() -> setStatus("Running SQL injection tests (with CMS detection & form discovery)..."));

                        // Full scan: JS endpoints + CMS profiles + HTML form/link auto-discovery
                        injectionResults = injectionAnalyzer.fullScan(
                                result.getEndpoints(), targetUrl,
                                msg -> Platform.runLater(() -> setStatus(msg))
                        );
                    } else {
                        injectionResults = null;
                    }
                    
                    Platform.runLater(() -> {
                        lastJsAnalysisResult = result;
                        displayJsAnalysisResults(result, injectionResults);
                        String statusMsg = "JavaScript analysis completed (Full analysis)";
                        if (runInjections) {
                            int vulnCount = injectionResults != null ? injectionResults.size() : 0;
                            statusMsg += " + Injection testing (" + vulnCount + " vulnerable endpoints)";
                        }
                        setStatus(statusMsg);
                        jsAnalysisInProgress = false;
                        enablePortScannerControls();
                        resetJsAnalysisUI();
                    });
                    
                } catch (Exception e) {
                    Platform.runLater(() -> {
                        setStatus("JavaScript analysis failed: " + e.getMessage());
                        jsAnalysisInProgress = false;
                        enablePortScannerControls();
                        resetJsAnalysisUI();
                    });
                }
                return null;
            }
        };
    }
    
    private void displayJsAnalysisResults(JavaScriptAnalysisResult result, 
            Map<String, List<SQLInjectionAnalyzer.InjectionResult>> injectionResults) {
        // Update summary labels
        jsEndpointsLabel.setText(String.valueOf(result.getEndpoints().size()));
        jsDataStructuresLabel.setText(String.valueOf(result.getDataStructures().size()));
        jsDbSchemasLabel.setText(String.valueOf(result.getDatabaseSchemas().size()));
        jsSensitiveInfoLabel.setText(String.valueOf(result.getSensitiveInfo().size()));
        jsArchitectureLabel.setText(result.getArchitecture() != null ? 
            result.getArchitecture().getFramework().toString() : "Unknown");
        
        // Build detailed results text
        StringBuilder detailedResults = new StringBuilder();
        detailedResults.append(result.getSummary()).append("\n\n");
        
        // Add endpoints
        // Add discovered JS sources
        detailedResults.append("=== DISCOVERED SOURCES ===\n");
        if (result.getJsFiles() != null && !result.getJsFiles().isEmpty()) {
            result.getJsFiles().forEach(file -> 
                detailedResults.append("• ").append(file).append("\n"));
        } else {
            detailedResults.append("• No JavaScript sources found\n");
        }
        
        // Add endpoints
        detailedResults.append("\n=== DISCOVERED ENDPOINTS ===\n");
        result.getEndpoints().forEach(endpoint -> 
            detailedResults.append("• ").append(endpoint.toString()).append("\n"));
        
        // Add data structures
        detailedResults.append("\n=== DATA STRUCTURES ===\n");
        result.getDataStructures().forEach(structure -> 
            detailedResults.append("• ").append(structure.toString()).append("\n"));
        
        // Add database schemas
        detailedResults.append("\n=== INFERRED DATABASE SCHEMAS ===\n");
        result.getDatabaseSchemas().forEach(schema -> 
            detailedResults.append("• ").append(schema.toString()).append("\n"));
        
        // Add sensitive information
        detailedResults.append("\n=== SENSITIVE INFORMATION ===\n");
        result.getSensitiveInfo().forEach(leak -> 
            detailedResults.append("• ").append(leak.toString()).append("\n"));
        
        // Add architecture info
        if (result.getArchitecture() != null) {
            detailedResults.append("\n=== ARCHITECTURE ANALYSIS ===\n");
            detailedResults.append("• ").append(result.getArchitecture().toString()).append("\n");
            detailedResults.append("• Services: ").append(result.getArchitecture().getServices()).append("\n");
            detailedResults.append("• Middlewares: ").append(result.getArchitecture().getMiddlewares()).append("\n");
        }
        
        // Add injection testing results if available
        if (injectionResults != null) {
            detailedResults.append("\n").append(injectionAnalyzer.formatResults(injectionResults));
        }
        
        // Add errors if any
        if (!result.getErrors().isEmpty()) {
            detailedResults.append("\n=== ERRORS ===\n");
            result.getErrors().forEach(error -> 
                detailedResults.append("• ").append(error).append("\n"));
        }
        
        // Display in unified console
        consoleTextArea.setText(detailedResults.toString());
        jsResultsCard.setVisible(true);
        
        // Switch to JavaScript analysis mode  
        switchToJsAnalysisMode();
    }
    
    private void resetJsAnalysisUI() {
        Platform.runLater(() -> {
            jsAnalyzeButton.setDisable(false);
            jsStopButton.setDisable(true);
            jsProgressBar.setVisible(false);
        });
    }
    
    private void clearJsAnalysisResults() {
        jsEndpointsLabel.setText("0");
        jsDataStructuresLabel.setText("0");
        jsDbSchemasLabel.setText("0");
        jsSensitiveInfoLabel.setText("0");
        jsArchitectureLabel.setText("-");
        lastJsAnalysisResult = null;
    }
    
    private void adjustConsoleHeight() {
        Platform.runLater(() -> {
            String text = consoleTextArea.getText();
            if (text == null || text.isEmpty()) {
                consoleTextArea.setPrefRowCount(2);
                return;
            }
            int lineCount = text.split("\n", -1).length;
            consoleTextArea.setPrefRowCount(Math.max(2, lineCount + 1));
        });
    }
    
    /* -- Mutual Exclusion Control Methods -------------------- */
    
    /**
     * Disables port scanner controls when JavaScript analysis is running.
     */
    private void disablePortScannerControls() {
        Platform.runLater(() -> {
            hostTextField.setDisable(true);
            portsTextField.setDisable(true);
            threadSpinner.setDisable(true);
            scanTypeComboBox.setDisable(true);
            scanButton.setDisable(true);
        });
    }
    
    /**
     * Enables port scanner controls when JavaScript analysis stops.
     */
    private void enablePortScannerControls() {
        if (!scanningInProgress) { // Only enable if scanning is not running
            Platform.runLater(() -> {
                hostTextField.setDisable(false);
                portsTextField.setDisable(false);
                threadSpinner.setDisable(false);
                scanTypeComboBox.setDisable(false);
                scanButton.setDisable(false);
            });
        }
    }
    
    /**
     * Disables JavaScript analysis controls when port scanning is running.
     */
    private void disableJsAnalysisControls() {
        Platform.runLater(() -> {
            jsTargetUrlField.setDisable(true);
            jsAnalyzeButton.setDisable(true);
            if (jsInjectionCheckBox != null) jsInjectionCheckBox.setDisable(true);
        });
    }
    
    /**
     * Enables JavaScript analysis controls when port scanning stops.
     */
    private void enableJsAnalysisControls() {
        if (!jsAnalysisInProgress) { // Only enable if JS analysis is not running
            Platform.runLater(() -> {
                jsTargetUrlField.setDisable(false);
                jsAnalyzeButton.setDisable(false);
                if (jsInjectionCheckBox != null) jsInjectionCheckBox.setDisable(false);
            });
        }
    }
    
    /* -- Console Mode Management Methods ---------------------- */
    
    /**
     * Switch console to JavaScript analysis mode.
     */
    private void switchToJsAnalysisMode() {
        Platform.runLater(() -> {
            isJsAnalysisMode = true;
            consoleHeaderLabel.setText("JavaScript Analysis Results");
            resultCountLabel.setText("Analysis completed");
            
            // Show JS export button, hide port scanner export
            exportButton.setVisible(false);
            jsExportButton.setVisible(true);
            jsExportButton.setDisable(false);
            
            clearButton.setDisable(false);
        });
    }
    
    /**
     * Switch console to port scanner mode.
     */
    private void switchToPortScannerMode() {
        Platform.runLater(() -> {
            isJsAnalysisMode = false;
            consoleHeaderLabel.setText("Console Output");
            refreshResultCountLabel();
            
            // Show port scanner export button, hide JS export
            exportButton.setVisible(true);
            jsExportButton.setVisible(false);
            
            // Update clear button state based on results
            boolean hasResults = !results.isEmpty();
            clearButton.setDisable(!hasResults);
            exportButton.setDisable(!hasResults);
        });
    }
    
    /**
     * Updates result count label based on current mode.
     */
    private void refreshResultCountLabel() {
        if (isJsAnalysisMode) {
            resultCountLabel.setText("Analysis completed");
        } else {
            int n = results.size();
            resultCountLabel.setText(
                n == 0 ? "No open ports" : 
                n == 1 ? "1 open port" : 
                n + " open ports"
            );
        }
    }
    
    /**
     * Shutdown all services and cleanup resources.
     * Called when application closes.
     */
    public void shutdownExecutor() {
        if (scanCoordinator != null) {
            scanCoordinator.shutdown();
        }
        if (networkStatusMonitor != null) {
            networkStatusMonitor.stop();
        }
        if (jsAnalyzer != null) {
            jsAnalyzer.shutdown();
        }
        if (injectionAnalyzer != null) {
            injectionAnalyzer.shutdown();
        }
    }
}
