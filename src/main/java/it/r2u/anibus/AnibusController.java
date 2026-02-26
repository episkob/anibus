package it.r2u.anibus;

import it.r2u.anibus.coordinator.*;
import it.r2u.anibus.handlers.*;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.network.NetworkStatusMonitor;
import it.r2u.anibus.service.EnhancedServiceDetector;
import it.r2u.anibus.service.PortScannerService;
import it.r2u.anibus.ui.AlertHelper;
import it.r2u.anibus.ui.ConsoleViewManager;
import it.r2u.anibus.ui.InfoCardManager;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;

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

    /* -- State ------------------------------------------------ */
    private final ObservableList<PortScanResult> results = FXCollections.observableArrayList();
    
    /* -- Core services (Dependency Injection candidates) ------ */
    private PortScannerService     scanner;
    private EnhancedServiceDetector detector;
    private HostResolver           hostResolver;
    private NetworkStatusMonitor   networkStatusMonitor;
    private ConsoleViewManager     consoleViewManager;
    private InfoCardManager        infoCardManager;
    
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
        scanActionHandler.startScan(
            hostTextField.getText(),
            portsTextField.getText(),
            threadSpinner.getValue()
        );
    }

    @FXML
    protected void onStopButtonClick() {
        scanActionHandler.stopScan();
    }

    @FXML
    protected void onExportClick() {
        exportHandler.exportResults(results, consoleTextArea.getScene().getWindow());
    }

    @FXML
    protected void onClearClick() {
        results.clear();
        if (consoleTextArea != null) {
            consoleTextArea.clear();
        }
        infoCard.setVisible(false);
        setStatus("Results cleared");
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
            int n = results.size();
            if (resultCountLabel != null) {
                resultCountLabel.setText(
                    n == 0 ? "No open ports" : 
                    n == 1 ? "1 open port" : 
                    n + " open ports"
                );
            }
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
    }
}
