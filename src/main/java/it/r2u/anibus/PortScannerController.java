package it.r2u.anibus;

import it.r2u.anibus.coordinator.*;
import it.r2u.anibus.handlers.*;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.service.EnhancedServiceDetector;
import it.r2u.anibus.service.PortScannerService;
import it.r2u.anibus.ui.ConsoleViewManager;
import it.r2u.anibus.ui.InfoCardManager;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;

import java.net.URL;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

/**
 * Controller for the Port Scanner tab.
 * Handles port scanning, service detection, and result display.
 */
public class PortScannerController {

    /* -- FXML fields ------------------------------------------ */
    @FXML private TextField         hostTextField;
    @FXML private TextField         portsTextField;
    @FXML private Spinner<Integer>  threadSpinner;
    @FXML private Label             resolvedHostLabel;
    @FXML private ProgressBar       progressBar;
    @FXML private Button            scanButton;
    @FXML private Button            stopButton;
    @FXML private ComboBox<String>  scanTypeComboBox;
    @FXML private TextArea          consoleTextArea;
    @FXML private TextArea          liveLogArea;
    @FXML private Label             resultCountLabel;
    @FXML private Button            exportButton;
    @FXML private Button            clearButton;
    @FXML private VBox              infoCard;
    @FXML private Label             infoIpLabel;
    @FXML private Label             infoHostnameLabel;
    @FXML private Label             infoScanTimeLabel;
    @FXML private Label             infoPortsScannedLabel;
    @FXML private Label             infoOpenPortsLabel;
    @FXML private Label             infoAvgLatencyLabel;

    /* -- State ------------------------------------------------ */
    private final ObservableList<PortScanResult> results = FXCollections.observableArrayList();

    /* -- Services --------------------------------------------- */
    private PortScannerService      scanner;
    private EnhancedServiceDetector detector;
    private HostResolver            hostResolver;
    private ConsoleViewManager      consoleViewManager;
    private InfoCardManager         infoCardManager;

    /* -- Coordinators and Handlers ---------------------------- */
    private ScanCoordinator         scanCoordinator;
    private ScanActionHandler       scanActionHandler;
    private ClipboardActionHandler  clipboardHandler;
    private ExportActionHandler     exportHandler;
    private TracerouteActionHandler tracerouteHandler;

    /* -- External references ---------------------------------- */
    private Consumer<String> statusSetter;
    private URL cssUrl;

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        // Basic UI setup that doesn't need external context
        infoCard.managedProperty().bind(infoCard.visibleProperty());

        scanTypeComboBox.getItems().addAll("Standard Scanning", "Service Detection");
        scanTypeComboBox.getSelectionModel().selectFirst();

        threadSpinner.setValueFactory(
            new SpinnerValueFactory.IntegerSpinnerValueFactory(10, 500, 10, 10));
        threadSpinner.setTooltip(new Tooltip("Number of concurrent scanning threads"));

        consoleTextArea.textProperty().addListener((obs, o, n) -> adjustConsoleHeight());
        consoleTextArea.setPrefRowCount(2);
    }

    /**
     * Called by the parent controller after FXML loading to inject shared context.
     */
    public void setContext(Consumer<String> statusSetter, URL cssUrl) {
        this.statusSetter = statusSetter;
        this.cssUrl = cssUrl;

        initializeServices();
        initializeHandlers();
        setupEventHandlers();
        refreshResultCount();
    }

    private void initializeServices() {
        scanner = new PortScannerService();
        detector = new EnhancedServiceDetector();
        hostResolver = new HostResolver();
        consoleViewManager = new ConsoleViewManager(consoleTextArea);
        consoleViewManager.setConsoleView(true);

        infoCardManager = new InfoCardManager(
            infoCard, infoIpLabel, infoHostnameLabel,
            infoScanTimeLabel, infoPortsScannedLabel,
            infoOpenPortsLabel, infoAvgLatencyLabel
        );
    }

    private void initializeHandlers() {
        scanCoordinator = new ScanCoordinator();
        scanCoordinator.registerStrategy("Standard Scanning",
            new StandardScanStrategy(scanner));
        scanCoordinator.registerStrategy("Service Detection",
            new ServiceDetectionStrategy(detector));
        scanCoordinator.setActiveStrategy("Standard Scanning");

        scanActionHandler = new ScanActionHandler(
            scanCoordinator, scanner, hostResolver,
            results, consoleViewManager, infoCardManager,
            this::setStatus,
            new ScanActionHandler.UIComponents(
                hostTextField, scanButton, stopButton,
                progressBar, resolvedHostLabel
            ),
            cssUrl
        );
        scanActionHandler.setLogCallback(this::appendLog);

        clipboardHandler = new ClipboardActionHandler(this::setStatus);
        exportHandler = new ExportActionHandler(this::setStatus, cssUrl);
        tracerouteHandler = new TracerouteActionHandler(this::setStatus);
    }

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
                exportButton.setDisable(results.isEmpty());
                clearButton.setDisable(false);
            });
        });

        // Always enable Clear when console has content
        consoleTextArea.textProperty().addListener((obs, o, n) ->
            clearButton.setDisable(n == null || n.isEmpty()));

        // Host field focus lost → resolve DNS
        hostTextField.focusedProperty().addListener((obs, was, nowFocused) -> {
            if (!nowFocused) handleHostFieldFocusLost();
        });

        // Context menus
        setupConsoleContextMenu();
        setupResolvedHostContextMenu();
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
    void onScanButtonClick() {
        scanActionHandler.startScan(
            hostTextField.getText(),
            portsTextField.getText(),
            threadSpinner.getValue()
        );
    }

    @FXML
    void onStopButtonClick() {
        scanActionHandler.stopScan();
    }

    @FXML
    void onExportClick() {
        exportHandler.exportResults(results, consoleTextArea.getScene().getWindow());
    }

    @FXML
    void onClearClick() {
        results.clear();
        consoleTextArea.clear();
        liveLogArea.clear();
        infoCard.setVisible(false);
        setStatus("Results cleared");
    }

    /* -- Helpers ---------------------------------------------- */
    private void setStatus(String msg) {
        if (statusSetter != null) {
            statusSetter.accept(msg);
        }
    }

    private static final DateTimeFormatter LOG_TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    void appendLog(String msg) {
        Platform.runLater(() -> {
            if (liveLogArea == null) return;
            liveLogArea.appendText("[" + LocalTime.now().format(LOG_TIME) + "] " + msg + "\n");
        });
    }

    private void refreshResultCount() {
        Platform.runLater(() -> {
            int n = results.size();
            resultCountLabel.setText(
                n == 0 ? "No open ports" :
                n == 1 ? "1 open port" :
                n + " open ports"
            );
        });
    }

    private void adjustConsoleHeight() { /* no-op: layout managed by VBox.vgrow */ }

    /**
     * Shutdown scan coordinator resources.
     */
    public void shutdown() {
        if (scanCoordinator != null) scanCoordinator.shutdown();
    }
}
