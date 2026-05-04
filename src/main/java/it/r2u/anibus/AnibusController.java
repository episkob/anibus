package it.r2u.anibus;

import it.r2u.anibus.coordinator.*;
import it.r2u.anibus.handlers.*;
import it.r2u.anibus.model.DataStructureInfo;
import it.r2u.anibus.model.DatabaseSchemaInfo;
import it.r2u.anibus.model.EndpointInfo;
import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.network.NetworkStatusMonitor;
import it.r2u.anibus.service.EnhancedServiceDetector;
import it.r2u.anibus.service.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.service.PortScannerService;
import it.r2u.anibus.service.SQLInjectionAnalyzer;
import it.r2u.anibus.service.WebSourceAnalyzer;
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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

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
    @FXML private TextArea          consoleTextArea;
    @FXML private VBox              infoCard;
    @FXML private Label             infoIpLabel;
    @FXML private Label             infoHostnameLabel;
    @FXML private Label             infoScanTimeLabel;
    @FXML private Label             infoPortsScannedLabel;
    @FXML private Label             infoOpenPortsLabel;
    @FXML private Label             infoAvgLatencyLabel;

    /* -- JavaScript Analysis FXML fields ---------------------- */
    @FXML private CheckBox          jsAnalysisCheckBox;
    @FXML private VBox              jsResultsCard;
    @FXML private Label             jsEndpointsLabel;
    @FXML private Label             jsDataStructuresLabel;
    @FXML private Label             jsDbSchemasLabel;
    @FXML private Label             jsSensitiveInfoLabel;
    @FXML private Label             jsArchitectureLabel;
    @FXML private Button            jsExportButton;
    @FXML private CheckBox          jsInjectionCheckBox;
    @FXML private TreeView<String>  jsStructureTree;
    
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
        scanCoordinator.setActiveStrategy("Service Detection");
        
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

        
        // Monitor scan button state to detect scanning completion
        scanButton.disableProperty().addListener((obs, wasDisabled, isDisabled) -> {
            if (scanningInProgress && !isDisabled) {
                scanningInProgress = false;
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

    
    private void handleHostFieldFocusLost() {
        String originalHost = hostTextField.getText().trim();
        
        // Skip sanitization if JS analysis is selected or input looks like a URL
        if ((jsAnalysisCheckBox != null && jsAnalysisCheckBox.isSelected()) 
                || originalHost.toLowerCase().startsWith("http://")
                || originalHost.toLowerCase().startsWith("https://")) {
            return;
        }
        
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
        boolean runJsAnalysis = jsAnalysisCheckBox != null && jsAnalysisCheckBox.isSelected();
        boolean runInjections = jsInjectionCheckBox != null && jsInjectionCheckBox.isSelected();
        
        if (runJsAnalysis || runInjections) {
            // Run JavaScript analysis (and/or SQL injection) using the host field
            startJsAnalysis();
        } else {
            // Run port scan
            scanningInProgress = true;
            switchToPortScannerMode();
            
            scanActionHandler.startScan(
                hostTextField.getText(),
                portsTextField.getText(),
                threadSpinner.getValue()
            );
        }
    }

    @FXML
    protected void onStopButtonClick() {
        if (jsAnalysisInProgress && jsAnalysisTask != null && !jsAnalysisTask.isDone()) {
            jsAnalysisTask.cancel(true);
            jsAnalysisInProgress = false;
            setStatus("JavaScript analysis stopped");
            resetScanUI();
        } else {
            scanActionHandler.stopScan();
            scanningInProgress = false;
        }
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
        String version = "1.5.0";
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
    
    /* -- JavaScript Analysis --------------------------------- */
    
    private void startJsAnalysis() {
        String targetUrl = hostTextField.getText().trim();
        
        if (targetUrl.isEmpty()) {
            setStatus("Please enter a target URL");
            return;
        }
        
        // Add protocol if missing
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
            hostTextField.setText(targetUrl);
        }
        
        jsAnalysisInProgress = true;
        
        setStatus("Starting JavaScript analysis...");
        jsAnalysisTask = createJavaScriptAnalysisTask(targetUrl);
        
        // UI updates
        scanButton.setDisable(true);
        stopButton.setDisable(false);
        progressBar.setVisible(true);
        jsResultsCard.setVisible(false);
        
        // Start the task
        Thread thread = new Thread(jsAnalysisTask);
        thread.setDaemon(true);
        thread.start();
    }
    
    @SuppressWarnings("unused") // Referenced from FXML
    @FXML
    void onJsExportClick() {
        if (lastJsAnalysisResult != null) {
            exportHandler.exportJavaScriptAnalysis(lastJsAnalysisResult, consoleTextArea.getText());
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
                        resetScanUI();
                    });
                    
                } catch (Exception e) {
                    Platform.runLater(() -> {
                        setStatus("JavaScript analysis failed: " + e.getMessage());
                        jsAnalysisInProgress = false;
                        resetScanUI();
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

        // ── Populate Tree View ─────────────────────────────────────────────
        populateStructureTree(result.getDataStructures());

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

        // Attack surface view with risk-oriented endpoint grouping
        detailedResults.append("\n=== ATTACK SURFACE (RISK CLASSIFICATION) ===\n");
        appendAttackSurfaceSection(detailedResults, result);

        detailedResults.append("\n=== DYNAMIC ENDPOINTS (FUZZING TARGETS) ===\n");
        appendDynamicEndpointsSection(detailedResults, result);
        
        // Add endpoints
        detailedResults.append("\n=== DISCOVERED ENDPOINTS ===\n");
        result.getEndpoints().forEach(endpoint -> 
            detailedResults.append("• ").append(endpoint.toString()).append("\n"));

        // Entity map with user/media/error-oriented object correlation
        detailedResults.append("\n=== ENTITY MAP ===\n");
        appendEntityMapSection(detailedResults, result);
        
        // Add data structures
        detailedResults.append("\n=== DATA STRUCTURES ===\n");
        result.getDataStructures().forEach(structure -> 
            detailedResults.append("• ").append(structure.toString()).append("\n"));
        
        // Add database schemas
        detailedResults.append("\n=== INFERRED DATABASE SCHEMAS ===\n");
        result.getDatabaseSchemas().forEach(schema -> 
            detailedResults.append("• ").append(schema.toString()).append("\n"));

        detailedResults.append("\n=== SCHEMA INFERENCE (DEEP) ===\n");
        appendSchemaInferenceDeepSection(detailedResults, result);
        
        // Add sensitive information - grouped by priority tier and service
        detailedResults.append("\n=== SENSITIVE INFORMATION ===\n");
        appendSensitiveInfoSection(detailedResults, result.getSensitiveInfo(), result.getArchitecture());

        detailedResults.append("\n=== SENSITIVE DEEP-DIVE ===\n");
        appendSensitiveDeepDiveSection(detailedResults, result);

        detailedResults.append("\n=== DEPENDENCY TREE ===\n");
        appendDependencyTreeSection(detailedResults, result);
        
        // Add architecture info
        if (result.getArchitecture() != null) {
            detailedResults.append("\n=== ARCHITECTURE ANALYSIS ===\n");
            detailedResults.append("• ").append(result.getArchitecture().toString()).append("\n");
            detailedResults.append("• Services: ").append(result.getArchitecture().getServices()).append("\n");
            detailedResults.append("• Middlewares: ").append(result.getArchitecture().getMiddlewares()).append("\n");
        }

        detailedResults.append("\n=== ANALYSIS TIMING ===\n");
        appendAnalysisTimingSection(detailedResults, result);
        
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

    private void appendAttackSurfaceSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<EndpointInfo> endpoints = result.getEndpoints() != null ? result.getEndpoints() : java.util.Collections.emptyList();
        if (endpoints.isEmpty()) {
            sb.append("  No endpoints discovered.\n");
            return;
        }

        Set<String> authKeywords = Set.of("login", "auth", "password", "qr_auth", "get_anonym_token");
        Set<String> knownExternal = Set.of(
            "tns-counter.ru", "googletagmanager.com", "facebook.net",
            "mail.ru", "top-fwz1.mail.ru", "vk-analytics.net"
        );

        List<EndpointInfo> authEndpoints = new java.util.ArrayList<>();
        Map<String, List<EndpointInfo>> internalServices = new java.util.LinkedHashMap<>();
        Map<String, List<EndpointInfo>> thirdParty = new java.util.LinkedHashMap<>();

        String targetHost = extractHost(result.getTargetUrl());
        String targetRoot = normalizeRootDomain(targetHost);

        for (EndpointInfo ep : endpoints) {
            String urlLower = ep.getUrl() != null ? ep.getUrl().toLowerCase(Locale.ROOT) : "";
            if (authKeywords.stream().anyMatch(urlLower::contains)) {
                authEndpoints.add(ep);
            }

            String host = extractHost(ep.getUrl());
            if (host == null || host.isBlank()) continue;

            if (isInternalServiceHost(host, targetHost, targetRoot)) {
                internalServices.computeIfAbsent(host, k -> new java.util.ArrayList<>()).add(ep);
            }
            if (isThirdPartyHost(host, targetRoot, knownExternal)) {
                thirdParty.computeIfAbsent(host, k -> new java.util.ArrayList<>()).add(ep);
            }
        }

        sb.append("  Auth Endpoints: ").append(authEndpoints.size()).append("\n");
        for (EndpointInfo ep : authEndpoints) {
            sb.append("    • ").append(ep).append("\n");
        }

        sb.append("  Internal Services (microservice subdomains): ").append(internalServices.size()).append("\n");
        internalServices.forEach((host, eps) -> {
            sb.append("    • ").append(host).append("  (").append(eps.size()).append(" endpoint(s))\n");
        });

        sb.append("  Third-party Data Leakage Targets: ").append(thirdParty.size()).append("\n");
        thirdParty.forEach((host, eps) -> {
            sb.append("    • ").append(host).append("  (").append(eps.size()).append(" call(s))\n");
        });

        if (result.getArchitecture() != null) {
            sb.append("  Microservice Map: ");
            List<String> services = result.getArchitecture().getServices();
            sb.append((services == null || services.isEmpty()) ? "none detected" : String.join(", ", services));
            sb.append("\n");

            sb.append("  Middleware Stack: ");
            List<String> mids = result.getArchitecture().getMiddlewares();
            sb.append((mids == null || mids.isEmpty()) ? "none detected" : String.join(", ", mids));
            sb.append("\n");
        }
    }

    private void appendDynamicEndpointsSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<EndpointInfo> endpoints = result.getEndpoints() != null ? result.getEndpoints() : java.util.Collections.emptyList();
        if (endpoints.isEmpty()) {
            sb.append("  No endpoints for dynamic/fuzzing analysis.\n");
            return;
        }

        List<EndpointInfo> dynamic = endpoints.stream().filter(EndpointInfo::isDynamic).toList();
        if (dynamic.isEmpty()) {
            sb.append("  No dynamic URL templates detected.\n");
        } else {
            sb.append("  Dynamic Templates:\n");
            for (EndpointInfo ep : dynamic) {
                String params = (ep.getParameters() == null || ep.getParameters().isEmpty())
                    ? "(params: n/a)"
                    : "(params: " + String.join(", ", ep.getParameters()) + ")";
                sb.append("    • ").append(ep.getHttpMethod()).append(" ")
                    .append(ep.getUrl()).append(" ").append(params).append("\n");
            }
        }

        String[] hiddenPanels = {"/bugs?act=reporter", "/settings?f=chgpass", "/al_loader_part_configs.php"};
        sb.append("  Hidden Admin Panels / Internal Tooling:\n");
        boolean found = false;
        for (EndpointInfo ep : endpoints) {
            String u = ep.getUrl() != null ? ep.getUrl().toLowerCase(Locale.ROOT) : "";
            for (String panel : hiddenPanels) {
                if (u.contains(panel.toLowerCase(Locale.ROOT))) {
                    sb.append("    • ").append(ep).append("\n");
                    found = true;
                }
            }
        }
        if (!found) {
            sb.append("    • Not found in discovered endpoint set\n");
        }
    }

    private void appendEntityMapSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<DataStructureInfo> structures = result.getDataStructures() != null ? result.getDataStructures() : java.util.Collections.emptyList();
        if (structures.isEmpty()) {
            sb.append("  No data structures available for entity mapping.\n");
            return;
        }

        Set<String> userFields = Set.of("user_id", "screen_name", "id_iframe_params", "access_token");
        Set<String> mediaFields = Set.of("audio_id", "track_id", "album", "playlist", "duration", "playback_duration");

        List<String> userHits = collectEntityFieldHits(structures, userFields);
        List<String> mediaHits = collectEntityFieldHits(structures, mediaFields);

        sb.append("  User Profile Construction:\n");
        if (userHits.isEmpty()) sb.append("    • No direct user profile fields found\n");
        else userHits.forEach(hit -> sb.append("    • ").append(hit).append("\n"));

        sb.append("  Media & Metadata:\n");
        if (mediaHits.isEmpty()) sb.append("    • No media-specific structures found\n");
        else mediaHits.forEach(hit -> sb.append("    • ").append(hit).append("\n"));

        sb.append("  Error Tracking Structures:\n");
        boolean foundErrorTracking = false;
        for (DataStructureInfo ds : structures) {
            Set<String> keys = ds.getProperties().keySet().stream()
                .map(k -> k.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toSet());
            if (keys.contains("lineno") && keys.contains("colno") && keys.contains("source")) {
                foundErrorTracking = true;
                sb.append("    • ").append(ds.getName())
                    .append(" -> lineno/colno/source present (possible client error report payload)\n");
            }
        }
        if (!foundErrorTracking) {
            sb.append("    • No explicit request_payload with lineno/colno/source detected\n");
        }
    }

    private void appendSchemaInferenceDeepSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<DatabaseSchemaInfo> schemas = result.getDatabaseSchemas() != null ? result.getDatabaseSchemas() : java.util.Collections.emptyList();
        if (schemas.isEmpty()) {
            sb.append("  No inferred schemas.\n");
            return;
        }

        for (DatabaseSchemaInfo schema : schemas) {
            sb.append("  • ").append(schema.getDatabaseType())
                .append(" :: ").append(schema.getTableName())
                .append("  [confidence: ").append(String.format("%.0f%%", schema.getConfidence() * 100)).append("]\n");

            if (!schema.getColumns().isEmpty()) {
                sb.append("      Fields (type inference):\n");
                schema.getColumns().forEach((col, type) ->
                    sb.append("        - ").append(col).append(" : ").append(type).append("\n"));
                appendSchemaSemanticGroups(sb, schema.getColumns());
            }

            if (!schema.getRelationships().isEmpty()) {
                sb.append("      Cross-links / foreign keys:\n");
                schema.getRelationships().forEach(rel ->
                    sb.append("        - ").append(rel).append("\n"));
            }
        }
    }

    private void appendSchemaSemanticGroups(StringBuilder sb, Map<String, String> columns) {
        if (columns == null || columns.isEmpty()) return;

        Set<String> logSessionPattern = Set.of("msg", "loc", "module", "host", "id", "realloc", "lang");
        List<String> matched = new java.util.ArrayList<>();
        for (String key : columns.keySet()) {
            if (logSessionPattern.contains(key.toLowerCase(Locale.ROOT))) {
                matched.add(key + ":" + columns.get(key));
            }
        }
        if (!matched.isEmpty()) {
            sb.append("      Variable relation map (log/session-like payload):\n");
            matched.forEach(m -> sb.append("        - ").append(m).append("\n"));
        }

        List<String> objects = columns.entrySet().stream()
            .filter(e -> "object".equalsIgnoreCase(e.getValue()))
            .map(Map.Entry::getKey)
            .toList();
        List<String> arrays = columns.entrySet().stream()
            .filter(e -> "array".equalsIgnoreCase(e.getValue()))
            .map(Map.Entry::getKey)
            .toList();
        List<String> numbers = columns.entrySet().stream()
            .filter(e -> "number".equalsIgnoreCase(e.getValue()))
            .map(Map.Entry::getKey)
            .toList();

        if (!objects.isEmpty() || !arrays.isEmpty() || !numbers.isEmpty()) {
            sb.append("      Type classes:\n");
            if (!objects.isEmpty()) sb.append("        - object: ").append(String.join(", ", objects)).append("\n");
            if (!arrays.isEmpty()) sb.append("        - array: ").append(String.join(", ", arrays)).append("\n");
            if (!numbers.isEmpty()) sb.append("        - number: ").append(String.join(", ", numbers)).append("\n");
        }
    }

    private void appendSensitiveDeepDiveSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<WebSourceAnalyzer.LeakInfo> leaks = result.getSensitiveInfo() != null ? result.getSensitiveInfo() : java.util.Collections.emptyList();
        if (leaks.isEmpty()) {
            sb.append("  No sensitive findings for deep-dive.\n");
            return;
        }

        int shown = 0;
        for (WebSourceAnalyzer.LeakInfo leak : leaks) {
            if (shown >= 25) break;
            String module = leak.getService() != null ? leak.getService() : inferModuleFromLeak(leak);
            sb.append("  • [").append(module).append("] ")
              .append(leak.getType()).append(" -> ")
              .append(truncate(leak.getValue(), 140));

            if (leak.isPlaceholder()) sb.append("  [Default/Placeholder]");

            if (leak.getType() != null && leak.getType().toLowerCase(Locale.ROOT).contains("access token")) {
                String tokenType = inferTokenType(leak);
                if (tokenType != null) sb.append("  [TokenType: ").append(tokenType).append("]");
            }
            sb.append("\n");
            shown++;
        }

        List<String> historyRoutes = leaks.stream()
            .filter(l -> l.getType() != null && l.getType().toLowerCase(Locale.ROOT).contains("history locations"))
            .map(WebSourceAnalyzer.LeakInfo::getValue)
            .filter(v -> v != null && !v.isBlank())
            .toList();
        if (!historyRoutes.isEmpty()) {
            sb.append("  History Locations:\n");
            historyRoutes.forEach(v -> sb.append("    • ").append(v).append("\n"));
        }
    }

    private List<String> collectEntityFieldHits(List<DataStructureInfo> structures, Set<String> interestingFields) {
        List<String> hits = new java.util.ArrayList<>();
        for (DataStructureInfo ds : structures) {
            for (Map.Entry<String, String> entry : ds.getProperties().entrySet()) {
                String key = entry.getKey().toLowerCase(Locale.ROOT);
                if (interestingFields.contains(key)) {
                    hits.add(ds.getName() + "." + entry.getKey() + " : " + entry.getValue());
                }
            }
        }
        return hits;
    }

    private String inferModuleFromLeak(WebSourceAnalyzer.LeakInfo leak) {
        String combined = (leak.getType() + " " + leak.getValue() + " " + leak.getContext()).toLowerCase(Locale.ROOT);
        if (combined.contains("auth") || combined.contains("login") || combined.contains("token")) return "auth";
        if (combined.contains("payment") || combined.contains("billing") || combined.contains("checkout")) return "payment";
        if (combined.contains("order")) return "order";
        if (combined.contains("cart")) return "cart";
        if (combined.contains("profile") || combined.contains("user")) return "user";
        return "general";
    }

    private String inferTokenType(WebSourceAnalyzer.LeakInfo leak) {
        String combined = (leak.getValue() + " " + leak.getContext());
        String[] markers = {
            "VKSDKGeneralSuperAppToken", "VKSDKRequestSuperAppToken", "SuperAppToken", "Bearer", "JWT", "OAuth"
        };
        for (String marker : markers) {
            if (combined.contains(marker)) return marker;
        }
        return null;
    }

    private void appendDependencyTreeSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<WebSourceAnalyzer.LeakInfo> leaks = result.getSensitiveInfo() != null ? result.getSensitiveInfo() : java.util.Collections.emptyList();
        List<DataStructureInfo> structures = result.getDataStructures() != null ? result.getDataStructures() : java.util.Collections.emptyList();
        List<EndpointInfo> endpoints = result.getEndpoints() != null ? result.getEndpoints() : java.util.Collections.emptyList();

        List<WebSourceAnalyzer.LeakInfo> tokenLeaks = leaks.stream()
            .filter(l -> {
                String t = l.getType() != null ? l.getType().toLowerCase(Locale.ROOT) : "";
                String v = l.getValue() != null ? l.getValue().toLowerCase(Locale.ROOT) : "";
                return t.contains("token") || v.contains("access_token");
            })
            .limit(5)
            .toList();

        if (tokenLeaks.isEmpty()) {
            sb.append("  No token-centered dependency chain detected.\n");
            return;
        }

        for (WebSourceAnalyzer.LeakInfo tokenLeak : tokenLeaks) {
            String tokenType = inferTokenType(tokenLeak);
            sb.append("  • Token: ").append(tokenType != null ? tokenType : "generic").append("\n");
            sb.append("    ├─ Leak: ").append(truncate(tokenLeak.getValue(), 110)).append("\n");

            List<EndpointInfo> linkedEndpoints = endpoints.stream()
                .filter(ep -> {
                    String u = ep.getUrl() != null ? ep.getUrl().toLowerCase(Locale.ROOT) : "";
                    String c = ep.getContext() != null ? ep.getContext().toLowerCase(Locale.ROOT) : "";
                    return u.contains("token") || c.contains("token") || c.contains("authorization");
                })
                .limit(3)
                .toList();
            if (!linkedEndpoints.isEmpty()) {
                linkedEndpoints.forEach(ep -> sb.append("    ├─ Endpoint: ").append(ep).append("\n"));
            }

            List<DataStructureInfo> linkedStructures = structures.stream()
                .filter(ds -> ds.getProperties().keySet().stream()
                    .map(k -> k.toLowerCase(Locale.ROOT))
                    .anyMatch(k -> k.contains("token") || k.equals("access_token")))
                .limit(3)
                .toList();
            if (!linkedStructures.isEmpty()) {
                linkedStructures.forEach(ds -> sb.append("    └─ Structure: ").append(ds.getName()).append("\n"));
            }
        }
    }

    private void appendAnalysisTimingSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        sb.append("  Processing time: ").append(result.getAnalysisTime()).append(" ms\n");
        int endpointCount = result.getEndpoints() != null ? result.getEndpoints().size() : 0;
        int structureCount = result.getDataStructures() != null ? result.getDataStructures().size() : 0;
        int leakCount = result.getSensitiveInfo() != null ? result.getSensitiveInfo().size() : 0;
        sb.append("  Scale: endpoints=").append(endpointCount)
            .append(", structures=").append(structureCount)
            .append(", leaks=").append(leakCount).append("\n");
    }

    private String extractHost(String url) {
        if (url == null || url.isBlank() || !url.startsWith("http")) return null;
        try {
            URI uri = new URI(url);
            return uri.getHost() != null ? uri.getHost().toLowerCase(Locale.ROOT) : null;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private String normalizeRootDomain(String host) {
        if (host == null || host.isBlank()) return null;
        String[] parts = host.split("\\.");
        if (parts.length < 2) return host;
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private boolean isInternalServiceHost(String host, String targetHost, String targetRoot) {
        if (host == null) return false;
        if (host.contains(".ms.")) return true;
        if (targetRoot == null) return false;
        return host.endsWith("." + targetRoot) && targetHost != null && !host.equals(targetHost);
    }

    private boolean isThirdPartyHost(String host, String targetRoot, Set<String> knownExternal) {
        if (host == null) return false;
        for (String external : knownExternal) {
            if (host.endsWith(external)) return true;
        }
        if (targetRoot == null) return false;
        return !host.equals(targetRoot) && !host.endsWith("." + targetRoot);
    }

    private String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max) + "...";
    }
    
    /**
     * Renders sensitive findings as compact priority-tiered cards inside a StringBuilder.
     *
     * Format per tier:
     *   ── Critical (P8–P10) ──────────────────────────────────
     *   [P10] Private Key (PEM): -----BEGIN RSA PRI…
     *   [P 9] AWS Access Key: AKIA3F2EXAMPLE…  (×2)
    *   [P 8] KV Pair: Username + Password: Username: admin | Password: xxx  [Default/Placeholder]
     *
     * If architecture is MICROSERVICES findings are also grouped by service.
     */
    private void appendSensitiveInfoSection(
            StringBuilder sb,
            List<WebSourceAnalyzer.LeakInfo> leaks,
            it.r2u.anibus.model.ArchitectureInfo arch) {

        if (leaks == null || leaks.isEmpty()) {
            sb.append("  No sensitive information detected.\n");
            return;
        }

        boolean isMicroservices = arch != null
            && arch.getPattern() == it.r2u.anibus.model.ArchitectureInfo.ArchitecturePattern.MICROSERVICES;

        // Group by tier
        List<WebSourceAnalyzer.LeakInfo> critical  = new java.util.ArrayList<>();
        List<WebSourceAnalyzer.LeakInfo> important = new java.util.ArrayList<>();
        List<WebSourceAnalyzer.LeakInfo> lowRisk   = new java.util.ArrayList<>();

        for (WebSourceAnalyzer.LeakInfo l : leaks) {
            if (l.getPriority() >= 8)      critical.add(l);
            else if (l.getPriority() >= 5) important.add(l);
            else                           lowRisk.add(l);
        }

        java.util.function.BiConsumer<String, List<WebSourceAnalyzer.LeakInfo>> renderTier =
            (header, items) -> {
                if (items.isEmpty()) return;
                sb.append("\n  ── ").append(header).append(" ").append("─".repeat(Math.max(0, 46 - header.length()))).append("\n");
                // Optionally group by service inside tier
                if (isMicroservices) {
                    Map<String, List<WebSourceAnalyzer.LeakInfo>> byService = new java.util.LinkedHashMap<>();
                    for (WebSourceAnalyzer.LeakInfo l : items) {
                        String svc = l.getService() != null ? l.getService() : "general";
                        byService.computeIfAbsent(svc, k -> new java.util.ArrayList<>()).add(l);
                    }
                    byService.forEach((svc, svcLeaks) -> {
                        sb.append("    [").append(svc.toUpperCase()).append("]\n");
                        for (WebSourceAnalyzer.LeakInfo l : svcLeaks) renderLeakLine(sb, l);
                    });
                } else {
                    for (WebSourceAnalyzer.LeakInfo l : items) renderLeakLine(sb, l);
                }
            };

        renderTier.accept("Critical (P8–P10)", critical);
        renderTier.accept("Important (P5–P7)", important);
        renderTier.accept("Low Risk (P1–P4)",  lowRisk);
    }

    /** Formats a single LeakInfo line. Long values are shown in full on the next line. */
    private void renderLeakLine(StringBuilder sb,
                                WebSourceAnalyzer.LeakInfo leak) {
        String rawValue = leak.getValue() != null ? leak.getValue() : "";

        sb.append("  [P").append(String.format("%2d", leak.getPriority())).append("] ")
          .append(leak.getType()).append(":");

        if (leak.isPlaceholder()) sb.append("  [Default/Placeholder]");
        if (leak.getCount() > 1)  sb.append("  (×").append(leak.getCount()).append(")");

        // If the value contains newlines or is longer than 80 chars, show on its own indented line(s)
        if (rawValue.contains("\n") || rawValue.length() > 80) {
            sb.append("\n");
            for (String line : rawValue.split("\n", -1)) {
                sb.append("      ").append(line).append("\n");
            }
        } else {
            sb.append(" ").append(rawValue).append("\n");
        }
    }

    private void resetScanUI() {
        Platform.runLater(() -> {
            scanButton.setDisable(false);
            stopButton.setDisable(true);
            progressBar.setVisible(false);
        });
    }
    
    private void clearJsAnalysisResults() {
        jsEndpointsLabel.setText("0");
        jsDataStructuresLabel.setText("0");
        jsDbSchemasLabel.setText("0");
        jsSensitiveInfoLabel.setText("0");
        jsArchitectureLabel.setText("-");
        lastJsAnalysisResult = null;
        if (jsStructureTree != null) jsStructureTree.setRoot(null);
    }

    /**
     * Builds the collapsible TreeView of discovered data structures.
     *
     * Tree shape:
     *   (invisible root)
     *   ├─ REQUEST_PAYLOAD  (N structures)
     *   │   ├─ request_payload_1  (4 fields)
     *   │   │   ├─ product_id : String
     *   │   │   ├─ product_name : String
     *   │   │   └─ product_quantity : Number  [optional]
     *   │   └─ ...
     *   ├─ RESPONSE_MODEL  (...)
     *   └─ ...
     */
    private void populateStructureTree(List<DataStructureInfo> structures) {
        if (jsStructureTree == null) return;

        TreeItem<String> root = new TreeItem<>("root");
        root.setExpanded(true);

        // Group by DataType
        Map<DataStructureInfo.DataType, List<DataStructureInfo>> byType = new java.util.LinkedHashMap<>();
        for (DataStructureInfo ds : structures) {
            byType.computeIfAbsent(ds.getType(), k -> new java.util.ArrayList<>()).add(ds);
        }

        for (Map.Entry<DataStructureInfo.DataType, List<DataStructureInfo>> entry : byType.entrySet()) {
            String categoryLabel = entry.getKey().name().replace("_", " ")
                                   + "  (" + entry.getValue().size() + ")";
            TreeItem<String> categoryNode = new TreeItem<>(categoryLabel);
            categoryNode.setExpanded(true);

            for (DataStructureInfo ds : entry.getValue()) {
                int optCount = ds.getOptionalProperties().size();
                String structLabel = ds.getName()
                    + "  — " + ds.getProperties().size() + " fields"
                    + (optCount > 0 ? "  [" + optCount + " optional]" : "");
                TreeItem<String> structNode = new TreeItem<>(structLabel);
                structNode.setExpanded(false); // collapsed by default

                for (Map.Entry<String, String> prop : ds.getProperties().entrySet()) {
                    boolean optional = ds.isOptional(prop.getKey());
                    String fieldLabel = prop.getKey() + " : " + prop.getValue()
                        + (optional ? "  [optional]" : "");
                    structNode.getChildren().add(new TreeItem<>(fieldLabel));
                }

                categoryNode.getChildren().add(structNode);
            }
            root.getChildren().add(categoryNode);
        }

        jsStructureTree.setRoot(root);
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
