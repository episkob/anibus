package it.r2u.anibus;

import java.io.File;
import it.r2u.anibus.coordinator.*;
import it.r2u.anibus.handlers.*;
import it.r2u.anibus.model.DataStructureInfo;
import it.r2u.anibus.model.DatabaseSchemaInfo;
import it.r2u.anibus.model.EndpointInfo;
import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.model.LeakInfo;
import it.r2u.anibus.service.network.proxy.ProxyNode;
import it.r2u.anibus.service.network.proxy.ProxyRoutingService;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.network.NetworkStatusMonitor;
import it.r2u.anibus.service.detection.EnhancedServiceDetector;
import it.r2u.anibus.service.analysis.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.service.analysis.ApiSecurityModeService;
import it.r2u.anibus.service.analysis.PassiveReconService;
import it.r2u.anibus.service.analysis.SecretsValidationService;
import it.r2u.anibus.service.analysis.ParamMinerService;
import it.r2u.anibus.service.analysis.SourceMapAnalyzer;
import it.r2u.anibus.service.core.PortScannerService;
import it.r2u.anibus.service.core.ScanHistoryService;
import it.r2u.anibus.service.core.ScanSchedulerService;
import it.r2u.anibus.service.core.UdpScannerService;
import it.r2u.anibus.service.analysis.SQLInjectionAnalyzer;
import it.r2u.anibus.service.analysis.XssDetector;
import it.r2u.anibus.service.analysis.CorsChecker;
import it.r2u.anibus.service.analysis.JwtAnalyzer;
import it.r2u.anibus.service.analysis.SsrfDetector;
import it.r2u.anibus.service.analysis.DirectoryBruteforcer;
import it.r2u.anibus.service.analysis.GraphqlScanner;
import it.r2u.anibus.service.analysis.XxeDetector;
import it.r2u.anibus.service.analysis.SubdomainTakeoverChecker;
import it.r2u.anibus.service.analysis.Log4ShellChecker;
import it.r2u.anibus.service.analysis.Spring4ShellChecker;
import it.r2u.anibus.service.analysis.WebSocketDetector;
import it.r2u.anibus.service.network.WhoisService;
import it.r2u.anibus.service.network.SslTlsAuditor;
import it.r2u.anibus.service.network.DnsZoneTransferService;
import it.r2u.anibus.service.network.HttpProtocolDetector;
import it.r2u.anibus.service.network.AsnLookupService;
import it.r2u.anibus.service.analysis.HeartbleedChecker;
import it.r2u.anibus.service.export.ScanDiffService;
import it.r2u.anibus.service.network.TracerouteService;
import it.r2u.anibus.service.network.SubdomainEnumerationService;
import it.r2u.anibus.ui.AlertHelper;
import it.r2u.anibus.ui.ConsoleViewManager;
import it.r2u.anibus.ui.InfoCardManager;
import it.r2u.anibus.ui.NotificationService;
import it.r2u.anibus.ui.LanguageManager;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.control.RadioMenuItem;
import javafx.scene.control.ToggleGroup;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.input.TransferMode;
import javafx.stage.FileChooser;
import javafx.scene.layout.Pane;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;
import javafx.scene.shape.Line;
import javafx.scene.text.Text;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.time.Duration;

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

    /**
     * Manually wired core services passed from application composition root.
     */
    public record CoreServices(
        PortScannerService scanner,
        EnhancedServiceDetector detector,
        HostResolver hostResolver,
        JavaScriptSecurityAnalyzer jsAnalyzer,
        SQLInjectionAnalyzer injectionAnalyzer,
        SourceMapAnalyzer sourceMapAnalyzer,
        ParamMinerService paramMinerService,
        SubdomainEnumerationService subdomainEnumerationService,
        UdpScannerService udpScannerService,
        ScanDiffService scanDiffService,
        ScanSchedulerService scanSchedulerService,
        ScanHistoryService scanHistoryService,
        XssDetector xssDetector,
        CorsChecker corsChecker,
        JwtAnalyzer jwtAnalyzer,
        SsrfDetector ssrfDetector,
        DirectoryBruteforcer dirBruteforcer,
        WhoisService whoisService,
        SslTlsAuditor sslTlsAuditor,
        GraphqlScanner graphqlScanner,
        XxeDetector xxeDetector,
        SubdomainTakeoverChecker takeoverChecker,
        DnsZoneTransferService dnsAxfrService,
        Log4ShellChecker log4ShellChecker,
        Spring4ShellChecker spring4ShellChecker,
        WebSocketDetector webSocketDetector,
        HttpProtocolDetector httpProtocolDetector,
        AsnLookupService asnLookupService,
        HeartbleedChecker heartbleedChecker
    ) {}

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
    @FXML private TextArea          sqlInjectionTextArea;
    
    /* -- Unified Console FXML fields ------------------------- */
    @FXML private Label             consoleHeaderLabel;
    @FXML private TextField         consoleFilterField;

    /* -- i18n: configuration menu + translatable labels ------ */
    @FXML private MenuButton configMenuButton;
    @FXML private Button aboutButton;
    @FXML private Label  sectionScanTargetLabel;
    @FXML private Label  labelTargetKey;
    @FXML private Label  labelPortRangeKey;
    @FXML private Label  labelThreadsKey;
    @FXML private Label  labelOptionsKey;
    @FXML private Label  optionJsTitle;
    @FXML private Label  optionJsDesc;
    @FXML private Label  optionSqlTitle;
    @FXML private Label  optionSqlDesc;
    @FXML private Label  sectionHostInfoLabel;
    @FXML private Label  keyIpAddressLabel;
    @FXML private Label  keyHostnameLabel;
    @FXML private Label  keyScanTimeLabel;
    @FXML private Label  keyPortsScannedLabel;
    @FXML private Label  keyOpenPortsLabel;
    @FXML private Label  keyAvgLatencyLabel;
    @FXML private Tab    tabScanResults;
    @FXML private Tab    tabJsAnalysis;
    @FXML private Tab    tabSqlInjection;
    @FXML private Tab    tabTopology;
    @FXML private Tab    tabProxy;
    @FXML private Tab    tabStatistics;
    @FXML private Label  plannedFeaturesLabel;
    @FXML private Button udpScanButton;
    @FXML private Button subdomainButton;
    @FXML private Button sourceMapButton;
    @FXML private Button paramMinerButton;
    @FXML private Button diffModeButton;
    @FXML private Button schedulerStartButton;
    @FXML private Button schedulerStopButton;
    @FXML private TextArea proxyLogArea;
    @FXML private Label    activeProxyLabel;
    @FXML private Circle   proxyStatusDot;
    @FXML private Button   startProxyButton;
    @FXML private Button   clearProxyButton;
    @FXML private Button   loadProxyButton;
    @FXML private Button   rotateProxyButton;
    @FXML private Label    proxyStatCandidates;
    @FXML private Label    proxyStatLive;
    @FXML private Label    proxyStatCountries;
    @FXML private Label    proxyPhaseLabel;
    @FXML private ProgressBar proxyProgressBar;
    @FXML private Label  placeholderTitleLabel;
    @FXML private Label  placeholderDescLabel;
    @FXML private Label  keyEndpointsLabel;
    @FXML private Label  keyDataStructuresLabel;
    @FXML private Label  keyDbSchemasLabel;
    @FXML private Label  keySensitiveInfoLabel;
    @FXML private Label  keyArchitectureLabel;
    @FXML private Label  subtitleDataStructuresLabel;
    @FXML private TextArea chainDisplayArea;
    @FXML private VBox    chainDisplayCard;
    @FXML private ListView<String> proxyAvailableListView;
    @FXML private ListView<String> proxyChainListView;
    @FXML private Pane topologyGraphPane;
    @FXML private PieChart statsPortStateChart;
    @FXML private BarChart<String, Number> statsServiceChart;
    @FXML private BarChart<String, Number> statsRiskChart;
    @SuppressWarnings("unused")
    @FXML private Button  buildChainButton;  // injected by FXMLLoader, used via onBuildChainClick()

    /* -- State ------------------------------------------------ */
    private final CoreServices coreServices;
    private final ObservableList<PortScanResult> results = FXCollections.observableArrayList();
    private final List<ProxyNode> currentProxyChain = new java.util.ArrayList<>();
    private final Map<String, ProxyNode> proxyVisualMap = new java.util.LinkedHashMap<>();
    private Task<Void> jsAnalysisTask;
    private JavaScriptAnalysisResult lastJsAnalysisResult;
    private boolean scanningInProgress = false;
    private boolean jsAnalysisInProgress = false;
    private boolean isJsAnalysisMode = false; // Track current console mode
    private ProxyRoutingService proxyRoutingService;
    private ProxyNode currentActiveProxy = null;
    private boolean proxyHarvesting = false;
    
    /* -- Core services (Dependency Injection candidates) ------ */
    private PortScannerService     scanner;
    private EnhancedServiceDetector detector;
    private HostResolver           hostResolver;
    private NetworkStatusMonitor   networkStatusMonitor;
    private ConsoleViewManager     consoleViewManager;
    private InfoCardManager        infoCardManager;
    private JavaScriptSecurityAnalyzer jsAnalyzer;
    private ApiSecurityModeService apiSecurityModeService;
    private PassiveReconService passiveReconService;
    private SecretsValidationService secretsValidationService;
    private SQLInjectionAnalyzer injectionAnalyzer;
    private SourceMapAnalyzer sourceMapAnalyzer;
    private ParamMinerService paramMinerService;
    private SubdomainEnumerationService subdomainEnumerationService;
    private UdpScannerService udpScannerService;
    private ScanDiffService scanDiffService;
    private ScanSchedulerService scanSchedulerService;
    private ScanHistoryService   scanHistoryService;
    private XssDetector xssDetector;
    private CorsChecker corsChecker;
    private JwtAnalyzer jwtAnalyzer;
    private SsrfDetector ssrfDetector;
    private DirectoryBruteforcer dirBruteforcer;
    private WhoisService whoisService;
    private SslTlsAuditor sslTlsAuditor;
    private GraphqlScanner graphqlScanner;
    private XxeDetector xxeDetector;
    private SubdomainTakeoverChecker takeoverChecker;
    private DnsZoneTransferService dnsAxfrService;
    private Log4ShellChecker log4ShellChecker;
    private Spring4ShellChecker spring4ShellChecker;
    private WebSocketDetector webSocketDetector;
    private HttpProtocolDetector httpProtocolDetector;
    private AsnLookupService asnLookupService;
    private HeartbleedChecker heartbleedChecker;

    /* -- Console filter state --------------------------------- */
    private String  unfilteredConsoleText = "";
    private boolean isFilteringConsole    = false;

    /* -- Notifications ---------------------------------------- */
    private NotificationService notificationService;
    
    /* -- Coordinators and Handlers (SOLID refactoring) -------- */
    private ScanCoordinator        scanCoordinator;
    private ScanActionHandler      scanActionHandler;
    private ClipboardActionHandler clipboardHandler;
    private ExportActionHandler    exportHandler;
    private TracerouteActionHandler tracerouteHandler;

    public AnibusController() {
        this(null);
    }

    public AnibusController(CoreServices coreServices) {
        this.coreServices = coreServices;
    }

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        initializeCoreServices();
        initializeCoordinatorsAndHandlers();
        setupUI();
        setupEventHandlers();
        startBackgroundServices();
        applyLanguage();
    }
    
    /**
     * Initialize core business services.
     */
    private void initializeCoreServices() {
        scanner = coreServices != null && coreServices.scanner() != null
            ? coreServices.scanner() : new PortScannerService();
        detector = coreServices != null && coreServices.detector() != null
            ? coreServices.detector() : new EnhancedServiceDetector();
        hostResolver = coreServices != null && coreServices.hostResolver() != null
            ? coreServices.hostResolver() : new HostResolver();
        jsAnalyzer = coreServices != null && coreServices.jsAnalyzer() != null
            ? coreServices.jsAnalyzer() : new JavaScriptSecurityAnalyzer();
        apiSecurityModeService = new ApiSecurityModeService();
        passiveReconService = new PassiveReconService();
        secretsValidationService = new SecretsValidationService();
        injectionAnalyzer = coreServices != null && coreServices.injectionAnalyzer() != null
            ? coreServices.injectionAnalyzer() : new SQLInjectionAnalyzer();
        sourceMapAnalyzer = coreServices != null && coreServices.sourceMapAnalyzer() != null
            ? coreServices.sourceMapAnalyzer() : new SourceMapAnalyzer();
        paramMinerService = coreServices != null && coreServices.paramMinerService() != null
            ? coreServices.paramMinerService() : new ParamMinerService();
        subdomainEnumerationService = coreServices != null && coreServices.subdomainEnumerationService() != null
            ? coreServices.subdomainEnumerationService() : new SubdomainEnumerationService();
        udpScannerService = coreServices != null && coreServices.udpScannerService() != null
            ? coreServices.udpScannerService() : new UdpScannerService();
        scanDiffService = coreServices != null && coreServices.scanDiffService() != null
            ? coreServices.scanDiffService() : new ScanDiffService();
        scanSchedulerService = coreServices != null && coreServices.scanSchedulerService() != null
            ? coreServices.scanSchedulerService() : new ScanSchedulerService();
        scanHistoryService = coreServices != null && coreServices.scanHistoryService() != null
            ? coreServices.scanHistoryService() : new ScanHistoryService();
        xssDetector = coreServices != null && coreServices.xssDetector() != null
            ? coreServices.xssDetector() : new XssDetector();
        corsChecker = coreServices != null && coreServices.corsChecker() != null
            ? coreServices.corsChecker() : new CorsChecker();
        jwtAnalyzer = coreServices != null && coreServices.jwtAnalyzer() != null
            ? coreServices.jwtAnalyzer() : new JwtAnalyzer();
        ssrfDetector = coreServices != null && coreServices.ssrfDetector() != null
            ? coreServices.ssrfDetector() : new SsrfDetector();
        dirBruteforcer = coreServices != null && coreServices.dirBruteforcer() != null
            ? coreServices.dirBruteforcer() : new DirectoryBruteforcer();
        whoisService = coreServices != null && coreServices.whoisService() != null
            ? coreServices.whoisService() : new WhoisService();
        sslTlsAuditor = coreServices != null && coreServices.sslTlsAuditor() != null
            ? coreServices.sslTlsAuditor() : new SslTlsAuditor();
        graphqlScanner = coreServices != null && coreServices.graphqlScanner() != null
            ? coreServices.graphqlScanner() : new GraphqlScanner();
        xxeDetector = coreServices != null && coreServices.xxeDetector() != null
            ? coreServices.xxeDetector() : new XxeDetector();
        takeoverChecker = coreServices != null && coreServices.takeoverChecker() != null
            ? coreServices.takeoverChecker() : new SubdomainTakeoverChecker();
        dnsAxfrService = coreServices != null && coreServices.dnsAxfrService() != null
            ? coreServices.dnsAxfrService() : new DnsZoneTransferService();
        log4ShellChecker = coreServices != null && coreServices.log4ShellChecker() != null
            ? coreServices.log4ShellChecker() : new Log4ShellChecker();
        spring4ShellChecker = coreServices != null && coreServices.spring4ShellChecker() != null
            ? coreServices.spring4ShellChecker() : new Spring4ShellChecker();
        webSocketDetector = coreServices != null && coreServices.webSocketDetector() != null
            ? coreServices.webSocketDetector() : new WebSocketDetector();
        httpProtocolDetector = coreServices != null && coreServices.httpProtocolDetector() != null
            ? coreServices.httpProtocolDetector() : new HttpProtocolDetector();
        asnLookupService = coreServices != null && coreServices.asnLookupService() != null
            ? coreServices.asnLookupService() : new AsnLookupService();
        heartbleedChecker = coreServices != null && coreServices.heartbleedChecker() != null
            ? coreServices.heartbleedChecker() : new HeartbleedChecker();
        
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
        consoleTextArea.setPrefRowCount(18);
        

        
        // Setup thread spinner
        threadSpinner.setValueFactory(
            new SpinnerValueFactory.IntegerSpinnerValueFactory(10, 500, 10, 10));
        threadSpinner.setTooltip(new Tooltip("Number of concurrent scanning threads"));
        
        // Setup context menus
        setupConsoleContextMenu();
        setupReadOnlyTextAreaContextMenu(sqlInjectionTextArea, "sql-injection");
        setupReadOnlyTextAreaContextMenu(proxyLogArea, "proxy-log");
        setupReadOnlyTextAreaContextMenu(chainDisplayArea, "proxy-chain");
        setupResolvedHostContextMenu();
        setupProxyChainBuilderDnD();

        // Configuration MenuButton — Language sub-menu
        RadioMenuItem langEn = new RadioMenuItem("English");
        RadioMenuItem langIt = new RadioMenuItem("Italiano");
        RadioMenuItem langRu = new RadioMenuItem("Русский");
        ToggleGroup langGroup = new ToggleGroup();
        langEn.setToggleGroup(langGroup);
        langIt.setToggleGroup(langGroup);
        langRu.setToggleGroup(langGroup);
        langEn.setSelected(true);
        langEn.setOnAction(e -> { LanguageManager.getInstance().setLanguage(LanguageManager.Language.EN); applyLanguage(); });
        langIt.setOnAction(e -> { LanguageManager.getInstance().setLanguage(LanguageManager.Language.IT); applyLanguage(); });
        langRu.setOnAction(e -> { LanguageManager.getInstance().setLanguage(LanguageManager.Language.RU); applyLanguage(); });
        Menu langMenu = new Menu("Выбор языка");
        langMenu.getItems().addAll(langEn, langIt, langRu);

        // Theme sub-menu
        RadioMenuItem themeDark  = new RadioMenuItem("Dark");
        RadioMenuItem themeLight = new RadioMenuItem("Light");
        ToggleGroup themeGroup = new ToggleGroup();
        themeDark.setToggleGroup(themeGroup);
        themeLight.setToggleGroup(themeGroup);
        themeDark.setSelected(true);
        themeDark.setOnAction(e -> applyTheme(false));
        themeLight.setOnAction(e -> applyTheme(true));
        Menu themeMenu = new Menu("Тема");
        themeMenu.getItems().addAll(themeDark, themeLight);

        configMenuButton.getItems().addAll(langMenu, themeMenu);

        // Show saved-pool hint on startup
        it.r2u.anibus.service.network.proxy.ProxyStore ps =
                new it.r2u.anibus.service.network.proxy.ProxyStore();
        if (ps.exists()) {
            loadProxyButton.setText(LanguageManager.getInstance().get("btn.loadFromFile") + " ✓");
            loadProxyButton.setTooltip(new Tooltip(
                    "Cached pool found: " + ps.getStorePath()));
        }
    }
    
    /**
     * Setup event handlers and listeners.
     */
    private void setupEventHandlers() {

        
        // Monitor scan button state to detect scanning completion
        scanButton.disableProperty().addListener((obs, wasDisabled, isDisabled) -> {
            if (scanningInProgress && !isDisabled) {
                scanningInProgress = false;
                // Auto-save scan to history
                String host = hostTextField.getText().trim();
                if (!results.isEmpty() && scanHistoryService != null) {
                    Thread t = new Thread(() -> scanHistoryService.save(host, List.copyOf(results)), "scan-history-save");
                    t.setDaemon(true);
                    t.start();
                }
                // Notify user that background scan has finished
                int openCount = (int) results.stream()
                    .filter(r -> "Open".equalsIgnoreCase(r.getState())).count();
                if (notificationService != null) {
                    notificationService.notifyInfo("Anibus — Scan Complete",
                        openCount + " open port(s) found on " + hostTextField.getText().trim());
                }
            }
        });
        
        // Results list changes
        results.addListener((javafx.collections.ListChangeListener<PortScanResult>) c -> {
            refreshResultCount();
            infoCardManager.refreshInfoCard(results);
            updateStatisticsDashboard();
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

        // Console filter field
        if (consoleFilterField != null) {
            consoleTextArea.textProperty().addListener((obs, old, nv) -> {
                if (!isFilteringConsole) unfilteredConsoleText = nv;
            });
            consoleFilterField.textProperty().addListener((obs, old, nv) -> applyConsoleFilter(nv));
        }
    }
    
    /**
     * Start background services.
     */
    private void startBackgroundServices() {
        refreshResultCount();
        updateStatisticsDashboard();
        networkStatusMonitor.start();
        notificationService = new NotificationService();
        // Setup keyboard shortcuts after scene is ready
        Platform.runLater(this::setupKeyboardShortcuts);
    }

    /* -- Keyboard shortcuts ----------------------------------- */
    private void setupKeyboardShortcuts() {
        var scene = consoleTextArea.getScene();
        if (scene == null) return;
        var acc = scene.getAccelerators();
        // F5 — start scan
        acc.put(new KeyCodeCombination(KeyCode.F5), () -> {
            if (!scanButton.isDisabled()) onScanButtonClick();
        });
        // Escape — stop scan
        acc.put(new KeyCodeCombination(KeyCode.ESCAPE), () -> {
            if (!stopButton.isDisabled()) onStopButtonClick();
        });
        // Ctrl+S — export results
        acc.put(new KeyCodeCombination(KeyCode.S, KeyCombination.CONTROL_DOWN), () -> {
            if (!exportButton.isDisabled()) onExportClick();
        });
        // Ctrl+L — clear console
        acc.put(new KeyCodeCombination(KeyCode.L, KeyCombination.CONTROL_DOWN), () -> {
            if (!clearButton.isDisabled()) onClearClick();
        });
        // Ctrl+F — focus filter field
        acc.put(new KeyCodeCombination(KeyCode.F, KeyCombination.CONTROL_DOWN), () -> {
            if (consoleFilterField != null) consoleFilterField.requestFocus();
        });
    }

    /* -- Context menus ---------------------------------------- */
    private void setupConsoleContextMenu() {
        MenuItem copySelected = new MenuItem("Copy selected text");
        copySelected.setOnAction(e -> clipboardHandler.copySelectedText(consoleTextArea));

        MenuItem copyAll = new MenuItem("Copy all console output");
        copyAll.setOnAction(e -> clipboardHandler.copyConsoleOutput(consoleTextArea));

        MenuItem saveSelected = new MenuItem("Save selected text...");
        saveSelected.setOnAction(e -> exportHandler.exportSelectedText(
            consoleTextArea, consoleTextArea.getScene().getWindow(), "js-console"));
        
        MenuItem copyResults = new MenuItem("Copy results only");
        copyResults.setOnAction(e -> clipboardHandler.copyAllResults(results));
        
        MenuItem runTraceroute = new MenuItem("Run Traceroute...");
        runTraceroute.setOnAction(e -> tracerouteHandler.runTraceroute(
            hostTextField.getText(), consoleTextArea, this::renderTopologyGraph));

        MenuItem runUdpScan = new MenuItem("Run UDP Scan (common ports)");
        runUdpScan.setOnAction(e -> runUdpScan());

        MenuItem runSubdomainEnum = new MenuItem("Enumerate Subdomains");
        runSubdomainEnum.setOnAction(e -> runSubdomainEnumeration());

        MenuItem runSourceMap = new MenuItem("Analyze Source Maps");
        runSourceMap.setOnAction(e -> runSourceMapAnalysis());

        MenuItem runParamMiner = new MenuItem("Run Param Miner");
        runParamMiner.setOnAction(e -> runParamMiner());

        MenuItem runApiSecurityMode = new MenuItem("API Security Mode (OpenAPI/Swagger)...");
        runApiSecurityMode.setOnAction(e -> runApiSecurityMode());

        MenuItem runPassiveRecon = new MenuItem("Passive Recon Mode...");
        runPassiveRecon.setOnAction(e -> runPassiveRecon());
        MenuItem runSecretsValidation = new MenuItem("Validate Secrets (JS Leaks)...");
        runSecretsValidation.setOnAction(e -> runSecretsValidation());

        MenuItem runDiffMode = new MenuItem("Diff Current Results with XML...");
        runDiffMode.setOnAction(e -> runDiffMode());

        MenuItem startScheduler = new MenuItem("Start Scheduled Scan (30m)");
        startScheduler.setOnAction(e -> startScheduledScan());

        MenuItem stopScheduler = new MenuItem("Stop Scheduled Scan");
        stopScheduler.setOnAction(e -> stopScheduledScan());

        MenuItem showHistory = new MenuItem("Show Scan History...");
        showHistory.setOnAction(e -> runShowScanHistory());

        MenuItem runXssScan = new MenuItem("XSS Scan (reflected)...");
        runXssScan.setOnAction(e -> runXssScan());

        MenuItem runCorsScan = new MenuItem("CORS Misconfiguration Check...");
        runCorsScan.setOnAction(e -> runCorsCheck());

        MenuItem runJwtScan = new MenuItem("JWT Analyzer (from JS)...");
        runJwtScan.setOnAction(e -> runJwtAnalysis());

        MenuItem runSsrfScan = new MenuItem("SSRF Detector...");
        runSsrfScan.setOnAction(e -> runSsrfScan());

        MenuItem runDirBrute = new MenuItem("Directory Bruteforce...");
        runDirBrute.setOnAction(e -> runDirectoryBruteforce());

        MenuItem runWhois = new MenuItem("WHOIS Lookup...");
        runWhois.setOnAction(e -> runWhoisLookup());

        MenuItem runSslAudit = new MenuItem("SSL/TLS Deep Audit...");
        runSslAudit.setOnAction(e -> runSslAudit());

        MenuItem runGraphql = new MenuItem("GraphQL Introspection...");
        runGraphql.setOnAction(e -> runGraphqlScan());

        MenuItem runXxe = new MenuItem("XXE Detector...");
        runXxe.setOnAction(e -> runXxeScan());

        MenuItem runTakeover = new MenuItem("Subdomain Takeover Check...");
        runTakeover.setOnAction(e -> runTakeoverCheck());

        MenuItem runAxfr = new MenuItem("DNS Zone Transfer (AXFR)...");
        runAxfr.setOnAction(e -> runDnsAxfr());

        MenuItem runLog4Shell = new MenuItem("Log4Shell Check (CVE-2021-44228)...");
        runLog4Shell.setOnAction(e -> runLog4ShellCheck());

        MenuItem runSpring4Shell = new MenuItem("Spring4Shell Check (CVE-2022-22965)...");
        runSpring4Shell.setOnAction(e -> runSpring4ShellCheck());

        MenuItem runWsDetect = new MenuItem("WebSocket Detector...");
        runWsDetect.setOnAction(e -> runWebSocketDetect());

        MenuItem runHttpProto = new MenuItem("HTTP/2 + HTTP/3 Detector...");
        runHttpProto.setOnAction(e -> runHttpProtocolDetect());

        MenuItem runAsnLookup = new MenuItem("ASN Lookup...");
        runAsnLookup.setOnAction(e -> runAsnLookup());

        MenuItem runHeartbleed = new MenuItem("Heartbleed Check (CVE-2014-0160)...");
        runHeartbleed.setOnAction(e -> runHeartbleedCheck());

        MenuItem runSqlMeta = new MenuItem("SQL Metadata Extraction...");
        runSqlMeta.setOnAction(e -> runSqlMetadataExtraction());

        consoleTextArea.setContextMenu(new ContextMenu(
            copySelected, copyAll, saveSelected, copyResults,
            new SeparatorMenuItem(),
            runTraceroute, runUdpScan, runSubdomainEnum,
            runSourceMap, runParamMiner, runApiSecurityMode, runPassiveRecon, runSecretsValidation,
            new SeparatorMenuItem(),
            runXssScan, runCorsScan, runJwtScan,
            runSsrfScan, runDirBrute, runWhois,
            runSslAudit, runGraphql, runXxe,
            runTakeover, runAxfr, runLog4Shell,
            runSpring4Shell, runWsDetect, runHttpProto,
            runAsnLookup, runHeartbleed, runSqlMeta,
            new SeparatorMenuItem(),
            runDiffMode,
            new SeparatorMenuItem(),
            startScheduler, stopScheduler,
            new SeparatorMenuItem(),
            showHistory));
    }

    private void setupReadOnlyTextAreaContextMenu(TextArea textArea, String baseFileName) {
        if (textArea == null) {
            return;
        }

        MenuItem copySelected = new MenuItem("Copy selected text");
        copySelected.setOnAction(e -> clipboardHandler.copySelectedText(textArea));

        MenuItem copyAll = new MenuItem("Copy all text");
        copyAll.setOnAction(e -> clipboardHandler.copyConsoleOutput(textArea));

        MenuItem saveSelected = new MenuItem("Save selected text...");
        saveSelected.setOnAction(e -> exportHandler.exportSelectedText(
            textArea, textArea.getScene().getWindow(), baseFileName));

        textArea.setContextMenu(new ContextMenu(copySelected, copyAll, saveSelected));
    }

    private void setupProxyChainBuilderDnD() {
        if (proxyAvailableListView == null || proxyChainListView == null) {
            return;
        }

        proxyAvailableListView.setPlaceholder(new Label("Load/harvest proxies first"));
        proxyChainListView.setPlaceholder(new Label("Drag proxies here to build chain"));

        proxyAvailableListView.setOnDragDetected(event -> {
            String selected = proxyAvailableListView.getSelectionModel().getSelectedItem();
            if (selected == null) {
                return;
            }
            Dragboard db = proxyAvailableListView.startDragAndDrop(TransferMode.COPY);
            ClipboardContent content = new ClipboardContent();
            content.putString(selected);
            db.setContent(content);
            event.consume();
        });

        proxyChainListView.setOnDragDetected(event -> {
            String selected = proxyChainListView.getSelectionModel().getSelectedItem();
            if (selected == null) {
                return;
            }
            Dragboard db = proxyChainListView.startDragAndDrop(TransferMode.MOVE);
            ClipboardContent content = new ClipboardContent();
            content.putString(selected);
            db.setContent(content);
            event.consume();
        });

        proxyChainListView.setOnDragOver(event -> {
            if (event.getDragboard().hasString()) {
                event.acceptTransferModes(TransferMode.COPY_OR_MOVE);
            }
            event.consume();
        });

        proxyChainListView.setOnDragDropped(event -> {
            String item = event.getDragboard().getString();
            boolean completed = false;
            if (item != null && proxyVisualMap.containsKey(item)) {
                if (!proxyChainListView.getItems().contains(item)) {
                    proxyChainListView.getItems().add(item);
                }
                syncChainFromListView();
                completed = true;
            }
            event.setDropCompleted(completed);
            event.consume();
        });

        proxyChainListView.setOnMouseClicked(event -> {
            if (event.getClickCount() == 2) {
                String selected = proxyChainListView.getSelectionModel().getSelectedItem();
                if (selected != null) {
                    proxyChainListView.getItems().remove(selected);
                    syncChainFromListView();
                }
            }
        });
    }

    private void refreshAvailableProxiesForChainBuilder() {
        if (proxyAvailableListView == null || proxyRoutingService == null || !proxyRoutingService.isReady()) {
            return;
        }
        proxyVisualMap.clear();
        List<String> labels = proxyRoutingService.allProxies().stream()
            .sorted(java.util.Comparator.comparingLong(ProxyNode::latencyMs))
            .map(this::formatProxyNodeDisplay)
            .toList();
        proxyRoutingService.allProxies().forEach(node -> proxyVisualMap.put(formatProxyNodeDisplay(node), node));
        proxyAvailableListView.getItems().setAll(labels);
    }

    private String formatProxyNodeDisplay(ProxyNode node) {
        return node.host() + ":" + node.port() + " [" + node.type() + "] " + node.countryCode() + " ~ " + node.latencyMs() + "ms";
    }

    private void syncChainFromListView() {
        currentProxyChain.clear();
        for (String item : proxyChainListView.getItems()) {
            ProxyNode node = proxyVisualMap.get(item);
            if (node != null) {
                currentProxyChain.add(node);
            }
        }
        displayProxyChain();
    }

    private void renderTopologyGraph(TracerouteService.TraceRoute trace) {
        if (topologyGraphPane == null || trace == null) {
            return;
        }
        topologyGraphPane.getChildren().clear();

        List<TracerouteService.Hop> hops = trace.getHops();
        if (hops.isEmpty()) {
            Text empty = new Text("No hops captured for traceroute to " + trace.getTargetHost());
            empty.setLayoutX(20);
            empty.setLayoutY(40);
            topologyGraphPane.getChildren().add(empty);
            return;
        }

        double x = 60;
        double y = 140;
        double step = 160;

        Text title = new Text("Target: " + trace.getTargetHost() + (trace.getTargetIP() != null ? " (" + trace.getTargetIP() + ")" : ""));
        title.setLayoutX(20);
        title.setLayoutY(24);
        topologyGraphPane.getChildren().add(title);

        for (int i = 0; i < hops.size(); i++) {
            TracerouteService.Hop hop = hops.get(i);
            Circle node = new Circle(x, y, 18);
            node.setFill(hop.isTimeout() ? javafx.scene.paint.Color.web("#ff9f0a") : javafx.scene.paint.Color.web("#30d158"));
            Text hopNo = new Text(String.valueOf(hop.getHopNumber()));
            hopNo.setLayoutX(x - 4);
            hopNo.setLayoutY(y + 4);

            String host = hop.getIpAddress() != null ? hop.getIpAddress() : "timeout";
            long avg = hop.getAverageRTT();
            Text label = new Text(host + (avg >= 0 ? "  (" + avg + " ms)" : ""));
            label.setLayoutX(x - 50);
            label.setLayoutY(y + 34);

            topologyGraphPane.getChildren().addAll(node, hopNo, label);

            if (i < hops.size() - 1) {
                Line edge = new Line(x + 20, y, x + step - 20, y);
                edge.setStroke(javafx.scene.paint.Color.web("#6c757d"));
                topologyGraphPane.getChildren().add(edge);
            }
            x += step;
        }

        topologyGraphPane.setPrefWidth(Math.max(1200, hops.size() * step + 120));
        tabTopology.getTabPane().getSelectionModel().select(tabTopology);
    }

    private void updateStatisticsDashboard() {
        if (statsPortStateChart == null || statsServiceChart == null || statsRiskChart == null) {
            return;
        }

        long open = results.stream().filter(r -> "Open".equalsIgnoreCase(r.getState())).count();
        long closed = Math.max(0, results.size() - open);
        statsPortStateChart.setData(FXCollections.observableArrayList(
            new PieChart.Data("Open", open),
            new PieChart.Data("Other", closed)
        ));

        Map<String, Long> byService = results.stream()
            .collect(java.util.stream.Collectors.groupingBy(
                r -> {
                    String s = r.getService();
                    return (s == null || s.isBlank()) ? "unknown" : s;
                },
                java.util.stream.Collectors.counting()
            ));

        XYChart.Series<String, Number> serviceSeries = new XYChart.Series<>();
        byService.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .limit(8)
            .forEach(e -> serviceSeries.getData().add(new XYChart.Data<>(e.getKey(), e.getValue())));
        serviceSeries.setName("Services");
        statsServiceChart.getData().setAll(serviceSeries);

        long highRisk = results.stream().filter(this::isHighRiskPort).count();
        long mediumRisk = results.stream().filter(this::isMediumRiskPort).count();
        long lowRisk = Math.max(0, results.size() - highRisk - mediumRisk);

        XYChart.Series<String, Number> riskSeries = new XYChart.Series<>();
        riskSeries.getData().add(new XYChart.Data<>("High", highRisk));
        riskSeries.getData().add(new XYChart.Data<>("Medium", mediumRisk));
        riskSeries.getData().add(new XYChart.Data<>("Low", lowRisk));
        riskSeries.setName("Risk");
        statsRiskChart.getData().setAll(riskSeries);
    }

    private boolean isHighRiskPort(PortScanResult r) {
        int port = r.getPort();
        String service = r.getService() != null ? r.getService().toLowerCase(Locale.ROOT) : "";
        return port == 23 || port == 445 || port == 3389 || service.contains("telnet") || service.contains("rdp");
    }

    private boolean isMediumRiskPort(PortScanResult r) {
        int port = r.getPort();
        String service = r.getService() != null ? r.getService().toLowerCase(Locale.ROOT) : "";
        return port == 21 || port == 22 || port == 3306 || port == 5432 || service.contains("ftp") || service.contains("ssh") || service.contains("mysql");
    }

    private void runUdpScan() {
        String host = extractHostOrDomain(hostTextField.getText());
        if (host.isBlank()) {
            setStatus("Enter a host or URL before UDP scan");
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
        setStatus("Running UDP scan on " + host + "...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            List<PortScanResult> udpResults = task.getValue();
            if (udpResults == null || udpResults.isEmpty()) {
                setStatus("UDP scan completed: no responsive UDP ports detected");
                return;
            }
            results.addAll(udpResults);
            consoleViewManager.appendRawText("\n=== UDP SCAN RESULTS ===\n");
            udpResults.forEach(consoleViewManager::appendToConsole);
            setStatus("UDP scan completed: " + udpResults.size() + " result(s)");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("UDP scan failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    private void runSubdomainEnumeration() {
        String host = extractHostOrDomain(hostTextField.getText());
        String domain = normalizeRootDomain(host);
        if (domain == null || domain.isBlank()) {
            setStatus("Enter a valid domain for subdomain enumeration");
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
        setStatus("Enumerating subdomains for " + domain + "...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            List<SubdomainEnumerationService.SubdomainResult> found = task.getValue();
            consoleViewManager.appendRawText("\n" + SubdomainEnumerationService.formatReport(found, domain) + "\n");
            setStatus("Subdomain enumeration completed: " + found.size() + " live subdomain(s)");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("Subdomain enumeration failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    private void runSourceMapAnalysis() {
        if (lastJsAnalysisResult == null || lastJsAnalysisResult.getJsFiles() == null) {
            setStatus("Run JavaScript analysis first to discover JS files");
            return;
        }

        List<String> jsUrls = lastJsAnalysisResult.getJsFiles().stream()
            .filter(u -> u != null && u.startsWith("http") && u.contains(".js"))
            .distinct()
            .limit(10)
            .toList();

        if (jsUrls.isEmpty()) {
            setStatus("No HTTP(S) JS files available for source map analysis");
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
                            // Annotate leaks with exploit context
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
        setStatus("Analyzing source maps...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            consoleViewManager.appendRawText("\n=== SOURCE MAP ANALYSIS ===\n" + task.getValue() + "\n");
            setStatus("Source map analysis completed");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("Source map analysis failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    private void runParamMiner() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) {
            setStatus("Enter a target URL for param miner");
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
        setStatus("Running param miner on " + target + "...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            List<ParamMinerService.ParamFinding> findings = task.getValue();
            consoleViewManager.appendRawText("\n" + ParamMinerService.formatReport(findings, target) + "\n");
            setStatus("Param miner completed: " + findings.size() + " interesting parameter(s)");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("Param miner failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    private void runPassiveRecon() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) {
            setStatus("Enter a target URL for passive recon");
            return;
        }

        Task<PassiveReconService.PassiveReconResult> task = new Task<>() {
            @Override
            protected PassiveReconService.PassiveReconResult call() {
                return passiveReconService.scan(target);
            }
        };

        setStatus("Passive recon running on " + target + "...");
        progressBar.setVisible(true);

        task.setOnSucceeded(ev -> {
            progressBar.setVisible(false);
            PassiveReconService.PassiveReconResult result = task.getValue();
            consoleViewManager.appendRawText("\n" + PassiveReconService.formatReport(result) + "\n");
            setStatus("Passive recon completed for " + target);
        });

        task.setOnFailed(ev -> {
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("Passive recon failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task, "passive-recon");
        worker.setDaemon(true);
        worker.start();
    }

    private void runSecretsValidation() {
        if (lastJsAnalysisResult == null) {
            setStatus("No JS analysis results available. Run JS Security Scan first.");
            return;
        }
        List<it.r2u.anibus.model.LeakInfo> leaks = lastJsAnalysisResult.getSensitiveInfo();
        if (leaks == null || leaks.isEmpty()) {
            setStatus("No leaked secrets found in the last JS analysis.");
            return;
        }
        String source = hostTextField.getText().isBlank() ? "JS Analysis" : hostTextField.getText();

        Task<List<SecretsValidationService.ValidationResult>> task = new Task<>() {
            @Override
            protected List<SecretsValidationService.ValidationResult> call() {
                return secretsValidationService.validate(leaks);
            }
        };

        setStatus("Validating " + leaks.size() + " leaked secret(s)...");
        progressBar.setVisible(true);

        task.setOnSucceeded(ev -> {
            progressBar.setVisible(false);
            List<SecretsValidationService.ValidationResult> validationResults = task.getValue();
            consoleViewManager.appendRawText("\n" + SecretsValidationService.formatReport(validationResults, source) + "\n");
            setStatus("Secrets validation completed: " + validationResults.size() + " pattern match(es).");
        });

        task.setOnFailed(ev -> {
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("Secrets validation failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task, "secrets-validation");
        worker.setDaemon(true);
        worker.start();
    }

    private void runDiffMode() {
        if (results.isEmpty()) {
            setStatus("No current scan results to compare");
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

        setStatus("Computing diff against " + oldFile.getName() + "...");
        task.setOnSucceeded(ev -> {
            ScanDiffService.DiffResult diff = task.getValue();
            consoleViewManager.appendRawText("\n" + ScanDiffService.formatReport(diff) + "\n");
            setStatus("Diff mode completed");
        });
        task.setOnFailed(ev -> {
            Throwable ex = task.getException();
            setStatus("Diff mode failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    /** Ports open in the previous scheduled scan — used for drift detection. */
    private java.util.Set<Integer> prevScheduledPorts = null;

    private void startScheduledScan() {
        if (scanSchedulerService.isRunning()) {
            setStatus(scanSchedulerService.statusString());
            return;
        }

        String host = extractHostOrDomain(hostTextField.getText());
        int[] ports = scanner.parsePortsRange(portsTextField.getText());
        if (host.isBlank() || ports == null) {
            setStatus("Provide host and valid port range before scheduling");
            return;
        }

        int start = ports[0];
        int end = ports[1];
        prevScheduledPorts = null; // reset drift baseline on new schedule

        scanSchedulerService.schedule(Duration.ofMinutes(30),
            () -> runScheduledTcpSnapshot(host, start, end),
            snapshot -> Platform.runLater(() -> {
                results.setAll(snapshot.results());
                consoleViewManager.clear();
                consoleViewManager.appendRawText("=== SCHEDULED SCAN ===\n");
                snapshot.results().forEach(consoleViewManager::appendToConsole);
                setStatus("Scheduled scan finished at " + snapshot.formattedTimestamp() +
                        " (" + snapshot.results().size() + " open port(s))");

                // Security drift detection
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
            }),
            error -> Platform.runLater(() -> setStatus("Scheduled scan failed: " + error))
        );

        setStatus("Scheduled scan started (every 30 minutes)");
    }

    private String buildDriftMessage(String host, java.util.Set<Integer> opened, java.util.Set<Integer> closed) {
        StringBuilder sb = new StringBuilder("\n⚠ SECURITY DRIFT DETECTED on ").append(host).append("\n");
        if (!opened.isEmpty()) sb.append("  [OPENED] ports: ").append(opened).append("\n");
        if (!closed.isEmpty()) sb.append("  [CLOSED] ports: ").append(closed).append("\n");
        return sb.toString();
    }

    private void stopScheduledScan() {
        scanSchedulerService.cancel();
        setStatus("Scheduled scan stopped");
    }

    private void runXssScan() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) {
            setStatus("Enter a target URL for XSS scan");
            return;
        }
        Task<List<XssDetector.XssResult>> task = new Task<>() {
            @Override
            protected List<XssDetector.XssResult> call() {
                return xssDetector.scan(target, null, p -> updateProgress(p, 1.0));
            }
        };
        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        setStatus("XSS scan running on " + target + "...");
        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            List<XssDetector.XssResult> hits = task.getValue();
            consoleViewManager.appendRawText("\n" + XssDetector.formatReport(hits, target) + "\n");
            long vulns = hits.stream().filter(XssDetector.XssResult::reflected).count();
            setStatus("XSS scan completed: " + vulns + " reflected finding(s)");
        });
        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("XSS scan failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });
        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    private void runCorsCheck() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) {
            setStatus("Enter a target URL for CORS check");
            return;
        }
        Task<List<CorsChecker.CorsResult>> task = new Task<>() {
            @Override
            protected List<CorsChecker.CorsResult> call() {
                return corsChecker.check(target);
            }
        };
        setStatus("CORS check running on " + target + "...");
        task.setOnSucceeded(ev -> {
            List<CorsChecker.CorsResult> corsResults = task.getValue();
            consoleViewManager.appendRawText("\n" + CorsChecker.formatReport(corsResults, target) + "\n");
            long issues = corsResults.stream().filter(r -> r.risk() != CorsChecker.CorsRisk.SAFE).count();
            setStatus("CORS check completed: " + issues + " misconfiguration(s)");
        });
        task.setOnFailed(ev -> {
            Throwable ex = task.getException();
            setStatus("CORS check failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });
        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    private void runJwtAnalysis() {
        String rawText = consoleTextArea.getText();
        if (rawText == null || rawText.isBlank()) {
            setStatus("Run JS Analysis first to populate console with JWT tokens");
            return;
        }
        List<JwtAnalyzer.JwtFinding> findings = jwtAnalyzer.analyzeFromText(rawText);
        String report = JwtAnalyzer.formatReport(findings, hostTextField.getText());
        consoleViewManager.appendRawText("\n" + report + "\n");
        setStatus("JWT analysis completed: " + findings.size() + " token(s) found");
    }

    private void runSsrfScan() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) { setStatus("Enter a target URL first"); return; }
        setStatus("Running SSRF scan against " + target + "…");
        Task<List<SsrfDetector.SsrfResult>> task = new Task<>() {
            @Override
            protected List<SsrfDetector.SsrfResult> call() {
                return ssrfDetector.scan(target, p -> updateProgress(p, 1.0));
            }
        };
        task.setOnSucceeded(ev -> {
            List<SsrfDetector.SsrfResult> ssrfResults = task.getValue();
            consoleViewManager.appendRawText("\n" + SsrfDetector.formatReport(ssrfResults, target) + "\n");
            long vulns = ssrfResults.stream().filter(SsrfDetector.SsrfResult::potentiallyVulnerable).count();
            setStatus("SSRF scan complete: " + vulns + " potential issue(s) found");
        });
        task.setOnFailed(ev -> setStatus("SSRF scan error: " + task.getException().getMessage()));
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        Thread t = new Thread(task, "ssrf-scan");
        t.setDaemon(true);
        t.start();
    }

    private void runDirectoryBruteforce() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) { setStatus("Enter a target URL first"); return; }
        setStatus("Directory bruteforce running against " + target + "…");
        Task<List<DirectoryBruteforcer.PathResult>> task = new Task<>() {
            @Override
            protected List<DirectoryBruteforcer.PathResult> call() {
                return dirBruteforcer.scan(target, p -> updateProgress(p, 1.0));
            }
        };
        task.setOnSucceeded(ev -> {
            List<DirectoryBruteforcer.PathResult> hits = task.getValue();
            consoleViewManager.appendRawText("\n" + DirectoryBruteforcer.formatReport(hits, target) + "\n");
            setStatus("Directory bruteforce complete: " + hits.size() + " path(s) found");
        });
        task.setOnFailed(ev -> setStatus("Dir bruteforce error: " + task.getException().getMessage()));
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        Thread t = new Thread(task, "dir-bruteforce");
        t.setDaemon(true);
        t.start();
    }

    private void runWhoisLookup() {
        String host = extractHostOrDomain(hostTextField.getText());
        if (host.isBlank()) { setStatus("Enter a target host/domain first"); return; }
        setStatus("WHOIS lookup for " + host + "…");
        Task<WhoisService.WhoisResult> task = new Task<>() {
            @Override
            protected WhoisService.WhoisResult call() {
                return whoisService.lookup(host);
            }
        };
        task.setOnSucceeded(ev -> {
            WhoisService.WhoisResult wr = task.getValue();
            consoleViewManager.appendRawText("\n" + WhoisService.formatReport(wr) + "\n");
            setStatus("WHOIS lookup complete for " + host);
        });
        task.setOnFailed(ev -> setStatus("WHOIS error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "whois-lookup");
        t.setDaemon(true);
        t.start();
    }

    private void runSslAudit() {
        String host = extractHostOrDomain(hostTextField.getText());
        if (host.isBlank()) { setStatus("Enter a target host first"); return; }
        setStatus("SSL/TLS audit running for " + host + "…");
        Task<SslTlsAuditor.AuditResult> task = new Task<>() {
            @Override
            protected SslTlsAuditor.AuditResult call() {
                return sslTlsAuditor.audit(host, 443);
            }
        };
        task.setOnSucceeded(ev -> {
            SslTlsAuditor.AuditResult r = task.getValue();
            consoleViewManager.appendRawText("\n" + SslTlsAuditor.formatReport(r) + "\n");
            setStatus("SSL/TLS audit complete [" + r.overallRisk() + "]");
        });
        task.setOnFailed(ev -> setStatus("SSL audit error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "ssl-audit");
        t.setDaemon(true);
        t.start();
    }

    private void runGraphqlScan() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) { setStatus("Enter a target URL first"); return; }
        setStatus("GraphQL introspection scan running against " + target + "…");
        Task<List<GraphqlScanner.GraphqlEndpoint>> task = new Task<>() {
            @Override
            protected List<GraphqlScanner.GraphqlEndpoint> call() {
                return graphqlScanner.scan(target);
            }
        };
        task.setOnSucceeded(ev -> {
            List<GraphqlScanner.GraphqlEndpoint> eps = task.getValue();
            consoleViewManager.appendRawText("\n" + GraphqlScanner.formatReport(eps, target) + "\n");
            long exposed = eps.stream().filter(GraphqlScanner.GraphqlEndpoint::introspectionEnabled).count();
            setStatus("GraphQL scan complete: " + exposed + " exposed endpoint(s) of " + eps.size() + " found");
        });
        task.setOnFailed(ev -> setStatus("GraphQL scan error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "graphql-scan");
        t.setDaemon(true);
        t.start();
    }

    private void runXxeScan() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) { setStatus("Enter a target URL first"); return; }
        setStatus("XXE scan running against " + target + "…");
        Task<List<XxeDetector.XxeResult>> task = new Task<>() {
            @Override
            protected List<XxeDetector.XxeResult> call() {
                return xxeDetector.scan(target, p -> updateProgress(p, 1.0));
            }
        };
        task.setOnSucceeded(ev -> {
            List<XxeDetector.XxeResult> xxeResults = task.getValue();
            consoleViewManager.appendRawText("\n" + XxeDetector.formatReport(xxeResults, target) + "\n");
            setStatus("XXE scan complete: " + xxeResults.size() + " finding(s)");
        });
        task.setOnFailed(ev -> setStatus("XXE scan error: " + task.getException().getMessage()));
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        Thread t = new Thread(task, "xxe-scan");
        t.setDaemon(true);
        t.start();
    }

    private void runTakeoverCheck() {
        String input = hostTextField.getText().trim();
        if (input.isBlank()) { setStatus("Enter a domain first"); return; }
        String domain = extractHostOrDomain(input);
        if (domain.isBlank()) { setStatus("Cannot resolve domain from input"); return; }
        setStatus("Subdomain takeover check running for " + domain + "…");
        Task<List<SubdomainTakeoverChecker.TakeoverFinding>> task = new Task<>() {
            @Override
            protected List<SubdomainTakeoverChecker.TakeoverFinding> call() {
                return takeoverChecker.check(domain);
            }
        };
        task.setOnSucceeded(ev -> {
            List<SubdomainTakeoverChecker.TakeoverFinding> found = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + SubdomainTakeoverChecker.formatReport(found, domain) + "\n");
            long vuln = found.stream().filter(SubdomainTakeoverChecker.TakeoverFinding::vulnerable).count();
            setStatus("Takeover check complete: " + vuln + " vulnerable of " + found.size() + " probed");
        });
        task.setOnFailed(ev -> setStatus("Takeover check error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "takeover-check");
        t.setDaemon(true);
        t.start();
    }

    private void runDnsAxfr() {
        String input = hostTextField.getText().trim();
        if (input.isBlank()) { setStatus("Enter a domain first"); return; }
        String domain = extractHostOrDomain(input);
        if (domain.isBlank()) { setStatus("Cannot resolve domain from input"); return; }
        setStatus("DNS Zone Transfer (AXFR) attempt for " + domain + "…");
        Task<DnsZoneTransferService.ZoneTransferResult> task = new Task<>() {
            @Override
            protected DnsZoneTransferService.ZoneTransferResult call() {
                return dnsAxfrService.attemptAxfr(domain);
            }
        };
        task.setOnSucceeded(ev -> {
            DnsZoneTransferService.ZoneTransferResult result = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + DnsZoneTransferService.formatReport(result) + "\n");
            String msg = result.transferSucceeded()
                ? "AXFR SUCCEEDED — " + result.records().size() + " record(s) retrieved!"
                : "AXFR refused (zone transfer is protected)";
            setStatus("DNS AXFR: " + msg);
        });
        task.setOnFailed(ev -> setStatus("AXFR error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "dns-axfr");
        t.setDaemon(true);
        t.start();
    }

    private void runLog4ShellCheck() {
        String input = hostTextField.getText().trim();
        if (input.isBlank()) { setStatus("Enter a target first"); return; }
        String domain = extractHostOrDomain(input);
        if (domain.isBlank()) { setStatus("Cannot resolve host from input"); return; }
        // Try to parse port from results, default to 80
        int port = results.isEmpty() ? 80 : results.get(0).getPort();
        setStatus("Log4Shell check (CVE-2021-44228) against " + domain + ":" + port + "…");
        Task<List<Log4ShellChecker.Log4ShellFinding>> task = new Task<>() {
            @Override
            protected List<Log4ShellChecker.Log4ShellFinding> call() {
                return log4ShellChecker.scan(domain, port);
            }
        };
        task.setOnSucceeded(ev -> {
            List<Log4ShellChecker.Log4ShellFinding> found = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + Log4ShellChecker.formatReport(found, domain) + "\n");
            setStatus("Log4Shell check complete: " + found.size() + " indicator(s) found");
        });
        task.setOnFailed(ev -> setStatus("Log4Shell check error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "log4shell-check");
        t.setDaemon(true);
        t.start();
    }

    private void runSpring4ShellCheck() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) { setStatus("Enter a target URL first"); return; }
        setStatus("Spring4Shell check (CVE-2022-22965) against " + target + "…");
        Task<List<Spring4ShellChecker.Spring4ShellFinding>> task = new Task<>() {
            @Override
            protected List<Spring4ShellChecker.Spring4ShellFinding> call() {
                return spring4ShellChecker.scan(target);
            }
        };
        task.setOnSucceeded(ev -> {
            List<Spring4ShellChecker.Spring4ShellFinding> found = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + Spring4ShellChecker.formatReport(found, target) + "\n");
            setStatus("Spring4Shell check complete: " + found.size() + " indicator(s) found");
        });
        task.setOnFailed(ev -> setStatus("Spring4Shell error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "spring4shell-check");
        t.setDaemon(true);
        t.start();
    }

    private void runWebSocketDetect() {
        String input = hostTextField.getText().trim();
        if (input.isBlank()) { setStatus("Enter a target first"); return; }
        String domain = extractHostOrDomain(input);
        if (domain.isBlank()) { setStatus("Cannot resolve host from input"); return; }
        int port = results.isEmpty() ? 80 : results.get(0).getPort();
        setStatus("WebSocket detection on " + domain + ":" + port + "…");
        Task<List<WebSocketDetector.WsEndpoint>> task = new Task<>() {
            @Override
            protected List<WebSocketDetector.WsEndpoint> call() {
                return webSocketDetector.detect(domain, port);
            }
        };
        task.setOnSucceeded(ev -> {
            List<WebSocketDetector.WsEndpoint> eps = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + WebSocketDetector.formatReport(eps, domain + ":" + port) + "\n");
            setStatus("WebSocket detection complete: " + eps.size() + " endpoint(s) found");
        });
        task.setOnFailed(ev -> setStatus("WebSocket detect error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "ws-detect");
        t.setDaemon(true);
        t.start();
    }

    private void runHttpProtocolDetect() {
        String input = hostTextField.getText().trim();
        if (input.isBlank()) { setStatus("Enter a target first"); return; }
        String domain = extractHostOrDomain(input);
        if (domain.isBlank()) { setStatus("Cannot resolve host from input"); return; }
        int port = results.isEmpty() ? 80 : results.get(0).getPort();
        setStatus("HTTP protocol detection on " + domain + ":" + port + "…");
        Task<HttpProtocolDetector.ProtocolResult> task = new Task<>() {
            @Override
            protected HttpProtocolDetector.ProtocolResult call() {
                return httpProtocolDetector.detect(domain, port);
            }
        };
        task.setOnSucceeded(ev -> {
            HttpProtocolDetector.ProtocolResult r = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + HttpProtocolDetector.formatReport(r) + "\n");
            setStatus(String.format("HTTP proto: HTTP/1.1=%s  HTTP/2=%s  HTTP/3=%s",
                r.http11() ? "✓" : "✗", r.http2() ? "✓" : "✗",
                r.http3Advertised() ? "✓" : "✗"));
        });
        task.setOnFailed(ev -> setStatus("HTTP protocol detect error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "http-proto-detect");
        t.setDaemon(true);
        t.start();
    }

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

    private String extractHostOrDomain(String input) {
        if (input == null) return "";
        String trimmed = input.trim();
        if (trimmed.isBlank()) return "";
        try {
            String candidate = trimmed;
            if (!candidate.startsWith("http://") && !candidate.startsWith("https://")) {
                candidate = "https://" + candidate;
            }
            URI uri = new URI(candidate);
            if (uri.getHost() != null) {
                return uri.getHost().trim();
            }
        } catch (URISyntaxException ignored) {
            // Fallback to host sanitizer for raw hostnames/IPs.
        }
        return hostResolver.sanitizeHost(trimmed);
    }

    private String ensureHttpUrl(String input) {
        String host = extractHostOrDomain(input);
        if (host.isBlank()) return "";
        if (input != null && (input.startsWith("http://") || input.startsWith("https://"))) {
            return input.trim();
        }
        return "https://" + host;
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
            hostResolver.resolveHostAsync(sanitizedHost, resolvedHostLabel,
                    this::autoSelectProxyForCurrentTarget);
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

            // Auto-select proxy by target country if pool is ready
            if (proxyRoutingService != null && proxyRoutingService.isReady()) {
                String resolvedIp = hostResolver.extractIPFromResolvedText(
                        resolvedHostLabel.getText());
                String geoTarget = resolvedIp.isBlank()
                        ? hostTextField.getText().trim() : resolvedIp;
                proxyRoutingService.selectProxy(geoTarget).ifPresent(this::updateActiveProxy);
            }

            consoleViewManager.printScanHeader(
                    hostTextField.getText(), currentActiveProxy);

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
    protected void onUdpScanClick() {
        runUdpScan();
    }

    @FXML
    protected void onSubdomainEnumClick() {
        runSubdomainEnumeration();
    }

    @FXML
    protected void onSourceMapClick() {
        runSourceMapAnalysis();
    }

    @FXML
    protected void onParamMinerClick() {
        runParamMiner();
    }

    @FXML
    protected void onDiffModeClick() {
        runDiffMode();
    }

    @FXML
    protected void onSchedulerStartClick() {
        startScheduledScan();
    }

    @FXML
    protected void onSchedulerStopClick() {
        stopScheduledScan();
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

    /* -- Proxy tab -------------------------------------------- */

    @FXML
    protected void onStartProxyClick() {
        LanguageManager lm = LanguageManager.getInstance();
        startProxyButton.setDisable(true);
        clearProxyButton.setText(lm.get("btn.stopHarvesting"));
        proxyHarvesting = true;
        proxyLogArea.clear();
        appendProxyLog("═══════════════════════════════════════\n");
        appendProxyLog("  ANIBUS PROXY HARVESTER\n");
        appendProxyLog("═══════════════════════════════════════\n");

        proxyRoutingService = new ProxyRoutingService();
        proxyRoutingService.setLogCallback(
                msg -> Platform.runLater(() -> appendProxyLog(msg)));
        proxyRoutingService.setStatsCallback(stats -> Platform.runLater(() -> {
            if (stats[0] > 0) proxyStatCandidates.setText(String.valueOf(stats[0]));
            proxyStatLive.setText(String.valueOf(stats[1]));
            proxyStatCountries.setText(String.valueOf(stats[2]));
        }));
        proxyRoutingService.setProgressCallback(
                val -> Platform.runLater(() -> {
                    proxyProgressBar.setVisible(true);
                    proxyProgressBar.setProgress(val);
                }));

        proxyRoutingService.initializeAsync().thenRun(() -> Platform.runLater(() -> {
            proxyHarvesting = false;
            startProxyButton.setDisable(false);
            clearProxyButton.setText(lm.get("btn.clear"));
            proxyProgressBar.setVisible(false);
            if (proxyRoutingService.isReady()) {
                appendProxyLog("\n✓ Pool ready — " + proxyRoutingService.poolSize() + " live proxies\n");
                refreshAvailableProxiesForChainBuilder();
                if (proxyRoutingService.hasSavedPool()) {
                    loadProxyButton.setText(LanguageManager.getInstance().get("btn.loadFromFile") + " ✓");
                    loadProxyButton.setTooltip(new Tooltip(
                            "Cached pool: " + proxyRoutingService.savedPoolPath()));
                }
                String target = hostTextField.getText().trim();
                if (!target.isBlank()) {
                    proxyRoutingService.selectProxy(target).ifPresentOrElse(
                        p -> {
                            updateActiveProxy(p);
                            appendProxyLog("\n● Active proxy: "
                                    + p.host() + ":" + p.port()
                                    + "  [" + p.type() + "]  "
                                    + p.countryCode() + "  ~  " + p.latencyMs() + " ms\n");
                        },
                        () -> appendProxyLog("\n✗ No suitable proxy for target\n")
                    );
                }
            } else {
                appendProxyLog("\n✗ No live proxies found\n");
                proxyStatusDot.setFill(javafx.scene.paint.Color.web("#ff453a"));
                activeProxyLabel.setText("No live proxies found");
                activeProxyLabel.setStyle("-fx-text-fill: #ff453a;");
            }
        }));
    }

    @FXML
    protected void onLoadProxyClick() {
        proxyRoutingService = new ProxyRoutingService();
        proxyRoutingService.setLogCallback(
                msg -> Platform.runLater(() -> appendProxyLog(msg)));
        proxyRoutingService.setStatsCallback(stats -> Platform.runLater(() -> {
            if (stats[0] > 0) proxyStatCandidates.setText(String.valueOf(stats[0]));
            proxyStatLive.setText(String.valueOf(stats[1]));
            proxyStatCountries.setText(String.valueOf(stats[2]));
        }));

        proxyLogArea.clear();
        appendProxyLog("═══════════════════════════════════════\n");
        appendProxyLog("  LOADING PROXY POOL FROM FILE\n");
        appendProxyLog("═══════════════════════════════════════\n");

        if (!proxyRoutingService.hasSavedPool()) {
            appendProxyLog("✗ No saved proxy file found.\n");
            appendProxyLog("  Run harvesting first to create one.\n");
            return;
        }

        int count = proxyRoutingService.loadFromFile();
        if (count == 0) {
            appendProxyLog("✗ File is empty or unreadable.\n");
            return;
        }

        appendProxyLog("✓ Loaded " + count + " proxies\n");
        appendProxyLog("  File: " + proxyRoutingService.savedPoolPath() + "\n");
        loadProxyButton.setDisable(true);
        refreshAvailableProxiesForChainBuilder();

        String target = hostTextField.getText().trim();
        if (!target.isBlank()) {
            String resolvedIp = hostResolver.extractIPFromResolvedText(
                    resolvedHostLabel.getText());
            String geoTarget = resolvedIp.isBlank() ? target : resolvedIp;
            proxyRoutingService.selectProxy(geoTarget).ifPresentOrElse(
                p -> {
                    updateActiveProxy(p);
                    appendProxyLog("\n● Active proxy: "
                            + p.host() + ":" + p.port()
                            + "  [" + p.type() + "]  "
                            + p.countryCode() + "  ~  " + p.latencyMs() + " ms\n");
                },
                () -> appendProxyLog("\n✗ No suitable proxy for target\n")
            );
        }
    }

    @FXML
    protected void onClearProxyLogClick() {
        LanguageManager lm = LanguageManager.getInstance();
        if (proxyHarvesting && proxyRoutingService != null) {
            // Stop the running harvester
            proxyRoutingService.cancel();
            proxyHarvesting = false;
            startProxyButton.setDisable(false);
            clearProxyButton.setText(lm.get("btn.clear"));
            appendProxyLog("\n■ Harvesting stopped by user.\n");
            return;
        }
        proxyLogArea.clear();
        proxyStatCandidates.setText("—");
        proxyStatLive.setText("—");
        proxyStatCountries.setText("—");
        proxyPhaseLabel.setText("IDLE");
        proxyProgressBar.setVisible(false);
        proxyStatusDot.setFill(javafx.scene.paint.Color.web("#8E8E93"));
        activeProxyLabel.setText("No active proxy");
        activeProxyLabel.setStyle("");
        currentActiveProxy = null;
        currentProxyChain.clear();
        if (proxyChainListView != null) {
            proxyChainListView.getItems().clear();
        }
        displayProxyChain();
        loadProxyButton.setDisable(false);
    }

    private void updateActiveProxy(ProxyNode p) {
        currentActiveProxy = p;
        proxyStatusDot.setFill(javafx.scene.paint.Color.web("#30d158"));
        activeProxyLabel.setText(
                p.host() + ":" + p.port()
                + "  [" + p.type() + "]  "
                + p.countryCode() + "  ~  " + p.latencyMs() + " ms");
        activeProxyLabel.setStyle("-fx-text-fill: #30d158; -fx-font-weight: 600;");
        rotateProxyButton.setVisible(true);
        rotateProxyButton.setManaged(true);
    }

    @FXML
    protected void onRotateProxyClick() {
        if (proxyRoutingService == null || !proxyRoutingService.isReady()) return;
        String resolvedIp = hostResolver.extractIPFromResolvedText(resolvedHostLabel.getText());
        String geoTarget = resolvedIp.isBlank() ? hostTextField.getText().trim() : resolvedIp;
        // Exclude current proxy from selection by temporarily marking it dead, then restoring
        ProxyNode prev = currentActiveProxy;
        if (prev != null) proxyRoutingService.failover(prev, geoTarget).ifPresentOrElse(
            p -> {
                updateActiveProxy(p);
                appendProxyLog("\n↻ Rotated to: " + p.host() + ":" + p.port()
                        + "  [" + p.type() + "]  " + p.countryCode()
                        + "  ~  " + p.latencyMs() + " ms\n");
            },
            () -> {
                // failover removed prev, try selecting again freshly
                proxyRoutingService.selectProxy(geoTarget).ifPresent(p -> {
                    updateActiveProxy(p);
                    appendProxyLog("\n↻ Rotated to: " + p.host() + ":" + p.port()
                            + "  [" + p.type() + "]  " + p.countryCode()
                            + "  ~  " + p.latencyMs() + " ms\n");
                });
            });
        else
            proxyRoutingService.selectProxy(geoTarget).ifPresent(this::updateActiveProxy);
    }

    /**
     * Called after host resolve completes — re-selects geo-optimal proxy for new target.
     * Runs on JavaFX thread (called from resolveHostAsync onUpdate callback).
     */
    private void autoSelectProxyForCurrentTarget() {
        if (proxyRoutingService == null || !proxyRoutingService.isReady()) return;
        String resolvedIp = hostResolver.extractIPFromResolvedText(resolvedHostLabel.getText());
        if (resolvedIp.isBlank()) return;
        proxyRoutingService.selectProxy(resolvedIp).ifPresent(p -> {
            if (currentActiveProxy == null
                    || !p.countryCode().equals(currentActiveProxy.countryCode())) {
                updateActiveProxy(p);
            }
        });
    }

    private void appendProxyLog(String text) {
        proxyLogArea.appendText(text);
        proxyLogArea.setScrollTop(Double.MAX_VALUE);
    }

    /**
     * Handle "Build Chain" button click to create/edit proxy chain.
     */
    @FXML
    protected void onBuildChainClick() {
        LanguageManager lm = LanguageManager.getInstance();
        
        if (proxyRoutingService == null || !proxyRoutingService.isReady()) {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle(lm.get("dialog.chainBuilder.emptyTitle"));
            alert.setHeaderText(lm.get("dialog.chainBuilder.emptyHeader"));
            alert.setContentText(lm.get("dialog.chainBuilder.emptyContent"));
            alert.showAndWait();
            return;
        }

        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(lm.get("dialog.chainBuilder.title"));
        alert.setHeaderText(lm.get("dialog.chainBuilder.header"));
        String content = lm.get("dialog.chainBuilder.content");
        alert.setContentText(String.format(content, proxyRoutingService.poolSize()));
        alert.showAndWait();

        if (proxyChainListView != null && !proxyChainListView.getItems().isEmpty()) {
            syncChainFromListView();
            appendProxyLog("\n● Chain updated via drag-and-drop builder\n");
            return;
        }

        if (currentActiveProxy != null) {
            currentProxyChain.clear();
            currentProxyChain.add(currentActiveProxy);
            if (proxyChainListView != null) {
                String label = formatProxyNodeDisplay(currentActiveProxy);
                proxyVisualMap.put(label, currentActiveProxy);
                proxyChainListView.getItems().setAll(label);
            }
            displayProxyChain();
            String chainMsg = String.format(
                lm.get("dialog.chain.initialized"),
                currentActiveProxy.host(),
                currentActiveProxy.port()
            );
            appendProxyLog("\n" + chainMsg + "\n");
        }
    }

    /**
     * Display current proxy chain in the UI chain display area.
     */
    private void displayProxyChain() {
        if (currentProxyChain.isEmpty()) {
            chainDisplayCard.setVisible(false);
            chainDisplayCard.setManaged(false);
            return;
        }

        chainDisplayCard.setVisible(true);
        chainDisplayCard.setManaged(true);
        
        // Use ProxyChainService.formatChain() for consistent formatting
        String chainDisplay = it.r2u.anibus.service.network.proxy.ProxyChainService.formatChain(currentProxyChain);
        chainDisplayArea.setText(chainDisplay);
        if (proxyChainListView != null) {
            List<String> labels = currentProxyChain.stream().map(this::formatProxyNodeDisplay).toList();
            proxyChainListView.getItems().setAll(labels);
        }
    }

    /* -- Language switching ----------------------------------- */

    /**
     * Apply current language bundle to all static UI elements.
     * Call after language change or on first initialize.
     */
    private void applyLanguage() {
        LanguageManager lm = LanguageManager.getInstance();

        // Nav bar
        aboutButton.setText(lm.get("nav.about"));

        // Sidebar — Scan Target card
        sectionScanTargetLabel.setText(lm.get("section.scanTarget"));
        labelTargetKey.setText(lm.get("label.target"));
        hostTextField.setPromptText(lm.get("prompt.host"));
        labelPortRangeKey.setText(lm.get("label.portRange"));
        portsTextField.setPromptText(lm.get("prompt.ports"));
        labelThreadsKey.setText(lm.get("label.threads"));
        labelOptionsKey.setText(lm.get("label.options"));

        // Options
        optionJsTitle.setText(lm.get("option.jsAnalysis"));
        optionJsDesc.setText(lm.get("option.jsAnalysis.desc"));
        optionSqlTitle.setText(lm.get("option.sqlInjection"));
        optionSqlDesc.setText(lm.get("option.sqlInjection.desc"));

        // Buttons
        scanButton.setText(lm.get("btn.startScan"));
        stopButton.setText(lm.get("btn.stop"));
        exportButton.setText(lm.get("btn.export"));
        clearButton.setText(lm.get("btn.clear"));
        jsExportButton.setText(lm.get("btn.exportAnalysis"));

        // Host Info card
        sectionHostInfoLabel.setText(lm.get("section.hostInfo"));
        keyIpAddressLabel.setText(lm.get("key.ipAddress"));
        keyHostnameLabel.setText(lm.get("key.hostname"));
        keyScanTimeLabel.setText(lm.get("key.scanTime"));
        keyPortsScannedLabel.setText(lm.get("key.portsScanned"));
        keyOpenPortsLabel.setText(lm.get("key.openPorts"));
        keyAvgLatencyLabel.setText(lm.get("key.avgLatency"));

        // Console / results header
        consoleHeaderLabel.setText(
            isJsAnalysisMode ? lm.get("console.headerJs") : lm.get("console.header"));

        // Tabs
        tabScanResults.setText(lm.get("tab.scanResults"));
        tabJsAnalysis.setText(lm.get("tab.jsAnalysis"));
        tabSqlInjection.setText("SQL Injection");
        tabTopology.setText("Topology Map");
        tabProxy.setText(lm.get("tab.proxy"));
        tabStatistics.setText("Statistics");
        startProxyButton.setText(lm.get("btn.startHarvesting"));
        clearProxyButton.setText(lm.get("btn.clear"));
        loadProxyButton.setText(lm.get("btn.loadFromFile"));
        rotateProxyButton.setText(lm.get("btn.rotateProxy"));

        plannedFeaturesLabel.setText(lm.get("section.plannedFeatures"));
        udpScanButton.setText(lm.get("btn.udpScan"));
        subdomainButton.setText(lm.get("btn.subdomains"));
        sourceMapButton.setText(lm.get("btn.sourceMaps"));
        paramMinerButton.setText(lm.get("btn.paramMiner"));
        diffModeButton.setText(lm.get("btn.diffMode"));
        schedulerStartButton.setText(lm.get("btn.schedulerOn"));
        schedulerStopButton.setText(lm.get("btn.schedulerOff"));

        // JS Analysis pane
        placeholderTitleLabel.setText(lm.get("placeholder.noData"));
        placeholderDescLabel.setText(lm.get("placeholder.noData.desc"));
        keyEndpointsLabel.setText(lm.get("key.endpoints"));
        keyDataStructuresLabel.setText(lm.get("key.dataStructures"));
        keyDbSchemasLabel.setText(lm.get("key.dbSchemas"));
        keySensitiveInfoLabel.setText(lm.get("key.sensitiveInfo"));
        keyArchitectureLabel.setText(lm.get("key.architecture"));
        subtitleDataStructuresLabel.setText(lm.get("subtitle.dataStructures"));

        // Refresh result count label with translated strings
        refreshResultCountLabel();

        // Sync language radio selection in config menu
        configMenuButton.setText(lm.get("menu.configuration"));
        Menu langMenu = (Menu) configMenuButton.getItems().get(0);
        langMenu.setText(lm.get("menu.language"));
        LanguageManager.Language curLang = LanguageManager.getInstance().getLanguage();
        for (var item : langMenu.getItems()) {
            if (item instanceof RadioMenuItem ri) {
                ri.setSelected(
                    (curLang == LanguageManager.Language.EN && "English".equals(ri.getText())) ||
                    (curLang == LanguageManager.Language.IT && "Italiano".equals(ri.getText())) ||
                    (curLang == LanguageManager.Language.RU && "Русский".equals(ri.getText()))
                );
            }
        }
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

    private void applyTheme(boolean light) {
        var scene = consoleTextArea.getScene();
        if (scene == null) return;
        var sheets = scene.getStylesheets();
        String lightUrl = getClass().getResource("anibus-style-light.css").toExternalForm();
        if (light) {
            if (!sheets.contains(lightUrl)) sheets.add(lightUrl);
        } else {
            sheets.remove(lightUrl);
        }
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

        // Infrastructure inference
        if (result.getArchitecture() != null && result.getArchitecture().getInfrastructureInfo() != null) {
            it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo infra =
                result.getArchitecture().getInfrastructureInfo();
            if (infra.hasFindings()) {
                detailedResults.append("\n=== INFRASTRUCTURE INFERENCE ===\n");

                it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.ContainerRuntime cr = infra.getContainerRuntime();
                if (cr != it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.ContainerRuntime.NONE &&
                    cr != it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.ContainerRuntime.UNKNOWN) {
                    detailedResults.append(String.format("• Containerization : %s (confidence %.0f%%)%n",
                        cr, infra.getContainerConfidence() * 100));
                }

                it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.Orchestrator orch = infra.getOrchestrator();
                if (orch != it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.Orchestrator.NONE &&
                    orch != it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.Orchestrator.UNKNOWN) {
                    detailedResults.append(String.format("• Orchestration    : %s (confidence %.0f%%)%n",
                        orch, infra.getOrchestratorConfidence() * 100));
                }

                it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.ProxyGateway pg = infra.getProxyGateway();
                if (pg != it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.ProxyGateway.NONE &&
                    pg != it.r2u.anibus.model.ArchitectureInfo.InfrastructureInfo.ProxyGateway.UNKNOWN) {
                    detailedResults.append(String.format("• Proxy/Gateway    : %s%n", pg));
                }

                if (infra.getEvidence() != null && !infra.getEvidence().isEmpty()) {
                    detailedResults.append("• Evidence:\n");
                    infra.getEvidence().forEach(e -> detailedResults.append("    - ").append(e).append("\n"));
                }
            }
        }


        detailedResults.append("\n=== ANALYSIS TIMING ===\n");
        appendAnalysisTimingSection(detailedResults, result);
        
        updateSqlInjectionResults(injectionResults);
        
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
                sb.append("      ").append(ep.toCurlCommand()).append("\n");
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
        List<LeakInfo> leaks = result.getSensitiveInfo() != null ? result.getSensitiveInfo() : java.util.Collections.emptyList();
        if (leaks.isEmpty()) {
            sb.append("  No sensitive findings for deep-dive.\n");
            return;
        }

        int shown = 0;
        for (LeakInfo leak : leaks) {
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
            .map(LeakInfo::getValue)
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

    private String inferModuleFromLeak(LeakInfo leak) {
        String combined = (leak.getType() + " " + leak.getValue() + " " + leak.getContext()).toLowerCase(Locale.ROOT);
        if (combined.contains("auth") || combined.contains("login") || combined.contains("token")) return "auth";
        if (combined.contains("payment") || combined.contains("billing") || combined.contains("checkout")) return "payment";
        if (combined.contains("order")) return "order";
        if (combined.contains("cart")) return "cart";
        if (combined.contains("profile") || combined.contains("user")) return "user";
        return "general";
    }

    private String inferTokenType(LeakInfo leak) {
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
        List<LeakInfo> leaks = result.getSensitiveInfo() != null ? result.getSensitiveInfo() : java.util.Collections.emptyList();
        List<DataStructureInfo> structures = result.getDataStructures() != null ? result.getDataStructures() : java.util.Collections.emptyList();
        List<EndpointInfo> endpoints = result.getEndpoints() != null ? result.getEndpoints() : java.util.Collections.emptyList();

        List<LeakInfo> tokenLeaks = leaks.stream()
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

        for (LeakInfo tokenLeak : tokenLeaks) {
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
            List<LeakInfo> leaks,
            it.r2u.anibus.model.ArchitectureInfo arch) {

        if (leaks == null || leaks.isEmpty()) {
            sb.append("  No sensitive information detected.\n");
            return;
        }

        boolean isMicroservices = arch != null
            && arch.getPattern() == it.r2u.anibus.model.ArchitectureInfo.ArchitecturePattern.MICROSERVICES;

        // Group by tier
        List<LeakInfo> critical  = new java.util.ArrayList<>();
        List<LeakInfo> important = new java.util.ArrayList<>();
        List<LeakInfo> lowRisk   = new java.util.ArrayList<>();

        for (LeakInfo l : leaks) {
            if (l.getPriority() >= 8)      critical.add(l);
            else if (l.getPriority() >= 5) important.add(l);
            else                           lowRisk.add(l);
        }
        // Sort within each tier: highest priority first, then by type for stability
        java.util.Comparator<LeakInfo> byPriorityDesc = java.util.Comparator
            .comparingInt(LeakInfo::getPriority).reversed()
            .thenComparing(l -> l.getType() != null ? l.getType() : "");
        critical.sort(byPriorityDesc);
        important.sort(byPriorityDesc);
        lowRisk.sort(byPriorityDesc);

        java.util.function.BiConsumer<String, List<LeakInfo>> renderTier =
            (header, items) -> {
                if (items.isEmpty()) return;
                sb.append("\n  ── ").append(header).append(" ").append("─".repeat(Math.max(0, 46 - header.length()))).append("\n");
                // Optionally group by service inside tier
                if (isMicroservices) {
                    Map<String, List<LeakInfo>> byService = new java.util.LinkedHashMap<>();
                    for (LeakInfo l : items) {
                        String svc = l.getService() != null ? l.getService() : "general";
                        byService.computeIfAbsent(svc, k -> new java.util.ArrayList<>()).add(l);
                    }
                    byService.forEach((svc, svcLeaks) -> {
                        sb.append("    [").append(svc.toUpperCase()).append("]\n");
                        for (LeakInfo l : svcLeaks) renderLeakLine(sb, l);
                    });
                } else {
                    for (LeakInfo l : items) renderLeakLine(sb, l);
                }
            };

        renderTier.accept("Critical (P8–P10)", critical);
        renderTier.accept("Important (P5–P7)", important);
        renderTier.accept("Low Risk (P1–P4)",  lowRisk);
    }

    /** Formats a single LeakInfo line. Long values are shown in full on the next line. */
    private void renderLeakLine(StringBuilder sb,
                                LeakInfo leak) {
        String rawValue = leak.getValue() != null ? leak.getValue() : "";
        String conf = switch (leak.getConfidence()) {
            case HIGH   -> "HIGH";
            case MEDIUM -> "MED ";
            case LOW    -> "LOW ";
        };

        sb.append("  [P").append(String.format("%2d", leak.getPriority())).append("] ")
          .append("[").append(conf).append("] ")
          .append(String.format("[RS:%4.1f] ", leak.riskScore()))
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
        if (sqlInjectionTextArea != null) sqlInjectionTextArea.clear();
    }

    private void updateSqlInjectionResults(Map<String, List<SQLInjectionAnalyzer.InjectionResult>> injectionResults) {
        if (sqlInjectionTextArea == null) {
            return;
        }

        if (injectionResults == null || injectionResults.isEmpty()) {
            sqlInjectionTextArea.setText("SQL injection testing was not run for this scan.");
            return;
        }

        sqlInjectionTextArea.setText(injectionAnalyzer.formatResults(injectionResults));
        sqlInjectionTextArea.setScrollTop(0);
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
    
    /* -- Console Mode Management Methods ---------------------- */
    
    /**
     * Switch console to JavaScript analysis mode.
     */
    private void switchToJsAnalysisMode() {
        Platform.runLater(() -> {
            LanguageManager lm = LanguageManager.getInstance();
            isJsAnalysisMode = true;
            consoleHeaderLabel.setText(lm.get("console.headerJs"));
            resultCountLabel.setText(lm.get("result.analysisCompleted"));

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
            LanguageManager lm = LanguageManager.getInstance();
            isJsAnalysisMode = false;
            consoleHeaderLabel.setText(lm.get("console.header"));
            refreshResultCountLabel();

            exportButton.setVisible(true);
            jsExportButton.setVisible(false);

            boolean hasResults = !results.isEmpty();
            clearButton.setDisable(!hasResults);
            exportButton.setDisable(!hasResults);
        });
    }
    
    /**
     * Updates result count label based on current mode.
     */
    private void refreshResultCountLabel() {
        LanguageManager lm = LanguageManager.getInstance();
        if (isJsAnalysisMode) {
            resultCountLabel.setText(lm.get("result.analysisCompleted"));
        } else {
            int n = results.size();
            resultCountLabel.setText(
                n == 0 ? lm.get("result.noResults") :
                n == 1 ? lm.get("result.onePort") :
                String.format(lm.get("result.manyPorts"), n)
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
        if (notificationService != null) {
            notificationService.shutdown();
        }
    }

    private void runSqlMetadataExtraction() {
        String host = hostTextField.getText().trim();
        if (host.isBlank()) { setStatus("Enter a host first"); return; }
        String targetUrl = host.startsWith("http") ? host : "http://" + host;
        setStatus("SQL Metadata Extraction — running…");
        Task<it.r2u.anibus.service.analysis.SqlMetadataExtractor.MetadataResult> task = new Task<>() {
            @Override
            protected it.r2u.anibus.service.analysis.SqlMetadataExtractor.MetadataResult call() {
                // Build a minimal stub InjectionResult from current host as endpoint
                var vuln = new it.r2u.anibus.service.analysis.SQLInjectionAnalyzer.InjectionResult(
                    "' OR 1=1-- -", targetUrl, "GET", 200, 0, null, List.of("manual"), "");
                return new it.r2u.anibus.service.analysis.SqlMetadataExtractor().extract(vuln);
            }
        };
        task.setOnSucceeded(ev -> {
            var r = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + it.r2u.anibus.service.analysis.SqlMetadataExtractor.formatReport(r) + "\n");
            setStatus("SQL Metadata Extraction complete — " + r.tables().size() + " table(s) found");
        });
        task.setOnFailed(ev -> setStatus("SQL Extraction error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "sql-meta-extraction");
        t.setDaemon(true);
        t.start();
    }

    private void runShowScanHistory() {        if (scanHistoryService == null) return;
        setStatus("Loading scan history…");
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
            setStatus("Scan history: " + entries.size() + " entry(ies)");
        });
        task.setOnFailed(ev -> setStatus("History error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "scan-history-list");
        t.setDaemon(true);
        t.start();
    }

    private void applyConsoleFilter(String filter) {
        isFilteringConsole = true;
        try {
            if (filter == null || filter.isBlank()) {
                consoleTextArea.setText(unfilteredConsoleText);
            } else {
                String lower = filter.toLowerCase(java.util.Locale.ROOT);
                String filtered = unfilteredConsoleText.lines()
                    .filter(line -> line.toLowerCase(java.util.Locale.ROOT).contains(lower))
                    .collect(java.util.stream.Collectors.joining("\n"));
                consoleTextArea.setText(filtered.isEmpty()
                    ? "(No matches for: " + filter + ")"
                    : filtered);
            }
        } finally {
            isFilteringConsole = false;
        }
    }

    private void runAsnLookup() {
        String input = hostTextField.getText().trim();
        if (input.isBlank()) { setStatus("Enter a target IP or host first"); return; }
        String host = extractHostOrDomain(input);
        if (host.isBlank()) { setStatus("Cannot resolve host from input"); return; }
        setStatus("ASN lookup for " + host + "…");
        Task<AsnLookupService.AsnInfo> task = new Task<>() {
            @Override
            protected AsnLookupService.AsnInfo call() {
                String ip = host;
                try { ip = java.net.InetAddress.getByName(host).getHostAddress(); } catch (java.net.UnknownHostException | SecurityException ignored) {}
                return asnLookupService.lookup(ip);
            }
        };
        task.setOnSucceeded(ev -> {
            AsnLookupService.AsnInfo info = task.getValue();
            consoleViewManager.appendRawText("\n" + AsnLookupService.formatReport(info) + "\n");
            String asn = info.asn() != null ? "AS" + info.asn() : "unknown";
            setStatus("ASN lookup done: " + asn + (info.asnName() != null ? " — " + info.asnName() : ""));
        });
        task.setOnFailed(ev -> setStatus("ASN lookup error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "asn-lookup");
        t.setDaemon(true);
        t.start();
    }

    private void runHeartbleedCheck() {
        String input = hostTextField.getText().trim();
        if (input.isBlank()) { setStatus("Enter a target first"); return; }
        String host = extractHostOrDomain(input);
        if (host.isBlank()) { setStatus("Cannot resolve host from input"); return; }
        int port = results.stream()
            .filter(r -> r.getPort() == 443 || r.getPort() == 8443)
            .mapToInt(PortScanResult::getPort)
            .findFirst()
            .orElse(443);
        setStatus("Heartbleed check on " + host + ":" + port + "…");
        Task<HeartbleedChecker.HeartbleedResult> task = new Task<>() {
            @Override
            protected HeartbleedChecker.HeartbleedResult call() {
                return heartbleedChecker.check(host, port);
            }
        };
        task.setOnSucceeded(ev -> {
            HeartbleedChecker.HeartbleedResult r = task.getValue();
            consoleViewManager.appendRawText("\n" + HeartbleedChecker.formatReport(r) + "\n");
            setStatus(r.vulnerable()
                ? "⚠ VULNERABLE to Heartbleed! CVE-2014-0160"
                : "Heartbleed check done — not vulnerable");
        });
        task.setOnFailed(ev -> setStatus("Heartbleed check error: " + task.getException().getMessage()));
        Thread t = new Thread(task, "heartbleed-check");
        t.setDaemon(true);
        t.start();
    }

    private void runApiSecurityMode() {
        String target = ensureHttpUrl(hostTextField.getText());
        if (target.isBlank()) {
            setStatus("Enter a target URL first");
            return;
        }
        setStatus("API Security Mode running against " + target + "...");
        Task<ApiSecurityModeService.ScanResult> task = new Task<>() {
            @Override
            protected ApiSecurityModeService.ScanResult call() {
                return apiSecurityModeService.scan(target);
            }
        };
        task.setOnSucceeded(ev -> {
            ApiSecurityModeService.ScanResult result = task.getValue();
            consoleViewManager.appendRawText(
                "\n" + ApiSecurityModeService.formatReport(result) + "\n");
            setStatus("API Security Mode complete: " + result.probes().size() + " endpoint probe(s)");
        });
        task.setOnFailed(ev -> {
            Throwable ex = task.getException();
            setStatus("API Security Mode error: " + (ex != null ? ex.getMessage() : "unknown error"));
        });
        Thread t = new Thread(task, "api-security-mode");
        t.setDaemon(true);
        t.start();
    }
}
