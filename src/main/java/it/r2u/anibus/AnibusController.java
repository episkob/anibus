package it.r2u.anibus;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import it.r2u.anibus.coordinator.ScanCoordinator;
import it.r2u.anibus.coordinator.ServiceDetectionStrategy;
import it.r2u.anibus.coordinator.StandardScanStrategy;
import it.r2u.anibus.handlers.ClipboardActionHandler;
import it.r2u.anibus.handlers.ExportActionHandler;
import it.r2u.anibus.handlers.ExtraScanHandler;
import it.r2u.anibus.handlers.JsAnalysisHandler;
import it.r2u.anibus.handlers.ProxyTabHandler;
import it.r2u.anibus.handlers.ScanActionHandler;
import it.r2u.anibus.handlers.SecurityAnalysisHandler;
import it.r2u.anibus.handlers.StatisticsHandler;
import it.r2u.anibus.handlers.TopologyHandler;
import it.r2u.anibus.handlers.TracerouteActionHandler;
import it.r2u.anibus.model.EndpointInfo;
import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.network.NetworkStatusMonitor;
import it.r2u.anibus.service.analysis.ApiSecurityModeService;
import it.r2u.anibus.service.analysis.AuthCrawler;
import it.r2u.anibus.service.analysis.CorsChecker;
import it.r2u.anibus.service.analysis.DirectoryBruteforcer;
import it.r2u.anibus.service.analysis.GraphqlScanner;
import it.r2u.anibus.service.analysis.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.service.analysis.JwtAnalyzer;
import it.r2u.anibus.service.analysis.ParamMinerService;
import it.r2u.anibus.service.analysis.PassiveReconService;
import it.r2u.anibus.service.analysis.SQLInjectionAnalyzer;
import it.r2u.anibus.service.analysis.SecretsValidationService;
import it.r2u.anibus.service.analysis.ServiceMisconfigurationChecker;
import it.r2u.anibus.service.analysis.SourceMapAnalyzer;
import it.r2u.anibus.service.analysis.SsrfDetector;
import it.r2u.anibus.service.analysis.SubdomainTakeoverChecker;
import it.r2u.anibus.service.analysis.WebSocketDetector;
import it.r2u.anibus.service.analysis.XssDetector;
import it.r2u.anibus.service.analysis.XxeDetector;
import it.r2u.anibus.service.core.PortScannerService;
import it.r2u.anibus.service.core.ScanHistoryService;
import it.r2u.anibus.service.core.ScanSchedulerService;
import it.r2u.anibus.service.core.UdpScannerService;
import it.r2u.anibus.service.detection.EnhancedServiceDetector;
import it.r2u.anibus.service.export.ScanDiffService;
import it.r2u.anibus.service.network.AsnLookupService;
import it.r2u.anibus.service.network.DnsZoneTransferService;
import it.r2u.anibus.service.network.HttpProtocolDetector;
import it.r2u.anibus.service.network.SslTlsAuditor;
import it.r2u.anibus.service.network.SubdomainEnumerationService;
import it.r2u.anibus.service.network.TracerouteService;
import it.r2u.anibus.service.network.WhoisService;
import it.r2u.anibus.ui.AlertHelper;
import it.r2u.anibus.ui.ConsoleViewManager;
import it.r2u.anibus.ui.InfoCardManager;
import it.r2u.anibus.ui.LanguageManager;
import it.r2u.anibus.ui.NotificationService;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.PieChart;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ContextMenu;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuButton;
import javafx.scene.control.MenuItem;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.RadioMenuItem;
import javafx.scene.control.SeparatorMenuItem;
import javafx.scene.control.Spinner;
import javafx.scene.control.SpinnerValueFactory;
import javafx.scene.control.Tab;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Tooltip;
import javafx.scene.control.TreeView;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.layout.Pane;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;
import javafx.stage.FileChooser;

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

    private static final Logger LOG = Logger.getLogger(AnibusController.class.getName());

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
        WebSocketDetector webSocketDetector,
        HttpProtocolDetector httpProtocolDetector,
        AsnLookupService asnLookupService
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
    @FXML private VBox              jsResultsCard;
    @FXML private Label             jsEndpointsLabel;
    @FXML private Label             jsDataStructuresLabel;
    @FXML private Label             jsDbSchemasLabel;
    @FXML private Label             jsSensitiveInfoLabel;
    @FXML private Label             jsArchitectureLabel;
    @FXML private Button            jsExportButton;
    @FXML private Button            jsAnalysisRunButton;
    @FXML private TreeView<String>  jsStructureTree;
    @FXML private TextArea          jsAnalysisTextArea;
    @FXML private Button            sqlInjectionRunButton;
    @FXML private TextArea          sqlInjectionTextArea;
    
    /* -- Unified Console FXML fields ------------------------- */
    @FXML private Label             consoleHeaderLabel;
    @FXML private TextField         consoleFilterField;

    /* -- i18n: configuration menu + translatable labels ------ */
    @FXML private MenuButton configMenuButton;
    @FXML private MenuButton actionsMenuButton;
    @FXML private Button aboutButton;
    @FXML private Label  sectionScanTargetLabel;
    @FXML private Label  labelTargetKey;
    @FXML private Label  labelPortRangeKey;
    @FXML private Label  labelThreadsKey;
    @FXML private Label  sectionHostInfoLabel;
    @FXML private Label  keyIpAddressLabel;
    @FXML private Label  keyHostnameLabel;
    @FXML private Label  keyScanTimeLabel;
    @FXML private Label  keyPortsScannedLabel;
    @FXML private Label  keyOpenPortsLabel;
    @FXML private Label  keyAvgLatencyLabel;
    @FXML private Label  wordlistStatusTitleLabel;
    @FXML private Label  wordlistSubdomainStatusLabel;
    @FXML private Label  wordlistSqlStatusLabel;
    @FXML private Label  wordlistEndpointStatusLabel;
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
    @FXML private CheckBox proxyTransportAutoCheckBox;
    @FXML private CheckBox proxyTransportTorCheckBox;
    @FXML private CheckBox proxyTransportOtherOnionCheckBox;
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
    private boolean scanningInProgress = false;
    private boolean sqlInjectionInProgress = false;
    private Task<Map<String, List<SQLInjectionAnalyzer.InjectionResult>>> sqlInjectionTask;
    
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
    private WebSocketDetector webSocketDetector;
    private HttpProtocolDetector httpProtocolDetector;
    private AsnLookupService asnLookupService;

    /* -- Console filter state --------------------------------- */
    private String  unfilteredConsoleText = "";
    private boolean isFilteringConsole    = false;
    private volatile List<String> endpointWordlistEntries = List.of();
    private volatile String subdomainWordlistStatus = "default";
    private volatile String sqliWordlistStatus = "default";
    private volatile String endpointWordlistStatus = "none";
    private volatile String lastStatusMessage = "";

    /* -- Notifications ---------------------------------------- */
    private NotificationService notificationService;
    
    /* -- Coordinators and Handlers (SOLID refactoring) -------- */
    private ScanCoordinator        scanCoordinator;
    private ScanActionHandler      scanActionHandler;
    private ClipboardActionHandler clipboardHandler;
    private ExportActionHandler    exportHandler;
    private TracerouteActionHandler tracerouteHandler;
    private SecurityAnalysisHandler securityAnalysisHandler;
    private StatisticsHandler       statisticsHandler;
    private TopologyHandler         topologyHandler;
    private JsAnalysisHandler       jsAnalysisHandler;
    private ExtraScanHandler        extraScanHandler;
    private ProxyTabHandler         proxyTabHandler;

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
        webSocketDetector = coreServices != null && coreServices.webSocketDetector() != null
            ? coreServices.webSocketDetector() : new WebSocketDetector();
        httpProtocolDetector = coreServices != null && coreServices.httpProtocolDetector() != null
            ? coreServices.httpProtocolDetector() : new HttpProtocolDetector();
        asnLookupService = coreServices != null && coreServices.asnLookupService() != null
            ? coreServices.asnLookupService() : new AsnLookupService();
        
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

        securityAnalysisHandler = SecurityAnalysisHandler.builder()
            .targetUrlSupplier(() -> SecurityAnalysisHandler.ensureHttpUrl(hostTextField.getText()))
            .targetHostSupplier(() -> SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText()))
            .consoleTextSupplier(() -> consoleTextArea.getText())
            .firstScanPortSupplier(() -> results.isEmpty() ? 0 : results.get(0).getPort())
            .console(consoleViewManager)
            .progressBar(progressBar)
            .setStatus(this::setStatus)
            .xssDetector(xssDetector)
            .corsChecker(corsChecker)
            .jwtAnalyzer(jwtAnalyzer)
            .ssrfDetector(ssrfDetector)
            .dirBruteforcer(dirBruteforcer)
            .whoisService(whoisService)
            .sslTlsAuditor(sslTlsAuditor)
            .graphqlScanner(graphqlScanner)
            .xxeDetector(xxeDetector)
            .takeoverChecker(takeoverChecker)
            .dnsAxfrService(dnsAxfrService)
            .webSocketDetector(webSocketDetector)
            .httpProtocolDetector(httpProtocolDetector)
            .asnLookupService(asnLookupService)
            .apiSecurityModeService(apiSecurityModeService)
            .passiveReconService(passiveReconService)
            .secretsValidationService(secretsValidationService)
            .leaksSupplier(() -> jsAnalysisHandler != null ? jsAnalysisHandler.getLastJsAnalysisResult() != null ? jsAnalysisHandler.getLastJsAnalysisResult().getSensitiveInfo() : null : null)
            .build();

        statisticsHandler = new StatisticsHandler(
            statsPortStateChart, statsServiceChart, statsRiskChart, results);

        topologyHandler = new TopologyHandler(topologyGraphPane, tabTopology);

        jsAnalysisHandler = new JsAnalysisHandler(
            new JsAnalysisHandler.UIComponents(
                hostTextField, progressBar, scanButton, stopButton,
                exportButton, jsExportButton, clearButton,
                jsAnalysisRunButton, jsResultsCard,
                jsEndpointsLabel, jsDataStructuresLabel, jsDbSchemasLabel,
                jsSensitiveInfoLabel, jsArchitectureLabel,
                jsStructureTree, jsAnalysisTextArea, consoleTextArea,
                consoleHeaderLabel, resultCountLabel),
            jsAnalyzer, exportHandler,
            results, this::setStatus,
            this::resetScanUI);

        extraScanHandler = new ExtraScanHandler(
            hostTextField, portsTextField, progressBar, consoleTextArea,
            consoleViewManager, results, this::setStatus,
            () -> jsAnalysisHandler.getLastJsAnalysisResult(),
            udpScannerService, subdomainEnumerationService, sourceMapAnalyzer,
            paramMinerService, scanDiffService, scanSchedulerService,
            scanHistoryService, scanner);

        proxyTabHandler = new ProxyTabHandler(
            proxyLogArea, activeProxyLabel, proxyStatusDot,
            startProxyButton, clearProxyButton, loadProxyButton, rotateProxyButton,
            proxyStatCandidates, proxyStatLive, proxyStatCountries, proxyPhaseLabel,
            proxyProgressBar, chainDisplayArea, chainDisplayCard,
            proxyAvailableListView, proxyChainListView,
                hostTextField, resolvedHostLabel, hostResolver,
                proxyTransportAutoCheckBox, proxyTransportTorCheckBox,
                proxyTransportOtherOnionCheckBox);
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
        proxyTabHandler.setup();

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
        setupActionsMenu();

        // Show saved-pool hint on startup
        it.r2u.anibus.service.network.proxy.ProxyStore ps =
                new it.r2u.anibus.service.network.proxy.ProxyStore();
        if (ps.exists()) {
            loadProxyButton.setText(LanguageManager.getInstance().get("btn.loadFromFile") + " ✓");
            loadProxyButton.setTooltip(new Tooltip(
                    "Cached pool found: " + ps.getStorePath()));
        }

        refreshWordlistStatusLabels();
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
    private void setupActionsMenu() {
        if (actionsMenuButton == null) {
            return;
        }

        actionsMenuButton.getItems().setAll(
            buildDiscoveryMenu(),
            buildSecurityMenu(),
            buildNetworkMenu(),
            buildWordlistsMenu(),
            new SeparatorMenuItem(),
            createMenuItem("Diff Current Results with XML", this::runDiffMode),
            createMenuItem("Start Scheduled Scan (custom)", this::startScheduledScan),
            createMenuItem("Stop Scheduled Scan", this::stopScheduledScan),
            createMenuItem("Show Scan History", this::runShowScanHistory)
        );
    }

    private Menu buildDiscoveryMenu() {
        Menu menu = createMenu("Discovery");
        menu.getItems().addAll(
            createMenuItem("Run Traceroute", () -> tracerouteHandler.runTraceroute(
                hostTextField.getText(), consoleTextArea, this::renderTopologyGraph)),
            createMenuItem("UDP Scan (common ports)", this::runUdpScan),
            createMenuItem("Enumerate Subdomains", this::runSubdomainEnumeration),
            createMenuItem("Analyze Source Maps", this::runSourceMapAnalysis),
            createMenuItem("Run Param Miner", this::runParamMiner),
            createMenuItem("Passive Recon Mode", this::runPassiveRecon),
            createMenuItem("Validate Secrets and JS Leaks", this::runSecretsValidation),
            createMenuItem("Authenticated Crawl (Basic/Bearer/Digest/Form/OAuth2/NTLM)", this::runAuthCrawl)
        );
        return menu;
    }

    private Menu buildSecurityMenu() {
        Menu menu = createMenu("Security");
        menu.getItems().addAll(
            createMenuItem("API Security Mode (OpenAPI/Swagger)", this::runApiSecurityMode),
            createMenuItem("XSS Scan (reflected)", this::runXssScan),
            createMenuItem("XSS on JS Endpoints", this::runXssScanOnJsEndpoints),
            createMenuItem("CORS Misconfiguration Check", this::runCorsCheck),
            createMenuItem("JWT Analyzer (from JS)", this::runJwtAnalysis),
            createMenuItem("SSRF Detector", this::runSsrfScan),
            createMenuItem("Directory Bruteforce", this::runDirectoryBruteforce),
            createMenuItem("GraphQL Introspection", this::runGraphqlScan),
            createMenuItem("XXE Detector", this::runXxeScan),
            createMenuItem("Subdomain Takeover Check", this::runTakeoverCheck),
            createMenuItem("SQL Metadata Extraction", this::runSqlMetadataExtraction)
        );
        return menu;
    }

    private Menu buildWordlistsMenu() {
        Menu menu = createMenu("Wordlists");
        menu.getItems().addAll(
            createMenuItem("Load Subdomain Wordlist", this::loadSubdomainWordlist),
            createMenuItem("Load SQLi Payload Wordlist", this::loadSqlPayloadWordlist),
            createMenuItem("Load Endpoint Wordlist", this::loadEndpointWordlist),
            createMenuItem("Reset All Wordlists", this::resetWordlists)
        );
        return menu;
    }

    private Menu buildNetworkMenu() {
        Menu menu = createMenu("Network");
        menu.getItems().addAll(
            createMenuItem("WHOIS Lookup", this::runWhoisLookup),
            createMenuItem("SSL/TLS Audit", this::runSslAudit),
            createMenuItem("DNS Zone Transfer (AXFR)", this::runDnsAxfr),
            createMenuItem("WebSocket Detector", this::runWebSocketDetect),
            createMenuItem("HTTP/2 and HTTP/3 Support", this::runHttpProtocolDetect),
            createMenuItem("ASN Lookup", this::runAsnLookup),
            createMenuItem("Service Misconfiguration Check (Redis/Mongo/ES/Docker/...)", this::runServiceMisconfigCheck)
        );
        return menu;
    }

    private Menu createMenu(String text) {
        Menu menu = new Menu(text);
        menu.getStyleClass().add("actions-submenu");
        return menu;
    }

    private MenuItem createMenuItem(String text, Runnable action) {
        MenuItem item = new MenuItem(text);
        item.getStyleClass().add("actions-menu-item");
        item.setOnAction(e -> action.run());
        return item;
    }

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

        consoleTextArea.setContextMenu(new ContextMenu(
            copySelected, copyAll, saveSelected, copyResults));
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

    private void renderTopologyGraph(TracerouteService.TraceRoute trace) {
        topologyHandler.renderTopologyGraph(trace);
    }

    private void updateStatisticsDashboard() {
        statisticsHandler.updateStatisticsDashboard();
    }

    private void runUdpScan() { extraScanHandler.runUdpScan(); }

    private void runSubdomainEnumeration() { extraScanHandler.runSubdomainEnumeration(); }

    private void runAuthCrawl() {
        javafx.scene.control.Dialog<java.util.Map<String, String>> dialog = new javafx.scene.control.Dialog<>();
        dialog.setTitle("Authenticated Crawl");
        dialog.setHeaderText("Configure authentication and target paths");
        javafx.scene.control.ButtonType runBtn = new javafx.scene.control.ButtonType("Run", javafx.scene.control.ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(runBtn, javafx.scene.control.ButtonType.CANCEL);

        javafx.scene.layout.GridPane grid = new javafx.scene.layout.GridPane();
        grid.setHgap(8);
        grid.setVgap(6);
        grid.setPadding(new javafx.geometry.Insets(10));

        javafx.scene.control.ComboBox<AuthCrawler.Mode> modeBox = new javafx.scene.control.ComboBox<>();
        modeBox.getItems().setAll(AuthCrawler.Mode.values());
        modeBox.getSelectionModel().select(AuthCrawler.Mode.BASIC);

        TextField baseUrlField = new TextField();
        baseUrlField.setPromptText("https://target.example.com");
        String currentHost = hostTextField != null ? hostTextField.getText() : "";
        if (currentHost != null && !currentHost.isBlank()) {
            baseUrlField.setText(currentHost.startsWith("http") ? currentHost : "http://" + currentHost);
        }

        TextField userField = new TextField();
        userField.setPromptText("username / client_id");
        javafx.scene.control.PasswordField passField = new javafx.scene.control.PasswordField();
        passField.setPromptText("password / client_secret / bearer token");
        TextField extraField = new TextField();
        extraField.setPromptText("OAuth2 token URL  |  Form login URL  |  scope");
        javafx.scene.control.TextArea pathsArea = new javafx.scene.control.TextArea();
        pathsArea.setPromptText("Comma- or newline-separated paths to probe, e.g. /admin, /dashboard, /api/me");
        pathsArea.setPrefRowCount(4);
        javafx.scene.control.TextArea formFieldsArea = new javafx.scene.control.TextArea();
        formFieldsArea.setPromptText("Form fields (key=value per line, FORM mode only): username=admin\\npassword=secret");
        formFieldsArea.setPrefRowCount(3);

        grid.add(new Label("Mode:"), 0, 0);            grid.add(modeBox, 1, 0);
        grid.add(new Label("Base URL:"), 0, 1);        grid.add(baseUrlField, 1, 1);
        grid.add(new Label("User / id:"), 0, 2);       grid.add(userField, 1, 2);
        grid.add(new Label("Password / secret:"), 0, 3); grid.add(passField, 1, 3);
        grid.add(new Label("Token URL / Login URL / scope:"), 0, 4); grid.add(extraField, 1, 4);
        grid.add(new Label("Paths:"), 0, 5);           grid.add(pathsArea, 1, 5);
        grid.add(new Label("Form fields:"), 0, 6);     grid.add(formFieldsArea, 1, 6);

        dialog.getDialogPane().setContent(grid);
        dialog.setResultConverter(bt -> {
            if (bt != runBtn) return null;
            java.util.Map<String, String> m = new java.util.LinkedHashMap<>();
            m.put("mode", modeBox.getValue() == null ? "BASIC" : modeBox.getValue().name());
            m.put("baseUrl", baseUrlField.getText());
            m.put("user", userField.getText());
            m.put("pass", passField.getText());
            m.put("extra", extraField.getText());
            m.put("paths", pathsArea.getText());
            m.put("form", formFieldsArea.getText());
            return m;
        });

        dialog.showAndWait().ifPresent(spec -> launchAuthCrawl(spec));
    }

    private void launchAuthCrawl(java.util.Map<String, String> spec) {
        String baseUrl = spec.getOrDefault("baseUrl", "").trim();
        if (baseUrl.isBlank()) {
            setStatus("Auth crawl: base URL is required");
            return;
        }
        AuthCrawler.Mode mode;
        try {
            mode = AuthCrawler.Mode.valueOf(spec.getOrDefault("mode", "BASIC"));
        } catch (IllegalArgumentException e) {
            mode = AuthCrawler.Mode.BASIC;
        }
        final AuthCrawler.Mode chosenMode = mode;
        java.util.List<String> paths = java.util.Arrays.stream(
                spec.getOrDefault("paths", "").split("[,\\r\\n]+"))
            .map(String::trim).filter(s -> !s.isBlank()).toList();
        java.util.Map<String, String> formFields = new java.util.LinkedHashMap<>();
        for (String line : spec.getOrDefault("form", "").split("\\r?\\n")) {
            int eq = line.indexOf('=');
            if (eq > 0) formFields.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
        }
        String user = spec.getOrDefault("user", "");
        String pass = spec.getOrDefault("pass", "");
        String extra = spec.getOrDefault("extra", "");

        Task<AuthCrawler.AuthCrawlReport> task = new Task<>() {
            @Override
            protected AuthCrawler.AuthCrawlReport call() {
                AuthCrawler ac = new AuthCrawler();
                return switch (chosenMode) {
                    case BASIC -> ac.crawlWithBasic(baseUrl, user, pass, paths);
                    case BEARER -> ac.crawlWithBearer(baseUrl, pass, paths);
                    case OAUTH2_CLIENT_CREDENTIALS ->
                        ac.crawlWithOAuth2ClientCredentials(baseUrl, extra, user, pass, /* scope */ null, paths);
                    case DIGEST -> ac.crawlWithDigest(baseUrl, user, pass, paths);
                    case FORM -> {
                        if (!user.isBlank()) formFields.putIfAbsent("username", user);
                        if (!pass.isBlank()) formFields.putIfAbsent("password", pass);
                        yield ac.crawlWithFormLogin(baseUrl, extra.isBlank() ? baseUrl : extra, formFields, paths);
                    }
                    case NTLM -> {
                        // 'user' may be in DOMAIN\\user or user@domain form — split it.
                        String dom = "";
                        String u = user;
                        int slash = user.indexOf('\\');
                        if (slash > 0) { dom = user.substring(0, slash); u = user.substring(slash + 1); }
                        int at = u.indexOf('@');
                        if (at > 0) { dom = u.substring(at + 1); u = u.substring(0, at); }
                        yield ac.crawlWithNtlm(baseUrl, u, pass, /* workstation */ extra, dom, paths);
                    }
                };
            }
        };

        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        setStatus("Authenticated crawl (" + chosenMode + ") starting...");

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            AuthCrawler.AuthCrawlReport report = task.getValue();
            consoleTextArea.appendText("\n" + AuthCrawler.formatReport(report) + "\n");
            setStatus("Auth crawl done: " + (report.authSucceeded() ? "auth OK" : "auth failed")
                + ", " + report.probes().size() + " probe(s)");
        });
        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("Auth crawl failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });
        Thread t = new Thread(task, "anibus-auth-crawl");
        t.setDaemon(true);
        t.start();
    }

    private void runSourceMapAnalysis() { extraScanHandler.runSourceMapAnalysis(); }

    private void runServiceMisconfigCheck() {
        String host = it.r2u.anibus.handlers.SecurityAnalysisHandler.extractHostOrDomain(
            hostTextField != null ? hostTextField.getText() : "");
        if (host == null || host.isBlank()) {
            setStatus("Service misconfig check: enter a target host");
            return;
        }
        Task<List<ServiceMisconfigurationChecker.MisconfigFinding>> task = new Task<>() {
            @Override
            protected List<ServiceMisconfigurationChecker.MisconfigFinding> call() {
                return new ServiceMisconfigurationChecker().scan(host);
            }
        };
        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        setStatus("Service misconfig probe running against " + host + "...");
        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            List<ServiceMisconfigurationChecker.MisconfigFinding> findings = task.getValue();
            consoleTextArea.appendText("\n"
                + ServiceMisconfigurationChecker.formatReport(host, findings) + "\n");
            setStatus("Service misconfig check finished: " + findings.size() + " finding(s)");
        });
        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            setStatus("Service misconfig probe failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });
        Thread t = new Thread(task, "anibus-svc-misconfig");
        t.setDaemon(true);
        t.start();
    }

    private void runParamMiner() { extraScanHandler.runParamMiner(); }

    private void runPassiveRecon() { securityAnalysisHandler.runPassiveRecon(); }

    private void runSecretsValidation() { securityAnalysisHandler.runSecretsValidation(); }

    private void runDiffMode() { extraScanHandler.runDiffMode(); }

    private void startScheduledScan() { extraScanHandler.startScheduledScan(); }

    private void stopScheduledScan() { extraScanHandler.stopScheduledScan(); }

    private void runXssScan() { securityAnalysisHandler.runXssScan(); }

    private void runCorsCheck() { securityAnalysisHandler.runCorsCheck(); }

    private void runJwtAnalysis() { securityAnalysisHandler.runJwtAnalysis(); }

    private void runSsrfScan() { securityAnalysisHandler.runSsrfScan(); }

    private void runDirectoryBruteforce() { securityAnalysisHandler.runDirectoryBruteforce(); }

    private void runWhoisLookup() { securityAnalysisHandler.runWhoisLookup(); }

    private void runSslAudit() { securityAnalysisHandler.runSslAudit(); }

    private void runGraphqlScan() { securityAnalysisHandler.runGraphqlScan(); }

    private void runXxeScan() { securityAnalysisHandler.runXxeScan(); }

    private void runTakeoverCheck() { securityAnalysisHandler.runTakeoverCheck(); }

    private void runDnsAxfr() { securityAnalysisHandler.runDnsAxfr(); }

    private void runWebSocketDetect() { securityAnalysisHandler.runWebSocketDetect(80); }

    private void runHttpProtocolDetect() { securityAnalysisHandler.runHttpProtocolDetect(80); }

    private void runSqlInjectionScan() {
        String targetUrl = hostTextField.getText().trim();

        if (targetUrl.isEmpty()) {
            setStatus("Please enter a target URL");
            return;
        }

        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
            hostTextField.setText(targetUrl);
        }

        final String finalTargetUrl = targetUrl;
        final List<EndpointInfo> endpointCandidates = collectEndpointCandidates(finalTargetUrl);

        sqlInjectionInProgress = true;
        injectionAnalyzer.resetStopRequest();
        setStatus("Starting SQL injection scan (" + endpointCandidates.size() + " JS/wordlist endpoint candidates)...");
        sqlInjectionTask = new Task<>() {
            @Override
            protected Map<String, List<SQLInjectionAnalyzer.InjectionResult>> call() {
                return injectionAnalyzer.fullScan(
                        endpointCandidates,
                        finalTargetUrl,
                        msg -> Platform.runLater(() -> {
                            setStatus(msg);
                            if (sqlInjectionTextArea != null) {
                                sqlInjectionTextArea.appendText("\n" + msg);
                                sqlInjectionTextArea.setScrollTop(Double.MAX_VALUE);
                            }
                        }));
            }
        };

        sqlInjectionTask.setOnSucceeded(ev -> {
            Map<String, List<SQLInjectionAnalyzer.InjectionResult>> injectionResults = sqlInjectionTask.getValue();
            sqlInjectionTextArea.setText(injectionAnalyzer.formatResults(injectionResults));
            sqlInjectionTextArea.setScrollTop(0);
            sqlInjectionInProgress = false;
            resetScanUI();
            if (injectionAnalyzer.isStopRequested()) {
                setStatus("SQL injection scan stopped (partial results shown)");
            } else {
                setStatus("SQL injection scan completed");
            }
        });
        sqlInjectionTask.setOnFailed(ev -> {
            Throwable error = sqlInjectionTask.getException();
            sqlInjectionTextArea.setText("SQL injection scan failed: " + (error != null ? error.getMessage() : "unknown error"));
            sqlInjectionInProgress = false;
            resetScanUI();
            setStatus("SQL injection scan failed");
        });

        scanButton.setDisable(true);
        if (sqlInjectionRunButton != null) sqlInjectionRunButton.setDisable(true);
        stopButton.setDisable(false);
        progressBar.setVisible(true);
        sqlInjectionTextArea.setText("""
            Running SQL injection scan...
            Using endpoint candidates from JS analysis and endpoint wordlist: %d
            """.formatted(endpointCandidates.size()).stripTrailing());

        Thread thread = new Thread(sqlInjectionTask, "sql-injection-scan");
        thread.setDaemon(true);
        thread.start();
    }

    private void runXssScanOnJsEndpoints() {
        String targetUrl = SecurityAnalysisHandler.ensureHttpUrl(hostTextField.getText());
        if (targetUrl.isBlank()) {
            setStatus("Enter a target URL for XSS endpoint scan");
            return;
        }

        List<EndpointInfo> endpoints = collectEndpointCandidates(targetUrl);
        if (endpoints.isEmpty()) {
            setStatus("No JS or wordlist endpoints available. Run JS analysis or load endpoint wordlist first.");
            return;
        }

        Task<List<XssDetector.XssResult>> task = new Task<>() {
            @Override
            protected List<XssDetector.XssResult> call() {
                List<XssDetector.XssResult> findings = new ArrayList<>();
                int total = endpoints.size();
                int idx = 0;
                for (EndpointInfo ep : endpoints) {
                    String endpointUrl = resolveEndpointUrlForScan(ep, targetUrl);
                    List<String> params = (ep.getParameters() == null || ep.getParameters().isEmpty())
                            ? List.of("q", "id", "search")
                            : ep.getParameters();
                    findings.addAll(xssDetector.scan(endpointUrl, params, p -> {
                        // progress is reported per-endpoint below
                    }));
                    idx++;
                    final int done = idx;
                    Platform.runLater(() -> setStatus("XSS on JS endpoints: " + done + "/" + total + " tested"));
                }
                return findings;
            }
        };

        progressBar.setVisible(true);
        scanButton.setDisable(true);
        stopButton.setDisable(false);
        setStatus("Starting XSS scan on JS endpoints...");

        task.setOnSucceeded(ev -> {
            List<XssDetector.XssResult> findings = task.getValue();
            consoleViewManager.appendRawText("\n=== XSS ON JS ENDPOINTS ===\n");
            consoleViewManager.appendRawText(XssDetector.formatReport(findings, targetUrl) + "\n");
            long reflected = findings.stream().filter(XssDetector.XssResult::reflected).count();
            setStatus("XSS endpoint scan completed: " + reflected + " reflected finding(s)");
            resetScanUI();
        });

        task.setOnFailed(ev -> {
            Throwable error = task.getException();
            setStatus("XSS endpoint scan failed: " + (error != null ? error.getMessage() : "unknown error"));
            resetScanUI();
        });

        Thread thread = new Thread(task, "xss-endpoints-scan");
        thread.setDaemon(true);
        thread.start();
    }

    private List<EndpointInfo> collectEndpointCandidates(String baseUrl) {
        LinkedHashMap<String, EndpointInfo> merged = new LinkedHashMap<>();

        JavaScriptAnalysisResult js = jsAnalysisHandler != null ? jsAnalysisHandler.getLastJsAnalysisResult() : null;
        if (js != null && js.getEndpoints() != null) {
            for (EndpointInfo endpoint : js.getEndpoints()) {
                if (endpoint == null) continue;
                String key = (endpoint.getHttpMethod() == null ? "GET" : endpoint.getHttpMethod()) + "|" + endpoint.getUrl();
                merged.putIfAbsent(key, endpoint);
            }
        }

        for (String entry : endpointWordlistEntries) {
            String normalizedPath = normalizeEndpointPath(entry);
            String fullUrl = baseUrl.endsWith("/")
                    ? baseUrl.substring(0, baseUrl.length() - 1) + normalizedPath
                    : baseUrl + normalizedPath;
            EndpointInfo generated = new EndpointInfo(
                    fullUrl,
                    baseUrl,
                    normalizedPath,
                    "GET",
                    List.of("id", "q"),
                    Map.of(),
                    "endpoint-wordlist",
                    false
            );
            merged.putIfAbsent("GET|" + fullUrl, generated);
        }

        return List.copyOf(merged.values());
    }

    private String resolveEndpointUrlForScan(EndpointInfo endpoint, String baseUrl) {
        if (endpoint == null) return baseUrl;
        if (endpoint.getUrl() != null && endpoint.getUrl().startsWith("http")) {
            return endpoint.getUrl();
        }
        String path = endpoint.getPath() != null ? endpoint.getPath() : endpoint.getUrl();
        if (path == null || path.isBlank()) return baseUrl;
        String normalizedPath = normalizeEndpointPath(path);
        return baseUrl.endsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1) + normalizedPath
                : baseUrl + normalizedPath;
    }

    private String normalizeEndpointPath(String value) {
        String trimmed = value == null ? "" : value.trim();
        if (trimmed.isEmpty()) return "/";
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return trimmed;
        }
        return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
    }

    private void loadSubdomainWordlist() {
        List<String> words = chooseWordlist("Choose subdomain wordlist");
        if (words == null) return;
        subdomainEnumerationService.setCustomWordlist(words);
        subdomainWordlistStatus = "custom (" + words.size() + ")";
        refreshWordlistStatusLabels();
        setStatus("Loaded subdomain wordlist: " + words.size() + " entries");
    }

    private void loadSqlPayloadWordlist() {
        List<String> words = chooseWordlist("Choose SQLi payload wordlist");
        if (words == null) return;
        injectionAnalyzer.setCustomPayloads(words);
        sqliWordlistStatus = "custom (" + words.size() + ")";
        refreshWordlistStatusLabels();
        setStatus("Loaded SQLi payload wordlist: " + words.size() + " payloads");
    }

    private void loadEndpointWordlist() {
        List<String> words = chooseWordlist("Choose endpoint wordlist");
        if (words == null) return;
        endpointWordlistEntries = words;
        endpointWordlistStatus = "custom (" + words.size() + ")";
        refreshWordlistStatusLabels();
        setStatus("Loaded endpoint wordlist: " + words.size() + " entries");
    }

    private void resetWordlists() {
        subdomainEnumerationService.setCustomWordlist(List.of());
        injectionAnalyzer.setCustomPayloads(List.of());
        endpointWordlistEntries = List.of();
        subdomainWordlistStatus = "default";
        sqliWordlistStatus = "default";
        endpointWordlistStatus = "none";
        refreshWordlistStatusLabels();
        setStatus("Wordlists reset to defaults");
    }

    private List<String> chooseWordlist(String title) {
        if (hostTextField == null || hostTextField.getScene() == null) {
            setStatus("UI is not ready for file selection");
            return null;
        }
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);
        chooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Text files", "*.txt", "*.list", "*.lst", "*.wordlist"),
                new FileChooser.ExtensionFilter("All files", "*.*")
        );
        java.io.File selected = chooser.showOpenDialog(hostTextField.getScene().getWindow());
        if (selected == null) return null;
        try {
            List<String> lines = java.nio.file.Files.readAllLines(selected.toPath(), java.nio.charset.StandardCharsets.UTF_8)
                    .stream()
                    .map(String::trim)
                    .filter(s -> !s.isEmpty() && !s.startsWith("#"))
                    .distinct()
                    .toList();
            if (lines.isEmpty()) {
                setStatus("Selected wordlist is empty: " + selected.getName());
                return null;
            }
            return lines;
        } catch (java.io.IOException | SecurityException e) {
            setStatus("Failed to read wordlist: " + e.getMessage());
            return null;
        }
    }

    private void refreshWordlistStatusLabels() {
        if (wordlistStatusTitleLabel != null) {
            wordlistStatusTitleLabel.setText(getWordlistStatusTitle());
        }
        if (wordlistSubdomainStatusLabel != null) {
            wordlistSubdomainStatusLabel.setText("Subdomain: " + subdomainWordlistStatus);
        }
        if (wordlistSqlStatusLabel != null) {
            wordlistSqlStatusLabel.setText("SQLi payloads: " + sqliWordlistStatus);
        }
        if (wordlistEndpointStatusLabel != null) {
            wordlistEndpointStatusLabel.setText("Endpoints: " + endpointWordlistStatus);
        }
    }

    private String getWordlistStatusTitle() {
        LanguageManager.Language lang = LanguageManager.getInstance().getLanguage();
        return switch (lang) {
            case RU -> "СТАТУС WORDLIST";
            case IT -> "STATO WORDLIST";
            case EN -> "WORDLIST STATUS";
        };
    }

    private void setupResolvedHostContextMenu() {
        MenuItem copyIP = new MenuItem("Copy");
        copyIP.setOnAction(e -> clipboardHandler.copyResolvedIP(resolvedHostLabel));
        resolvedHostLabel.setContextMenu(new ContextMenu(copyIP));
    }

    /* -- Event handlers --------------------------------------- */

    
    private void handleHostFieldFocusLost() {
        String originalHost = hostTextField.getText().trim();
        
        // Skip sanitization if input looks like a URL
        if (originalHost.toLowerCase().startsWith("http://")
                || originalHost.toLowerCase().startsWith("https://")) {
            return;
        }
        
        String sanitizedHost = hostResolver.sanitizeHost(originalHost);
        
        if (!sanitizedHost.isEmpty()) {
            if (!sanitizedHost.equals(originalHost)) {
                hostTextField.setText(sanitizedHost);
            }
            hostResolver.resolveHostAsync(sanitizedHost, resolvedHostLabel,
                    proxyTabHandler::autoSelectProxyForCurrentTarget);
        } else {
            resolvedHostLabel.setText("");
        }
    }

    /* -- FXML button actions ---------------------------------- */
    @FXML
    protected void onScanButtonClick() {
        scanningInProgress = true;
        jsAnalysisHandler.switchToPortScannerMode();

        if (proxyTabHandler.getProxyRoutingService() != null
            && proxyTabHandler.getProxyRoutingService().isReady()) {
            String resolvedIp = hostResolver.extractIPFromResolvedText(
                resolvedHostLabel.getText());
            String geoTarget = resolvedIp.isBlank()
                ? hostTextField.getText().trim() : resolvedIp;
            proxyTabHandler.getProxyRoutingService()
                .selectProxy(geoTarget)
                .ifPresent(proxyTabHandler::updateActiveProxy);
        }

        consoleViewManager.printScanHeader(
            hostTextField.getText(), proxyTabHandler.getCurrentActiveProxy());

        scanActionHandler.startScan(
            hostTextField.getText(),
            portsTextField.getText(),
            threadSpinner.getValue()
        );
        }

        @FXML
        protected void onJsAnalysisClick() {
        jsAnalysisHandler.startJsAnalysis();
    }

    @FXML
    protected void onSqlInjectionClick() {
        runSqlInjectionScan();
    }

    @FXML
    protected void onStopButtonClick() {
        if (jsAnalysisHandler.isJsAnalysisInProgress()) {
            jsAnalysisHandler.cancelCurrentTask();
            setStatus("JavaScript analysis stopped");
            resetScanUI();
        } else if (sqlInjectionInProgress && sqlInjectionTask != null && !sqlInjectionTask.isDone()) {
            injectionAnalyzer.requestStop();
            setStatus("Stopping SQL injection scan...");
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
        extraScanHandler.runUdpScan();
    }

    @FXML
    protected void onSubdomainEnumClick() {
        extraScanHandler.runSubdomainEnumeration();
    }

    @FXML
    protected void onSourceMapClick() {
        extraScanHandler.runSourceMapAnalysis();
    }

    @FXML
    protected void onParamMinerClick() {
        extraScanHandler.runParamMiner();
    }

    @FXML
    protected void onDiffModeClick() {
        extraScanHandler.runDiffMode();
    }

    @FXML
    protected void onSchedulerStartClick() {
        extraScanHandler.startScheduledScan();
    }

    @FXML
    protected void onSchedulerStopClick() {
        extraScanHandler.stopScheduledScan();
    }

    @FXML
    protected void onClearClick() {
        if (jsAnalysisHandler.isJsAnalysisMode()) {
            jsAnalysisHandler.onJsClearClick();
        } else {
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
        proxyTabHandler.onStartProxy();
    }

    @FXML
    protected void onLoadProxyClick() {
        proxyTabHandler.onLoadProxy();
    }

    @FXML
    protected void onClearProxyLogClick() {
        proxyTabHandler.onClearProxyLog();
    }

    @FXML
    protected void onRotateProxyClick() {
        proxyTabHandler.onRotateProxy();
    }

    @FXML
    protected void onBuildChainClick() {
        proxyTabHandler.onBuildChain();
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

        // Buttons
        scanButton.setText(lm.get("btn.startScan"));
        stopButton.setText(lm.get("btn.stop"));
        exportButton.setText(lm.get("btn.export"));
        clearButton.setText(lm.get("btn.clear"));
        jsExportButton.setText(lm.get("btn.exportAnalysis"));
        if (jsAnalysisRunButton != null) jsAnalysisRunButton.setText("▶  Run JavaScript Analysis");

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
            jsAnalysisHandler.isJsAnalysisMode() ? lm.get("console.headerJs") : lm.get("console.header"));

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

        if (plannedFeaturesLabel != null) plannedFeaturesLabel.setText(lm.get("section.plannedFeatures"));
        if (udpScanButton != null) udpScanButton.setText(lm.get("btn.udpScan"));
        if (subdomainButton != null) subdomainButton.setText(lm.get("btn.subdomains"));
        if (sourceMapButton != null) sourceMapButton.setText(lm.get("btn.sourceMaps"));
        if (paramMinerButton != null) paramMinerButton.setText(lm.get("btn.paramMiner"));
        if (diffModeButton != null) diffModeButton.setText(lm.get("btn.diffMode"));
        if (schedulerStartButton != null) schedulerStartButton.setText(lm.get("btn.schedulerOn"));
        if (schedulerStopButton != null) schedulerStopButton.setText(lm.get("btn.schedulerOff"));

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
        jsAnalysisHandler.refreshResultCountLabel();

        // Sync language radio selection in config menu
        if (actionsMenuButton != null) {
            actionsMenuButton.setText("Actions");
        }
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

        refreshWordlistStatusLabels();
    }

    /* -- UI helpers ------------------------------------------- */
    private void refreshResultCount() {
        Platform.runLater(() -> {
            jsAnalysisHandler.refreshResultCountLabel();
        });
    }

    private void setStatus(String msg) {
        Platform.runLater(() -> {
            if (statusLabel != null) statusLabel.setText(msg);
            if (msg == null || msg.isBlank() || consoleViewManager == null) {
                return;
            }
            if (msg.equals(lastStatusMessage)) {
                return;
            }
            lastStatusMessage = msg;
            String ts = java.time.LocalTime.now().withNano(0).toString();
            consoleViewManager.appendRawText("[" + ts + "] " + msg + "\n");
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

    @SuppressWarnings("unused") // Referenced from FXML
    @FXML
    void onJsExportClick() {
        jsAnalysisHandler.onJsExportClick();
    }
    
    private void resetScanUI() {
        Platform.runLater(() -> {
            scanButton.setDisable(false);
            if (jsAnalysisRunButton != null) jsAnalysisRunButton.setDisable(false);
            if (sqlInjectionRunButton != null) sqlInjectionRunButton.setDisable(false);
            stopButton.setDisable(true);
            progressBar.setVisible(false);
        });
    }
    
    /**
     * Gracefully shuts down all services and background resources.
     * Called from {@link it.r2u.anibus.AnibusApplication#stop()} when the window closes.
     * Each service is stopped independently so a failure in one does not block the others.
     */
    public void shutdownExecutor() {
        shutdownSafe("ScanCoordinator", () -> { if (scanCoordinator != null) scanCoordinator.shutdown(); });
        shutdownSafe("NetworkStatusMonitor", () -> { if (networkStatusMonitor != null) networkStatusMonitor.stop(); });
        shutdownSafe("ScanSchedulerService", () -> { if (scanSchedulerService != null) scanSchedulerService.shutdown(); });
        shutdownSafe("JavaScriptAnalyzer", () -> { if (jsAnalyzer != null) jsAnalyzer.shutdown(); });
        shutdownSafe("SQLInjectionAnalyzer", () -> { if (injectionAnalyzer != null) injectionAnalyzer.shutdown(); });
        shutdownSafe("NotificationService", () -> { if (notificationService != null) notificationService.shutdown(); });
    }

    /** Runs {@code action}, catching and logging any exception so shutdown continues. */
    private static void shutdownSafe(String name, Runnable action) {
        try {
            action.run();
        } catch (Exception e) {
            LOG.warning(() -> "[SHUTDOWN] " + name + " failed to stop cleanly: " + e.getMessage());
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

    private void runAsnLookup() { securityAnalysisHandler.runAsnLookup(); }

    private void runApiSecurityMode() { securityAnalysisHandler.runApiSecurityMode(); }
}
