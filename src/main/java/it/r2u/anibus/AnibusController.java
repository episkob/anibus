package it.r2u.anibus;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Properties;

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
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.network.NetworkStatusMonitor;
import it.r2u.anibus.service.analysis.ApiSecurityModeService;
import it.r2u.anibus.service.analysis.CorsChecker;
import it.r2u.anibus.service.analysis.DirectoryBruteforcer;
import it.r2u.anibus.service.analysis.GraphqlScanner;
import it.r2u.anibus.service.analysis.HeartbleedChecker;
import it.r2u.anibus.service.analysis.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.service.analysis.JwtAnalyzer;
import it.r2u.anibus.service.analysis.Log4ShellChecker;
import it.r2u.anibus.service.analysis.ParamMinerService;
import it.r2u.anibus.service.analysis.PassiveReconService;
import it.r2u.anibus.service.analysis.SQLInjectionAnalyzer;
import it.r2u.anibus.service.analysis.SecretsValidationService;
import it.r2u.anibus.service.analysis.SourceMapAnalyzer;
import it.r2u.anibus.service.analysis.Spring4ShellChecker;
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
    private boolean scanningInProgress = false;
    
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

        securityAnalysisHandler = SecurityAnalysisHandler.builder()
            .targetUrlSupplier(() -> SecurityAnalysisHandler.ensureHttpUrl(hostTextField.getText()))
            .targetHostSupplier(() -> SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText()))
            .consoleTextSupplier(() -> consoleTextArea.getText())
            .firstScanPortSupplier(() -> results.isEmpty() ? 0 : results.get(0).getPort())
            .tlsPortSupplier(() -> results.stream()
                .filter(r -> r.getPort() == 443 || r.getPort() == 8443)
                .mapToInt(PortScanResult::getPort).findFirst().orElse(443))
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
            .log4ShellChecker(log4ShellChecker)
            .spring4ShellChecker(spring4ShellChecker)
            .webSocketDetector(webSocketDetector)
            .httpProtocolDetector(httpProtocolDetector)
            .asnLookupService(asnLookupService)
            .heartbleedChecker(heartbleedChecker)
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
                jsInjectionCheckBox, jsResultsCard,
                jsEndpointsLabel, jsDataStructuresLabel, jsDbSchemasLabel,
                jsSensitiveInfoLabel, jsArchitectureLabel,
                jsStructureTree, sqlInjectionTextArea, consoleTextArea,
                consoleHeaderLabel, resultCountLabel),
            jsAnalyzer, injectionAnalyzer, exportHandler,
            consoleViewManager, results, this::setStatus,
            this::resetScanUI);

        extraScanHandler = new ExtraScanHandler(
            hostTextField, portsTextField, progressBar, consoleTextArea,
            consoleViewManager, results, this::setStatus,
            () -> jsAnalysisHandler.getLastJsAnalysisResult(),
            udpScannerService, subdomainEnumerationService, sourceMapAnalyzer,
            paramMinerService, scanDiffService, scanSchedulerService,
            scanHistoryService, injectionAnalyzer, scanner);

        proxyTabHandler = new ProxyTabHandler(
            proxyLogArea, activeProxyLabel, proxyStatusDot,
            startProxyButton, clearProxyButton, loadProxyButton, rotateProxyButton,
            proxyStatCandidates, proxyStatLive, proxyStatCountries, proxyPhaseLabel,
            proxyProgressBar, chainDisplayArea, chainDisplayCard,
            proxyAvailableListView, proxyChainListView,
            hostTextField, resolvedHostLabel, hostResolver);
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

    private void renderTopologyGraph(TracerouteService.TraceRoute trace) {
        topologyHandler.renderTopologyGraph(trace);
    }

    private void updateStatisticsDashboard() {
        statisticsHandler.updateStatisticsDashboard();
    }

    private void runUdpScan() { extraScanHandler.runUdpScan(); }

    private void runSubdomainEnumeration() { extraScanHandler.runSubdomainEnumeration(); }

    private void runSourceMapAnalysis() { extraScanHandler.runSourceMapAnalysis(); }

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

    private void runLog4ShellCheck() { securityAnalysisHandler.runLog4ShellCheck(80); }

    private void runSpring4ShellCheck() { securityAnalysisHandler.runSpring4ShellCheck(); }

    private void runWebSocketDetect() { securityAnalysisHandler.runWebSocketDetect(80); }

    private void runHttpProtocolDetect() { securityAnalysisHandler.runHttpProtocolDetect(80); }

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
                    proxyTabHandler::autoSelectProxyForCurrentTarget);
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
            jsAnalysisHandler.startJsAnalysis();
        } else {
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
    }

    @FXML
    protected void onStopButtonClick() {
        if (jsAnalysisHandler.isJsAnalysisInProgress()) {
            jsAnalysisHandler.cancelCurrentTask();
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
        jsAnalysisHandler.refreshResultCountLabel();

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
            jsAnalysisHandler.refreshResultCountLabel();
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

    @SuppressWarnings("unused") // Referenced from FXML
    @FXML
    void onJsExportClick() {
        jsAnalysisHandler.onJsExportClick();
    }
    
    @FXML
    void onJsClearClick() {
        jsAnalysisHandler.onJsClearClick();
    }

    private void resetScanUI() {
        Platform.runLater(() -> {
            scanButton.setDisable(false);
            stopButton.setDisable(true);
            progressBar.setVisible(false);
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

    private void runAsnLookup() { securityAnalysisHandler.runAsnLookup(); }

    private void runHeartbleedCheck() { securityAnalysisHandler.runHeartbleedCheck(); }

    private void runApiSecurityMode() { securityAnalysisHandler.runApiSecurityMode(); }
}
