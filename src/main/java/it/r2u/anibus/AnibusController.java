package it.r2u.anibus;

import it.r2u.anibus.network.NetworkStatusMonitor;
import it.r2u.anibus.ui.AlertHelper;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Circle;

import java.util.Properties;

/**
 * Main application controller.
 * Manages navigation bar, status bar, network monitoring, and tab wiring.
 * Each tab has its own controller with isolated functionality.
 */
public class AnibusController {

    /* -- FXML fields ------------------------------------------ */
    @FXML private Label   statusLabel;
    @FXML private Circle  networkDot;
    @FXML private TabPane mainTabPane;

    /* -- Child controllers (injected via fx:include fx:id convention) -- */
    @FXML private VBox portScanner;
    @FXML private PortScannerController portScannerController;
    @FXML private VBox jsAnalysis;
    @FXML private JsAnalysisController jsAnalysisController;
    @FXML private VBox sqlInjection;
    @FXML private SqlInjectionController sqlInjectionController;

    /* -- Services --------------------------------------------- */
    private NetworkStatusMonitor networkStatusMonitor;

    /** Default status text shown when each tab becomes active. */
    private static final String[] TAB_DEFAULT_STATUS = {
        "Port Scanner — enter host and scan range, then press Scan",
        "JavaScript Analysis — enter target URL and press Analyze",
        "SQL Injection — enter target URL and press Run Injection Test"
    };

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        // Network status monitor
        Tooltip networkTooltip = new Tooltip("Checking network");
        Tooltip.install(networkDot, networkTooltip);
        networkStatusMonitor = new NetworkStatusMonitor(networkDot, networkTooltip);
        networkStatusMonitor.start();

        // Wire child controllers with shared context
        java.net.URL css = cssUrl();
        portScannerController.setContext(this::setStatus, css);
        jsAnalysisController.setContext(this::setStatus, css);
        sqlInjectionController.setContext(this::setStatus, css);

        // Update status bar when switching tabs
        mainTabPane.getSelectionModel().selectedIndexProperty().addListener((obs, oldIdx, newIdx) -> {
            int i = newIdx.intValue();
            if (i >= 0 && i < TAB_DEFAULT_STATUS.length) {
                setStatus(TAB_DEFAULT_STATUS[i]);
            }
        });

        // Set initial status for the first tab
        setStatus(TAB_DEFAULT_STATUS[0]);
    }

    /* -- FXML button actions ---------------------------------- */
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

    /* -- Helpers ---------------------------------------------- */
    private void setStatus(String msg) {
        Platform.runLater(() -> {
            if (statusLabel != null) statusLabel.setText(msg);
        });
    }

    private java.net.URL cssUrl() {
        return getClass().getResource("anibus-style.css");
    }

    /**
     * Shutdown all services and cleanup resources.
     * Called when application closes.
     */
    public void shutdownExecutor() {
        if (networkStatusMonitor != null) networkStatusMonitor.stop();
        if (portScannerController != null) portScannerController.shutdown();
        if (jsAnalysisController != null) jsAnalysisController.shutdown();
        if (sqlInjectionController != null) sqlInjectionController.shutdown();
    }
}
