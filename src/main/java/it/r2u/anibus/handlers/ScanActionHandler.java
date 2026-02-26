package it.r2u.anibus.handlers;

import it.r2u.anibus.coordinator.ScanCoordinator;
import it.r2u.anibus.coordinator.ScanContext;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.network.HostResolver;
import it.r2u.anibus.service.PortScannerService;
import it.r2u.anibus.ui.AlertHelper;
import it.r2u.anibus.ui.ConsoleViewManager;
import it.r2u.anibus.ui.InfoCardManager;
import javafx.application.Platform;
import javafx.collections.ObservableList;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Handler for scan operations.
 * Manages scan lifecycle, UI updates, and software stack analysis.
 * Follows Single Responsibility, Command, and Facade patterns.
 */
public class ScanActionHandler {
    
    private final ScanCoordinator scanCoordinator;
    private final PortScannerService scanner;
    private final HostResolver hostResolver;
    private final ObservableList<PortScanResult> results;
    private final ConsoleViewManager consoleViewManager;
    private final InfoCardManager infoCardManager;
    private final Consumer<String> statusSetter;
    private final UIComponents uiComponents;
    private final URL cssUrl;
    
    public ScanActionHandler(
            ScanCoordinator scanCoordinator,
            PortScannerService scanner,
            HostResolver hostResolver,
            ObservableList<PortScanResult> results,
            ConsoleViewManager consoleViewManager,
            InfoCardManager infoCardManager,
            Consumer<String> statusSetter,
            UIComponents uiComponents,
            URL cssUrl) {
        this.scanCoordinator = scanCoordinator;
        this.scanner = scanner;
        this.hostResolver = hostResolver;
        this.results = results;
        this.consoleViewManager = consoleViewManager;
        this.infoCardManager = infoCardManager;
        this.statusSetter = statusSetter;
        this.uiComponents = uiComponents;
        this.cssUrl = cssUrl;
    }
    
    /**
     * Start scan with validation and UI preparation.
     */
    public void startScan(String host, String portsRange, int threadCount) {
        results.clear();
        
        // Sanitize and validate host
        String sanitizedHost = hostResolver.sanitizeHost(host);
        if (sanitizedHost.isEmpty() || portsRange.trim().isEmpty()) {
            AlertHelper.show("Missing input", 
                "Please enter both hostname and port range.",
                Alert.AlertType.WARNING, cssUrl);
            return;
        }
        
        // Update host field if sanitized
        if (!sanitizedHost.equals(host.trim())) {
            uiComponents.setHostText(sanitizedHost);
        }
        
        // Parse and validate port range
        int[] ports = scanner.parsePortsRange(portsRange);
        if (ports == null) {
            AlertHelper.show("Invalid range", 
                "Use format start-end (1-65535), e.g. 1-1024 or 1-65535.",
                Alert.AlertType.ERROR, cssUrl);
            return;
        }
        
        // Prepare UI
        uiComponents.setScanInProgress(true);
        infoCardManager.startScanTime();
        
        // Show mode-specific status
        String prefix = scanCoordinator.getCurrentStatusPrefix();
        statusSetter.accept(prefix + " Resolving " + sanitizedHost + "...");
        
        // Create scan context and execute
        ScanContext context = createScanContext(sanitizedHost, ports[0], ports[1], threadCount);
        scanCoordinator.executeScan(context);
        
        // Bind progress
        uiComponents.getProgressBar().progressProperty().bind(scanCoordinator.progressProperty());
    }
    
    /**
     * Stop ongoing scan.
     */
    public void stopScan() {
        scanCoordinator.cancelScan();
    }
    
    /**
     * Create scan context with all callbacks.
     */
    private ScanContext createScanContext(String host, int startPort, int endPort, int threadCount) {
        return ScanContext.builder()
            .host(host)
            .startPort(startPort)
            .endPort(endPort)
            .threadCount(threadCount)
            .callbacks(new ScanContext.ScanCallbacks() {
                @Override
                public void onHostResolved(String ip) {
                    String sslStatus = hostResolver.checkSSL(host);
                    Platform.runLater(() -> 
                        uiComponents.getResolvedHostLabel().setText("Resolved: " + ip + sslStatus));
                }
                
                @Override
                public void onScanStarted(String ip, String hostname, int totalPorts) {
                    infoCardManager.showInfoCard(ip, hostname, totalPorts);
                }
                
                @Override
                public void onResult(PortScanResult result) {
                    results.add(result);
                    consoleViewManager.appendToConsole(result);
                }
                
                @Override
                public void onStatus(String message) {
                    statusSetter.accept(message);
                }
                
                @Override
                public void onCompleted() {
                    infoCardManager.finalizeScanTime();
                    analyzeSoftwareStackIfNeeded();
                    String prefix = scanCoordinator.getCurrentStatusPrefix();
                    String mode = scanCoordinator.getCurrentStrategyName();
                    statusSetter.accept(prefix + " " + mode + " complete — " + 
                        results.size() + " open port(s) found");
                    resetUI();
                }
                
                @Override
                public void onCancelled() {
                    infoCardManager.finalizeScanTime();
                    String prefix = scanCoordinator.getCurrentStatusPrefix();
                    String mode = scanCoordinator.getCurrentStrategyName();
                    statusSetter.accept(prefix + " " + mode + " stopped by user");
                    resetUI();
                }
                
                @Override
                public void onFailed(String error) {
                    infoCardManager.finalizeScanTime();
                    String prefix = scanCoordinator.getCurrentStatusPrefix();
                    String mode = scanCoordinator.getCurrentStrategyName();
                    statusSetter.accept(prefix + " " + mode + " failed: " + error);
                    resetUI();
                }
            })
            .build();
    }
    
    /**
     * Analyze software stack for service detection scans.
     */
    private void analyzeSoftwareStackIfNeeded() {
        if (results.isEmpty()) return;
        
        // Collect open ports with banners
        Map<Integer, String> openPortsWithBanners = new HashMap<>();
        for (PortScanResult result : results) {
            String banner = result.getBanner() != null ? result.getBanner() : "";
            banner = banner + " " + (result.getService() != null ? result.getService() : "");
            openPortsWithBanners.put(result.getPort(), banner);
        }
        
        // Software stack detection disabled by user request
        // Could be re-enabled here if needed
    }
    
    /**
     * Reset UI to normal state after scan completion.
     */
    private void resetUI() {
        Platform.runLater(() -> {
            // ВАЖНО: Сначала unbind, потом установка значений!
            uiComponents.getProgressBar().progressProperty().unbind();
            uiComponents.setScanInProgress(false);
        });
    }
    
    /**
     * Container for UI components to reduce parameter count.
     * Follows Data Transfer Object pattern.
     */
    public static class UIComponents {
        private final javafx.scene.control.TextField hostTextField;
        private final javafx.scene.control.Button scanButton;
        private final javafx.scene.control.Button stopButton;
        private final ProgressBar progressBar;
        private final Label resolvedHostLabel;
        
        public UIComponents(
                javafx.scene.control.TextField hostTextField,
                javafx.scene.control.Button scanButton,
                javafx.scene.control.Button stopButton,
                ProgressBar progressBar,
                Label resolvedHostLabel) {
            this.hostTextField = hostTextField;
            this.scanButton = scanButton;
            this.stopButton = stopButton;
            this.progressBar = progressBar;
            this.resolvedHostLabel = resolvedHostLabel;
        }
        
        public void setHostText(String text) {
            hostTextField.setText(text);
        }
        
        public void setScanInProgress(boolean inProgress) {
            scanButton.setDisable(inProgress);
            stopButton.setDisable(!inProgress);
            progressBar.setVisible(inProgress);
            if (!inProgress) {
                progressBar.setProgress(0);
            }
        }
        
        public ProgressBar getProgressBar() {
            return progressBar;
        }
        
        public Label getResolvedHostLabel() {
            return resolvedHostLabel;
        }
    }
}
