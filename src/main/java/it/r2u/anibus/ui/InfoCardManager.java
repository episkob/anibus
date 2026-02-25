package it.r2u.anibus.ui;

import it.r2u.anibus.model.PortScanResult;
import javafx.application.Platform;
import javafx.scene.control.Label;
import javafx.scene.layout.VBox;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Manages the info card display with scan statistics.
 */
public class InfoCardManager {
    
    private final VBox infoCard;
    private final Label infoIpLabel;
    private final Label infoHostnameLabel;
    private final Label infoScanTimeLabel;
    private final Label infoPortsScannedLabel;
    private final Label infoOpenPortsLabel;
    private final Label infoAvgLatencyLabel;
    
    private Instant scanStartTime;
    
    public InfoCardManager(VBox infoCard, Label infoIpLabel, Label infoHostnameLabel,
                           Label infoScanTimeLabel, Label infoPortsScannedLabel,
                           Label infoOpenPortsLabel, Label infoAvgLatencyLabel) {
        this.infoCard = infoCard;
        this.infoIpLabel = infoIpLabel;
        this.infoHostnameLabel = infoHostnameLabel;
        this.infoScanTimeLabel = infoScanTimeLabel;
        this.infoPortsScannedLabel = infoPortsScannedLabel;
        this.infoOpenPortsLabel = infoOpenPortsLabel;
        this.infoAvgLatencyLabel = infoAvgLatencyLabel;
    }
    
    /**
     * Shows the info card with initial scan information.
     */
    public void showInfoCard(String ip, String hostname, int totalPorts) {
        Platform.runLater(() -> {
            if (infoCard != null) infoCard.setVisible(true);
            if (infoIpLabel != null) infoIpLabel.setText(ip);
            if (infoHostnameLabel != null) infoHostnameLabel.setText(hostname);
            if (infoScanTimeLabel != null) infoScanTimeLabel.setText("—");
            if (infoPortsScannedLabel != null) infoPortsScannedLabel.setText(String.valueOf(totalPorts));
            if (infoOpenPortsLabel != null) infoOpenPortsLabel.setText("0");
            if (infoAvgLatencyLabel != null) infoAvgLatencyLabel.setText("—");
        });
    }
    
    /**
     * Updates the info card with current results.
     */
    public void refreshInfoCard(List<PortScanResult> results) {
        Platform.runLater(() -> {
            if (infoOpenPortsLabel != null) {
                infoOpenPortsLabel.setText(String.valueOf(results.size()));
            }
            if (infoAvgLatencyLabel != null && !results.isEmpty()) {
                double avg = results.stream().mapToLong(PortScanResult::getLatency).average().orElse(0.0);
                infoAvgLatencyLabel.setText(String.format("%.1f ms", avg));
            }
        });
    }
    
    /**
     * Starts scan time tracking.
     */
    public void startScanTime() {
        this.scanStartTime = Instant.now();
    }
    
    /**
     * Finalizes scan time and displays elapsed duration.
     */
    public void finalizeScanTime() {
        if (scanStartTime == null) return;
        
        Duration elapsed = Duration.between(scanStartTime, Instant.now());
        long sec = elapsed.getSeconds();
        String formatted = String.format("%d:%02d:%02d", sec / 3600, (sec % 3600) / 60, sec % 60);
        
        Platform.runLater(() -> {
            if (infoScanTimeLabel != null) {
                infoScanTimeLabel.setText(formatted);
            }
        });
    }
    
    /**
     * Hides the info card.
     */
    public void hideInfoCard() {
        Platform.runLater(() -> {
            if (infoCard != null) {
                infoCard.setVisible(false);
            }
        });
    }
}
