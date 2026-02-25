package it.r2u.anibus.ui;

import it.r2u.anibus.model.PortScanResult;
import javafx.application.Platform;
import javafx.scene.control.TextArea;

import java.util.List;

/**
 * Manages console view formatting and updates.
 */
public class ConsoleViewManager {
    
    private final TextArea consoleTextArea;
    private boolean isConsoleView;
    
    public ConsoleViewManager(TextArea consoleTextArea) {
        this.consoleTextArea = consoleTextArea;
        this.isConsoleView = false;
    }
    
    public boolean isConsoleView() {
        return isConsoleView;
    }
    
    public void toggle() {
        this.isConsoleView = !this.isConsoleView;
    }
    
    public void setConsoleView(boolean consoleView) {
        this.isConsoleView = consoleView;
    }
    
    /**
     * Formats a single port scan result for console display.
     */
    public String formatConsoleResult(PortScanResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("┌─ Port: %d (%s)\n", result.getPort(), result.getState()));
        sb.append(String.format("│  Service:  %s\n", 
            result.getService() != null && !result.getService().isEmpty() ? result.getService() : "unknown"));
        
        if (result.getVersion() != null && !result.getVersion().isEmpty()) {
            sb.append(String.format("│  Version:  %s\n", result.getVersion()));
        }
        
        if (result.getProtocol() != null && !result.getProtocol().isEmpty()) {
            sb.append(String.format("│  Protocol: %s\n", result.getProtocol()));
        }
        
        sb.append(String.format("│  Latency:  %d ms\n", result.getLatency()));
        
        if (result.getBanner() != null && !result.getBanner().isEmpty()) {
            // Show full banner without truncation
            sb.append(String.format("│  Banner:   %s\n", result.getBanner()));
        }
        
        sb.append("└─────────────────────────────────────────────────────────────────────\n\n");
        return sb.toString();
    }
    
    /**
     * Updates console with all results (used when switching from table view).
     */
    public void updateConsoleWithAllResults(List<PortScanResult> results) {
        if (consoleTextArea == null) return;
        
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        sb.append("                        ANIBUS SCAN RESULTS                            \n");
        sb.append("═══════════════════════════════════════════════════════════════════════\n\n");
        
        if (results.isEmpty()) {
            sb.append("No results to display\n");
        } else {
            for (PortScanResult result : results) {
                sb.append(formatConsoleResult(result));
            }
        }
        
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        sb.append(String.format("Total: %d open port%s\n", results.size(), results.size() == 1 ? "" : "s"));
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        
        consoleTextArea.setText(sb.toString());
    }
    
    /**
     * Appends a single result to console (for live updates during scanning).
     */
    public void appendToConsole(PortScanResult result) {
        if (consoleTextArea == null || !isConsoleView) return;
        
        Platform.runLater(() -> {
            String current = consoleTextArea.getText();
            if (current.isEmpty()) {
                // First result - add header
                consoleTextArea.setText(
                    "═══════════════════════════════════════════════════════════════════════\n" +
                    "                        ANIBUS SCAN RESULTS                            \n" +
                    "═══════════════════════════════════════════════════════════════════════\n\n" +
                    formatConsoleResult(result)
                );
            } else {
                consoleTextArea.appendText(formatConsoleResult(result));
            }
            
            // Auto-scroll to bottom
            consoleTextArea.setScrollTop(Double.MAX_VALUE);
        });
    }
    
    /**
     * Clears the console text area.
     */
    public void clear() {
        if (consoleTextArea != null) {
            consoleTextArea.clear();
        }
    }
}
