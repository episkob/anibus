package it.r2u.anibus.handlers;

import java.util.function.Consumer;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.ui.ClipboardService;
import javafx.collections.ObservableList;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;

/**
 * Handler for clipboard operations.
 * Follows Single Responsibility and Command patterns.
 */
public class ClipboardActionHandler {
    
    private final Consumer<String> statusSetter;
    
    public ClipboardActionHandler(Consumer<String> statusSetter) {
        this.statusSetter = statusSetter;
    }
    
    /**
     * Copy full console output to clipboard.
     */
    public void copyConsoleOutput(TextArea consoleTextArea) {
        if (consoleTextArea.getText() == null || consoleTextArea.getText().isEmpty()) {
            return;
        }
        ClipboardService.copy(consoleTextArea.getText());
        statusSetter.accept("Console output copied to clipboard");
    }

    /**
     * Copy the currently selected text to clipboard.
     */
    public void copySelectedText(TextArea textArea) {
        if (textArea == null) {
            return;
        }

        String selectedText = textArea.getSelectedText();
        if (selectedText == null || selectedText.isBlank()) {
            statusSetter.accept("Select text first");
            return;
        }

        ClipboardService.copy(selectedText);
        statusSetter.accept("Selected text copied to clipboard");
    }
    
    /**
     * Copy all scan results to clipboard.
     */
    public void copyAllResults(ObservableList<PortScanResult> results) {
        if (results.isEmpty()) {
            return;
        }
        ClipboardService.copy(ClipboardService.formatAll(results));
        statusSetter.accept("All results copied to clipboard");
    }
    
    /**
     * Copy resolved IP address from label.
     */
    public void copyResolvedIP(Label resolvedHostLabel) {
        String text = resolvedHostLabel.getText();
        if (text == null || text.isEmpty()) {
            return;
        }
        
        // Extract IP from "Resolved: 172.217.23.163 [SSL/TLS ✓]" format
        String ip = text.replace("Resolved:", "").trim();
        
        // Remove SSL status if present
        int sslIndex = ip.indexOf("[SSL/TLS");
        if (sslIndex != -1) {
            ip = ip.substring(0, sslIndex).trim();
        }
        
        if (!ip.isEmpty()) {
            ClipboardService.copy(ip);
            statusSetter.accept("IP address copied to clipboard");
        }
    }
}
