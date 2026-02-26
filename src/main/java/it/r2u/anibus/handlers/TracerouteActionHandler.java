package it.r2u.anibus.handlers;

import it.r2u.anibus.service.TracerouteService;
import javafx.application.Platform;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextInputDialog;

import java.util.function.Consumer;

/**
 * Handler for traceroute operations.
 * Follows Single Responsibility and Command patterns.
 */
public class TracerouteActionHandler {
    
    private final Consumer<String> statusSetter;
    
    public TracerouteActionHandler(Consumer<String> statusSetter) {
        this.statusSetter = statusSetter;
    }
    
    /**
     * Run traceroute with user prompt for target.
     */
    public void runTraceroute(String defaultHost, TextArea consoleTextArea) {
        TextInputDialog dialog = new TextInputDialog(defaultHost);
        dialog.setTitle("Traceroute");
        dialog.setHeaderText("Network Path Tracing");
        dialog.setContentText("Enter target host or IP:");
        
        dialog.showAndWait().ifPresent(target -> {
            if (target == null || target.trim().isEmpty()) {
                return;
            }
            
            executeTraceroute(target, consoleTextArea);
        });
    }
    
    private void executeTraceroute(String target, TextArea consoleTextArea) {
        // Show progress in console
        Platform.runLater(() -> {
            consoleTextArea.appendText("\n\n" + "=".repeat(80) + "\n");
            consoleTextArea.appendText("Starting traceroute to " + target + "...\n");
            consoleTextArea.appendText("This may take some time...\n");
            consoleTextArea.appendText("=".repeat(80) + "\n\n");
        });
        
        // Run traceroute in background thread
        Thread tracerouteThread = new Thread(() -> {
            TracerouteService.TraceRoute result = TracerouteService.traceroute(target);
            
            Platform.runLater(() -> {
                consoleTextArea.appendText(result.toString());
                consoleTextArea.appendText("\n\n");
                statusSetter.accept("Traceroute completed");
            });
        });
        
        tracerouteThread.setDaemon(true);
        tracerouteThread.start();
    }
}
