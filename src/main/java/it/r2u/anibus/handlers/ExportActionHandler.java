package it.r2u.anibus.handlers;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.ExportService;
import javafx.collections.ObservableList;
import javafx.stage.Window;

import java.net.URL;
import java.util.function.Consumer;

/**
 * Handler for export operations.
 * Follows Single Responsibility and Command patterns.
 */
public class ExportActionHandler {
    
    private final Consumer<String> statusSetter;
    private final URL cssUrl;
    
    public ExportActionHandler(Consumer<String> statusSetter, URL cssUrl) {
        this.statusSetter = statusSetter;
        this.cssUrl = cssUrl;
    }
    
    /**
     * Export scan results to file with user prompt.
     */
    public void exportResults(ObservableList<PortScanResult> results, Window owner) {
        new ExportService(results, owner, cssUrl, statusSetter)
                .promptAndExport();
    }
}
