package it.r2u.anibus.handlers;

import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.ExportService;
import javafx.collections.ObservableList;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.io.FileWriter;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
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
    
    /**
     * Export JavaScript analysis results to file.
     */
    public void exportJavaScriptAnalysis(JavaScriptAnalysisResult result) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Export JavaScript Analysis Results");
        fileChooser.setInitialFileName("js-analysis-" + 
            new SimpleDateFormat("yyyy-MM-dd-HHmmss").format(new Date()) + ".txt");
        
        FileChooser.ExtensionFilter textFilter = new FileChooser.ExtensionFilter("Text Files", "*.txt");
        FileChooser.ExtensionFilter jsonFilter = new FileChooser.ExtensionFilter("JSON Files", "*.json");
        fileChooser.getExtensionFilters().addAll(textFilter, jsonFilter);
        fileChooser.setSelectedExtensionFilter(textFilter);
        
        File file = fileChooser.showSaveDialog(null);
        if (file != null) {
            try (FileWriter writer = new FileWriter(file)) {
                if (file.getName().toLowerCase().endsWith(".json")) {
                    writer.write(generateJsonExport(result));
                } else {
                    writer.write(generateTextExport(result));
                }
                statusSetter.accept("JavaScript analysis exported to " + file.getName());
            } catch (Exception e) {
                statusSetter.accept("Export failed: " + e.getMessage());
            }
        }
    }
    
    private String generateTextExport(JavaScriptAnalysisResult result) {
        StringBuilder export = new StringBuilder();
        export.append("JavaScript Security Analysis Report\n");
        export.append("=====================================\n\n");
        export.append("Target: ").append(result.getTargetUrl()).append("\n");
        export.append("Analysis Date: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n");
        export.append("Analysis Time: ").append(result.getAnalysisTime()).append(" ms\n\n");
        
        export.append(result.getSummary()).append("\n\n");
        
        // Detailed sections
        export.append("DISCOVERED ENDPOINTS\n");
        export.append("===================\n");
        result.getEndpoints().forEach(endpoint -> {
            export.append("• ").append(endpoint.getHttpMethod()).append(" ").append(endpoint.getUrl());
            if (endpoint.isDynamic()) export.append(" (dynamic)");
            export.append("\n");
        });
        
        export.append("\nDATA STRUCTURES\n");
        export.append("===============\n");
        result.getDataStructures().forEach(structure -> {
            export.append("• ").append(structure.getName()).append(" (").append(structure.getType()).append(")\n");
            structure.getProperties().forEach((key, value) -> 
                export.append("  - ").append(key).append(": ").append(value).append("\n"));
        });
        
        export.append("\nDATABASE SCHEMAS\n");
        export.append("================\n");
        result.getDatabaseSchemas().forEach(schema -> {
            export.append("• ").append(schema.getTableName()).append(" (").append(schema.getDatabaseType())
                  .append(", ").append(String.format("%.0f", schema.getConfidence() * 100)).append("% confidence)\n");
            schema.getColumns().forEach((col, type) -> 
                export.append("  - ").append(col).append(": ").append(type).append("\n"));
        });
        
        export.append("\nSENSITIVE INFORMATION\n");
        export.append("====================\n");
        result.getSensitiveInfo().forEach(leak -> 
            export.append("• ").append(leak.getType()).append(": ").append(leak.getValue()).append("\n"));
        
        if (result.getArchitecture() != null) {
            export.append("\nARCHITECTURE ANALYSIS\n");
            export.append("====================\n");
            export.append("Framework: ").append(result.getArchitecture().getFramework()).append("\n");
            export.append("State Management: ").append(result.getArchitecture().getStateManagement()).append("\n");
            export.append("Pattern: ").append(result.getArchitecture().getPattern()).append("\n");
            export.append("Services: ").append(result.getArchitecture().getServices()).append("\n");
            export.append("Middlewares: ").append(result.getArchitecture().getMiddlewares()).append("\n");
        }
        
        if (!result.getErrors().isEmpty()) {
            export.append("\nERRORS\n");
            export.append("======\n");
            result.getErrors().forEach(error -> export.append("• ").append(error).append("\n"));
        }
        
        return export.toString();
    }
    
    private String generateJsonExport(JavaScriptAnalysisResult result) {
        // Simple JSON generation - in a real application, you'd use a proper JSON library
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"targetUrl\": \"").append(result.getTargetUrl()).append("\",\n");
        json.append("  \"analysisTime\": ").append(result.getAnalysisTime()).append(",\n");
        json.append("  \"timestamp\": \"").append(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(new Date())).append("\",\n");
        json.append("  \"summary\": {\n");
        json.append("    \"endpointsCount\": ").append(result.getEndpoints().size()).append(",\n");
        json.append("    \"dataStructuresCount\": ").append(result.getDataStructures().size()).append(",\n");
        json.append("    \"databaseSchemasCount\": ").append(result.getDatabaseSchemas().size()).append(",\n");
        json.append("    \"sensitiveInfoCount\": ").append(result.getSensitiveInfo().size()).append("\n");
        json.append("  },\n");
        json.append("  \"architecture\": ");
        if (result.getArchitecture() != null) {
            json.append("{\n");
            json.append("    \"framework\": \"").append(result.getArchitecture().getFramework()).append("\",\n");
            json.append("    \"stateManagement\": \"").append(result.getArchitecture().getStateManagement()).append("\",\n");
            json.append("    \"pattern\": \"").append(result.getArchitecture().getPattern()).append("\",\n");
            json.append("    \"confidence\": ").append(result.getArchitecture().getPatternConfidence()).append("\n");
            json.append("  }\n");
        } else {
            json.append("null\n");
        }
        json.append("}\n");
        
        return json.toString();
    }
}
