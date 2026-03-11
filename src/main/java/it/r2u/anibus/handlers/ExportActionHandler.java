package it.r2u.anibus.handlers;

import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.ExportService;
import it.r2u.anibus.ui.AlertHelper;
import javafx.collections.ObservableList;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.DialogPane;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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
     * Export JavaScript analysis results to file — dialog with Text / JSON buttons,
     * matching the port-scanner export UX.
     */
    public void exportJavaScriptAnalysis(JavaScriptAnalysisResult result) {
        ButtonType textBtn  = new ButtonType("Text");
        ButtonType jsonBtn  = new ButtonType("JSON");
        ButtonType cancel   = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);

        Alert fmt = new Alert(Alert.AlertType.NONE, "Choose export format:", textBtn, jsonBtn, cancel);
        fmt.setTitle("Export Format");
        fmt.setHeaderText(null);
        styleDialog(fmt.getDialogPane());

        fmt.showAndWait().ifPresent(choice -> {
            if (choice == cancel) return;
            boolean isText = (choice == textBtn);
            File file = pickJsExportFile(isText);
            if (file == null) return;
            try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
                if (isText) writeTextExport(pw, result); else writeJsonExport(pw, result);
                statusSetter.accept("JavaScript analysis exported to " + file.getName());
            } catch (IOException e) {
                AlertHelper.show("Export failed", e.getMessage(), Alert.AlertType.ERROR, cssUrl);
            }
        });
    }

    private File pickJsExportFile(boolean isText) {
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        FileChooser fc = new FileChooser();
        fc.setTitle("Export JavaScript Analysis");
        if (isText) {
            fc.setInitialFileName("anibus-js-analysis-" + stamp + ".txt");
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        } else {
            fc.setInitialFileName("anibus-js-analysis-" + stamp + ".json");
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("JSON Files", "*.json"));
        }
        return fc.showSaveDialog(null);
    }

    private void styleDialog(DialogPane dp) {
        if (cssUrl != null) dp.getStylesheets().add(cssUrl.toExternalForm());
        dp.getStyleClass().add("anibus-dialog");
    }

    /* ── Text export ─────────────────────────────────────────── */

    private void writeTextExport(PrintWriter pw, JavaScriptAnalysisResult result) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        pw.println("JavaScript Security Analysis Report");
        pw.println("=====================================");
        pw.println();
        pw.println("Target: " + result.getTargetUrl());
        pw.println("Analysis Date: " + ts);
        pw.println("Analysis Time: " + result.getAnalysisTime() + " ms");
        pw.println();
        pw.println(result.getSummary());
        pw.println();

        pw.println("DISCOVERED ENDPOINTS");
        pw.println("===================");
        result.getEndpoints().forEach(ep -> {
            pw.print("• " + ep.getHttpMethod() + " " + ep.getUrl());
            if (ep.isDynamic()) pw.print(" (dynamic)");
            pw.println();
        });

        pw.println();
        pw.println("DATA STRUCTURES");
        pw.println("===============");
        result.getDataStructures().forEach(ds -> {
            pw.println("• " + ds.getName() + " (" + ds.getType() + ")");
            ds.getProperties().forEach((k, v) -> pw.println("  - " + k + ": " + v));
        });

        pw.println();
        pw.println("DATABASE SCHEMAS");
        pw.println("================");
        result.getDatabaseSchemas().forEach(schema -> {
            pw.println("• " + schema.getTableName() + " (" + schema.getDatabaseType()
                    + ", " + String.format("%.0f", schema.getConfidence() * 100) + "% confidence)");
            schema.getColumns().forEach((col, type) -> pw.println("  - " + col + ": " + type));
        });

        pw.println();
        pw.println("SENSITIVE INFORMATION");
        pw.println("====================");
        result.getSensitiveInfo().forEach(leak ->
                pw.println("• " + leak.getType() + ": " + leak.getValue()));

        if (result.getArchitecture() != null) {
            pw.println();
            pw.println("ARCHITECTURE ANALYSIS");
            pw.println("====================");
            pw.println("Framework: " + result.getArchitecture().getFramework());
            pw.println("State Management: " + result.getArchitecture().getStateManagement());
            pw.println("Pattern: " + result.getArchitecture().getPattern());
            pw.println("Services: " + result.getArchitecture().getServices());
            pw.println("Middlewares: " + result.getArchitecture().getMiddlewares());
        }

        if (!result.getErrors().isEmpty()) {
            pw.println();
            pw.println("ERRORS");
            pw.println("======");
            result.getErrors().forEach(err -> pw.println("• " + err));
        }
    }

    /* ── JSON export ─────────────────────────────────────────── */

    private void writeJsonExport(PrintWriter pw, JavaScriptAnalysisResult result) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));
        pw.println("{");
        pw.println("  \"targetUrl\": " + j(result.getTargetUrl()) + ",");
        pw.println("  \"analysisTime\": " + result.getAnalysisTime() + ",");
        pw.println("  \"timestamp\": " + j(ts) + ",");

        // Architecture
        pw.print("  \"architecture\": ");
        if (result.getArchitecture() != null) {
            pw.println("{");
            pw.println("    \"framework\": " + j(String.valueOf(result.getArchitecture().getFramework())) + ",");
            pw.println("    \"stateManagement\": " + j(String.valueOf(result.getArchitecture().getStateManagement())) + ",");
            pw.println("    \"pattern\": " + j(String.valueOf(result.getArchitecture().getPattern())) + ",");
            pw.println("    \"confidence\": " + result.getArchitecture().getPatternConfidence());
            pw.println("  },");
        } else {
            pw.println("null,");
        }

        // Endpoints
        pw.println("  \"endpoints\": [");
        var endpoints = result.getEndpoints();
        for (int i = 0; i < endpoints.size(); i++) {
            var ep = endpoints.get(i);
            pw.print("    { \"method\": " + j(ep.getHttpMethod()) + ", \"url\": " + j(ep.getUrl())
                    + ", \"dynamic\": " + ep.isDynamic());
            if (ep.getParameters() != null && !ep.getParameters().isEmpty()) {
                pw.print(", \"params\": [");
                for (int p = 0; p < ep.getParameters().size(); p++) {
                    if (p > 0) pw.print(", ");
                    pw.print(j(ep.getParameters().get(p)));
                }
                pw.print("]");
            }
            pw.println(" }" + (i < endpoints.size() - 1 ? "," : ""));
        }
        pw.println("  ],");

        // Data structures
        pw.println("  \"dataStructures\": [");
        var structs = result.getDataStructures();
        for (int i = 0; i < structs.size(); i++) {
            var ds = structs.get(i);
            pw.print("    { \"name\": " + j(ds.getName()) + ", \"type\": " + j(String.valueOf(ds.getType()))
                    + ", \"properties\": {");
            int pi = 0;
            for (var entry : ds.getProperties().entrySet()) {
                if (pi++ > 0) pw.print(", ");
                pw.print(j(entry.getKey()) + ": " + j(entry.getValue()));
            }
            pw.println("} }" + (i < structs.size() - 1 ? "," : ""));
        }
        pw.println("  ],");

        // Database schemas
        pw.println("  \"databaseSchemas\": [");
        var schemas = result.getDatabaseSchemas();
        for (int i = 0; i < schemas.size(); i++) {
            var s = schemas.get(i);
            pw.print("    { \"table\": " + j(s.getTableName()) + ", \"type\": " + j(String.valueOf(s.getDatabaseType()))
                    + ", \"confidence\": " + s.getConfidence() + ", \"columns\": {");
            int ci = 0;
            for (var entry : s.getColumns().entrySet()) {
                if (ci++ > 0) pw.print(", ");
                pw.print(j(entry.getKey()) + ": " + j(entry.getValue()));
            }
            pw.print("}");
            if (!s.getRelationships().isEmpty()) {
                pw.print(", \"relationships\": [");
                for (int r = 0; r < s.getRelationships().size(); r++) {
                    if (r > 0) pw.print(", ");
                    pw.print(j(s.getRelationships().get(r)));
                }
                pw.print("]");
            }
            pw.println(" }" + (i < schemas.size() - 1 ? "," : ""));
        }
        pw.println("  ],");

        // Sensitive info
        pw.println("  \"sensitiveInfo\": [");
        var leaks = result.getSensitiveInfo();
        for (int i = 0; i < leaks.size(); i++) {
            var l = leaks.get(i);
            pw.println("    { \"type\": " + j(l.getType()) + ", \"value\": " + j(l.getValue())
                    + " }" + (i < leaks.size() - 1 ? "," : ""));
        }
        pw.println("  ],");

        // JS sources
        pw.println("  \"jsSources\": [");
        var files = result.getJsFiles();
        if (files != null) {
            for (int i = 0; i < files.size(); i++) {
                pw.println("    " + j(files.get(i)) + (i < files.size() - 1 ? "," : ""));
            }
        }
        pw.println("  ],");

        // Errors
        pw.println("  \"errors\": [");
        var errors = result.getErrors();
        for (int i = 0; i < errors.size(); i++) {
            pw.println("    " + j(errors.get(i)) + (i < errors.size() - 1 ? "," : ""));
        }
        pw.println("  ]");
        pw.println("}");
    }

    /** JSON-safe string quoting. */
    private static String j(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
}
