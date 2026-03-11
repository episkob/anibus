package it.r2u.anibus;

import it.r2u.anibus.handlers.ExportActionHandler;
import it.r2u.anibus.model.ArchitectureInfo;
import it.r2u.anibus.model.DataStructureInfo;
import it.r2u.anibus.model.DatabaseSchemaInfo;
import it.r2u.anibus.model.EndpointInfo;
import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.SchemaProbeResult;
import it.r2u.anibus.service.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.service.WebSourceAnalyzer;

import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;

import java.net.URL;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Controller for the JavaScript Security Analysis tab.
 * Handles JS analysis, SQL injection testing, and result display.
 */
public class JsAnalysisController {

    /* -- FXML fields ------------------------------------------ */
    @FXML private TextField   jsTargetUrlField;
    @FXML private Button      jsAnalyzeButton;
    @FXML private Button      jsStopButton;
    @FXML private ProgressBar jsProgressBar;
    @FXML private VBox        jsResultsCard;
    @FXML private Label       jsEndpointsLabel;
    @FXML private Label       jsDataStructuresLabel;
    @FXML private Label       jsDbSchemasLabel;
    @FXML private Label       jsSensitiveInfoLabel;
    @FXML private Label       jsArchitectureLabel;
    @FXML private Label       jsStatusLabel;
    @FXML private Button      jsExportButton;
    @FXML private Button      jsClearButton;
    @FXML private TextArea    consoleTextArea;
    @FXML private TextArea    liveLogArea;

    /* -- State ------------------------------------------------ */
    private Task<Void> jsAnalysisTask;
    private JavaScriptAnalysisResult lastJsAnalysisResult;

    /* -- Services --------------------------------------------- */
    private JavaScriptSecurityAnalyzer jsAnalyzer;
    private ExportActionHandler        exportHandler;

    /* -- External references ---------------------------------- */
    private Consumer<String> statusSetter;

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        jsResultsCard.managedProperty().bind(jsResultsCard.visibleProperty());
    }

    /**
     * Called by the parent controller after FXML loading to inject shared context.
     */
    public void setContext(Consumer<String> statusSetter, URL cssUrl) {
        this.statusSetter = statusSetter;

        jsAnalyzer = new JavaScriptSecurityAnalyzer();
        exportHandler = new ExportActionHandler(this::setStatus, cssUrl);
    }

    /* -- FXML button actions ---------------------------------- */
    @FXML
    void onJsAnalyzeButtonClick() {
        String targetUrl = jsTargetUrlField.getText().trim();

        if (targetUrl.isEmpty()) {
            setStatus("Please enter a target URL");
            return;
        }

        // Add protocol if missing
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
            jsTargetUrlField.setText(targetUrl);
        }

        setStatus("Starting JavaScript analysis...");
        jsAnalysisTask = createJavaScriptAnalysisTask(targetUrl);

        jsAnalyzeButton.setDisable(true);
        jsStopButton.setDisable(false);
        jsProgressBar.setVisible(true);
        jsResultsCard.setVisible(false);

        Thread thread = new Thread(jsAnalysisTask);
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    void onJsStopButtonClick() {
        if (jsAnalysisTask != null && !jsAnalysisTask.isDone()) {
            jsAnalysisTask.cancel(true);
            setStatus("JavaScript analysis stopped");
        }
        resetJsAnalysisUI();
    }

    @FXML
    void onJsExportClick() {
        if (lastJsAnalysisResult != null) {
            exportHandler.exportJavaScriptAnalysis(lastJsAnalysisResult);
        }
    }

    @FXML
    void onJsClearClick() {
        consoleTextArea.clear();
        liveLogArea.clear();
        clearJsAnalysisResults();
        setStatus("JavaScript analysis results cleared");
    }

    /* -- Analysis task ---------------------------------------- */
    private Task<Void> createJavaScriptAnalysisTask(String targetUrl) {
        return new Task<>() {
            @Override
            protected Void call() {
                try {
                    appendLog("Started JS analysis: " + targetUrl);
                    Platform.runLater(() -> setStatus("Analyzing JavaScript files..."));

                    JavaScriptAnalysisResult result = jsAnalyzer.analyzeTarget(
                        targetUrl, JavaScriptSecurityAnalyzer.AnalysisDepth.COMPREHENSIVE);

                    appendLog("JS analysis complete — " + result.getEndpoints().size() +
                            " endpoints, " + result.getDatabaseSchemas().size() +
                            " schemas, " + result.getSensitiveInfo().size() + " sensitive items" +
                            " (" + result.getAnalysisTime() + " ms)");

                    // Probe schemas for real data
                    final Map<String, SchemaProbeResult> probeResults;
                    if (!result.getDatabaseSchemas().isEmpty()) {
                        Platform.runLater(() -> setStatus("Probing discovered schemas for real data..."));
                        appendLog("Probing " + result.getDatabaseSchemas().size() + " schema(s) for live data...");
                        probeResults = jsAnalyzer.probeSchemaData(
                            result.getDatabaseSchemas(), result.getEndpoints(), targetUrl,
                            msg -> { Platform.runLater(() -> setStatus(msg)); appendLog(msg); });
                    } else {
                        appendLog("No DB schemas discovered — skipping schema probe");
                        probeResults = null;
                    }

                    Platform.runLater(() -> {
                        lastJsAnalysisResult = result;
                        displayJsAnalysisResults(result, probeResults);
                        setStatus("JavaScript analysis completed");
                        resetJsAnalysisUI();
                    });
                    appendLog("Analysis complete");

                } catch (Exception e) {
                    appendLog("ERROR: " + e.getMessage());
                    Platform.runLater(() -> {
                        setStatus("JavaScript analysis failed: " + e.getMessage());
                        resetJsAnalysisUI();
                    });
                }
                return null;
            }
        };
    }

    /* -- Display results -------------------------------------- */
    private void displayJsAnalysisResults(JavaScriptAnalysisResult result,
            Map<String, SchemaProbeResult> probeResults) {
        jsEndpointsLabel.setText(String.valueOf(result.getEndpoints().size()));
        jsDataStructuresLabel.setText(String.valueOf(result.getDataStructures().size()));
        jsDbSchemasLabel.setText(String.valueOf(result.getDatabaseSchemas().size()));
        jsSensitiveInfoLabel.setText(String.valueOf(result.getSensitiveInfo().size()));
        jsArchitectureLabel.setText(result.getArchitecture() != null ?
            result.getArchitecture().getFramework().toString() : "Unknown");

        StringBuilder d = new StringBuilder();

        // ═══ HEADER ═══
        d.append("╔══════════════════════════════════════════════════════╗\n");
        d.append("║           JAVASCRIPT SECURITY ANALYSIS              ║\n");
        d.append("╚══════════════════════════════════════════════════════╝\n\n");

        d.append("  Target:   ").append(result.getTargetUrl()).append("\n");
        d.append("  Time:     ").append(result.getAnalysisTime()).append(" ms\n\n");

        // ═══ ARCHITECTURE ═══
        if (result.getArchitecture() != null) {
            ArchitectureInfo arch = result.getArchitecture();
            d.append("┌─── ARCHITECTURE ─────────────────────────────────────\n");

            if (arch.getCms() != null && arch.getCms() != ArchitectureInfo.CMS.UNKNOWN) {
                d.append("│  CMS:           ").append(arch.getCms()).append("\n");
            }
            if (arch.getFramework() != null && arch.getFramework() != ArchitectureInfo.Framework.UNKNOWN) {
                d.append("│  Framework:     ").append(arch.getFramework()).append("\n");
            }
            d.append("│  Architecture:  ").append(arch.getPattern()).append("\n");
            if (arch.getStateManagement() != null && arch.getStateManagement() != ArchitectureInfo.StateManagement.UNKNOWN) {
                d.append("│  State:         ").append(arch.getStateManagement()).append("\n");
            }
            d.append("│  Confidence:    ").append(String.format("%.0f%%", arch.getPatternConfidence() * 100)).append("\n");

            if (arch.getServices() != null && !arch.getServices().isEmpty()) {
                d.append("│  Services:      ").append(String.join(", ", arch.getServices())).append("\n");
            }
            if (arch.getMiddlewares() != null && !arch.getMiddlewares().isEmpty()) {
                d.append("│  Middlewares:    ").append(String.join(", ", arch.getMiddlewares())).append("\n");
            }
            d.append("└──────────────────────────────────────────────────────\n\n");
        }

        // ═══ STATISTICS ═══
        d.append("┌─── STATISTICS ───────────────────────────────────────\n");
        d.append("│  JS Sources:     ").append(result.getJsFiles() != null ? result.getJsFiles().size() : 0).append("\n");
        d.append("│  Endpoints:      ").append(result.getEndpoints().size()).append("\n");
        d.append("│  Data Structs:   ").append(result.getDataStructures().size()).append("\n");
        d.append("│  DB Schemas:     ").append(result.getDatabaseSchemas().size()).append("\n");
        d.append("│  Sensitive Info:  ").append(result.getSensitiveInfo().size()).append("\n");
        d.append("└──────────────────────────────────────────────────────\n\n");

        // ═══ ENDPOINTS ═══
        if (!result.getEndpoints().isEmpty()) {
            d.append("┌─── API ENDPOINTS (").append(result.getEndpoints().size()).append(") ─────────────────────────\n");
            for (EndpointInfo ep : result.getEndpoints()) {
                d.append("│  ").append(padRight(ep.getHttpMethod() != null ? ep.getHttpMethod() : "GET", 6));
                d.append(" ").append(truncate(ep.getUrl(), 100));
                if (ep.isDynamic()) d.append("  ◄ dynamic");
                d.append("\n");
                if (ep.getParameters() != null && !ep.getParameters().isEmpty()) {
                    d.append("│        Params: ").append(String.join(", ", ep.getParameters())).append("\n");
                }
            }
            d.append("└──────────────────────────────────────────────────────\n\n");
        }

        // ═══ DATABASE SCHEMAS ═══
        if (!result.getDatabaseSchemas().isEmpty()) {
            d.append("┌─── DATABASE SCHEMAS (").append(result.getDatabaseSchemas().size()).append(") ───────────────────────\n");
            for (DatabaseSchemaInfo schema : result.getDatabaseSchemas()) {
                d.append("│  ▸ ").append(schema.getDatabaseType()).append(" → ").append(schema.getTableName());
                d.append("  (").append(schema.getColumns().size()).append(" columns, ");
                d.append(String.format("%.0f%%", schema.getConfidence() * 100)).append(" confidence)\n");
                if (!schema.getColumns().isEmpty()) {
                    schema.getColumns().forEach((col, type) ->
                        d.append("│      ").append(padRight(col, 25)).append(" : ").append(type).append("\n"));
                }
                if (!schema.getRelationships().isEmpty()) {
                    d.append("│    Relations: ").append(String.join(", ", schema.getRelationships())).append("\n");
                }

                // Show probed real data if available
                SchemaProbeResult probe = probeResults != null ? probeResults.get(schema.getTableName()) : null;
                if (probe != null && probe.hasData()) {
                    d.append("│\n│    ┌── PROBED DATA ──────────────────────────────\n");
                    for (SchemaProbeResult.ProbeHit hit : probe.getHits()) {
                        d.append("│    │  Source: ").append(truncate(hit.getProbeUrl(), 80))
                         .append("  [HTTP ").append(hit.getStatusCode())
                         .append(", ").append(hit.getTotalResponseKeys()).append(" keys]\n");
                        for (Map.Entry<String, String> entry : hit.getMatchedValues().entrySet()) {
                            d.append("│    │    ").append(padRight(entry.getKey(), 22))
                             .append(" = ").append(truncate(entry.getValue(), 120)).append("\n");
                        }
                    }
                    d.append("│    └─────────────────────────────────────────────\n");
                } else {
                    d.append("│    (no live data retrieved)\n");
                }
                d.append("│\n");
            }
            d.append("└──────────────────────────────────────────────────────\n\n");
        }

        // ═══ SENSITIVE INFORMATION ═══
        if (!result.getSensitiveInfo().isEmpty()) {
            d.append("┌─── SENSITIVE INFORMATION (").append(result.getSensitiveInfo().size()).append(") ────────────────────\n");
            // Group by type
            Map<String, List<WebSourceAnalyzer.LeakInfo>> groupedLeaks = new LinkedHashMap<>();
            for (WebSourceAnalyzer.LeakInfo leak : result.getSensitiveInfo()) {
                groupedLeaks.computeIfAbsent(leak.getType(), k -> new ArrayList<>()).add(leak);
            }
            for (Map.Entry<String, List<WebSourceAnalyzer.LeakInfo>> entry : groupedLeaks.entrySet()) {
                d.append("│\n│  ▸ ").append(entry.getKey()).append(" (").append(entry.getValue().size()).append(")\n");
                for (WebSourceAnalyzer.LeakInfo leak : entry.getValue()) {
                    d.append("│      ").append(cleanLeakValue(leak.getValue())).append("\n");
                }
            }
            d.append("└──────────────────────────────────────────────────────\n\n");
        }

        // ═══ DATA STRUCTURES (summary) ═══
        if (!result.getDataStructures().isEmpty()) {
            d.append("┌─── DATA STRUCTURES (").append(result.getDataStructures().size()).append(") ────────────────────────\n");
            // Group by type
            Map<DataStructureInfo.DataType, List<DataStructureInfo>> groupedDs = new LinkedHashMap<>();
            for (DataStructureInfo ds : result.getDataStructures()) {
                groupedDs.computeIfAbsent(ds.getType(), k -> new ArrayList<>()).add(ds);
            }
            for (Map.Entry<DataStructureInfo.DataType, List<DataStructureInfo>> entry : groupedDs.entrySet()) {
                d.append("│\n│  ▸ ").append(entry.getKey()).append(" (").append(entry.getValue().size()).append(")\n");
                for (DataStructureInfo ds : entry.getValue()) {
                    d.append("│      ").append(padRight(ds.getName(), 30));
                    d.append(" [").append(ds.getProperties().size()).append(" props");
                    if (!ds.getMethods().isEmpty()) d.append(", ").append(ds.getMethods().size()).append(" methods");
                    d.append("]\n");
                }
            }
            d.append("└──────────────────────────────────────────────────────\n\n");
        }

        // ═══ JS SOURCES ═══
        if (result.getJsFiles() != null && !result.getJsFiles().isEmpty()) {
            d.append("┌─── JS SOURCES (").append(result.getJsFiles().size()).append(") ──────────────────────────────\n");
            for (String file : result.getJsFiles()) {
                d.append("│  ").append(file).append("\n");
            }
            d.append("└──────────────────────────────────────────────────────\n\n");
        }

        // ═══ ERRORS ═══
        if (!result.getErrors().isEmpty()) {
            d.append("┌─── ERRORS (").append(result.getErrors().size()).append(") ──────────────────────────────────\n");
            result.getErrors().forEach(err -> d.append("│  ⚠ ").append(err).append("\n"));
            d.append("└──────────────────────────────────────────────────────\n");
        }

        consoleTextArea.setText(d.toString());
        jsResultsCard.setVisible(true);
        jsStatusLabel.setText("Analysis completed");
        jsExportButton.setDisable(false);
        jsClearButton.setDisable(false);
    }

    /**
     * Truncate a string to maxLen, adding "…" if truncated.
     */
    private static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() <= maxLen ? s : s.substring(0, maxLen - 1) + "…";
    }

    /**
     * Pad a string to the right with spaces.
     */
    private static String padRight(String s, int width) {
        if (s == null) s = "";
        return s.length() >= width ? s : s + " ".repeat(width - s.length());
    }

    /**
     * Clean up leak values: extract meaningful part from huge minified JS blobs.
     * Tokens, keys, passwords, and other real credentials are NEVER truncated.
     */
    private static String cleanLeakValue(String value) {
        if (value == null) return "";
        // Strip "[Priority N] " prefix — it's shown in grouping
        String cleaned = value.replaceFirst("^\\[Priority \\d+] ", "");

        // Never truncate structured credential data (pipe-delimited metadata)
        if (cleaned.contains(" | ")) {
            return cleaned;
        }

        // Never truncate short values
        if (cleaned.length() <= 500) {
            return cleaned;
        }

        // For very long values: check if it looks like minified code (lots of braces, semicolons, function keywords)
        String sample = cleaned.substring(0, Math.min(300, cleaned.length()));
        long codeIndicators = sample.chars().filter(c -> c == '{' || c == '}' || c == ';' || c == '(' || c == ')').count();
        boolean looksLikeCode = codeIndicators > 20
                || sample.contains("function(") || sample.contains("function (")
                || sample.contains("var ") || sample.contains("return ")
                || sample.contains(".prototype.") || sample.contains("===");

        if (looksLikeCode) {
            return cleaned.substring(0, 200) + "… [" + cleaned.length() + " chars total]";
        }

        // Not code — show in full (tokens, base64 keys, connection strings, etc.)
        return cleaned;
    }

    /* -- Helpers ---------------------------------------------- */
    private void setStatus(String msg) {
        if (statusSetter != null) {
            statusSetter.accept(msg);
        }
    }

    private static final DateTimeFormatter LOG_TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    void appendLog(String msg) {
        Platform.runLater(() -> {
            if (liveLogArea == null) return;
            liveLogArea.appendText("[" + LocalTime.now().format(LOG_TIME) + "] " + msg + "\n");
        });
    }

    private void resetJsAnalysisUI() {
        Platform.runLater(() -> {
            jsAnalyzeButton.setDisable(false);
            jsStopButton.setDisable(true);
            jsProgressBar.setVisible(false);
        });
    }

    private void clearJsAnalysisResults() {
        jsEndpointsLabel.setText("0");
        jsDataStructuresLabel.setText("0");
        jsDbSchemasLabel.setText("0");
        jsSensitiveInfoLabel.setText("0");
        jsArchitectureLabel.setText("-");
        jsStatusLabel.setText("");
        jsExportButton.setDisable(true);
        jsClearButton.setDisable(true);
        jsResultsCard.setVisible(false);
        lastJsAnalysisResult = null;
    }

    /**
     * Shutdown analyzer resources.
     */
    public void shutdown() {
        if (jsAnalyzer != null) jsAnalyzer.shutdown();
    }
}
