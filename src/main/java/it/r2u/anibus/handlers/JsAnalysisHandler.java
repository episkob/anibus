package it.r2u.anibus.handlers;

import it.r2u.anibus.model.ArchitectureInfo;
import it.r2u.anibus.model.DataStructureInfo;
import it.r2u.anibus.model.DatabaseSchemaInfo;
import it.r2u.anibus.model.EndpointInfo;
import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.LeakInfo;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.analysis.JavaScriptSecurityAnalyzer;
import it.r2u.anibus.ui.LanguageManager;

import javafx.application.Platform;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.scene.control.*;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Handles JavaScript analysis, SQL injection display, structure tree population,
 * and console mode switching between port scanner and JS analysis modes.
 */
public class JsAnalysisHandler {

    // ── UI components ─────────────────────────────────────────────────────────

    public record UIComponents(
            TextField hostTextField,
            ProgressBar progressBar,
            Button scanButton,
            Button stopButton,
            Button exportButton,
            Button jsExportButton,
            Button clearButton,
            Button jsAnalysisRunButton,
            javafx.scene.layout.VBox jsResultsCard,
            Label jsEndpointsLabel,
            Label jsDataStructuresLabel,
            Label jsDbSchemasLabel,
            Label jsSensitiveInfoLabel,
            Label jsArchitectureLabel,
            TreeView<String> jsStructureTree,
            TextArea jsAnalysisTextArea,
            TextArea consoleTextArea,
            Label consoleHeaderLabel,
            Label resultCountLabel) {}

    private final UIComponents ui;
    private final JavaScriptSecurityAnalyzer jsAnalyzer;
    private final ExportActionHandler exportHandler;
    private final ObservableList<PortScanResult> results;
    private final Consumer<String> statusSetter;
    private final Runnable resetScanUiCallback;

    // ── State ─────────────────────────────────────────────────────────────────

    private Task<Void> jsAnalysisTask;
    private JavaScriptAnalysisResult lastJsAnalysisResult;
    private boolean jsAnalysisInProgress = false;
    private boolean isJsAnalysisMode = false;

    // ── Constructor ───────────────────────────────────────────────────────────

    public JsAnalysisHandler(
            UIComponents ui,
            JavaScriptSecurityAnalyzer jsAnalyzer,
            ExportActionHandler exportHandler,
            ObservableList<PortScanResult> results,
            Consumer<String> statusSetter,
            Runnable resetScanUiCallback) {
        this.ui = ui;
        this.jsAnalyzer = jsAnalyzer;
        this.exportHandler = exportHandler;
        this.results = results;
        this.statusSetter = statusSetter;
        this.resetScanUiCallback = resetScanUiCallback;
    }

    // ── Public accessors ──────────────────────────────────────────────────────

    public boolean isJsAnalysisMode()       { return isJsAnalysisMode; }
    public boolean isJsAnalysisInProgress() { return jsAnalysisInProgress; }
    public Task<Void> getJsAnalysisTask()   { return jsAnalysisTask; }
    public JavaScriptAnalysisResult getLastJsAnalysisResult() { return lastJsAnalysisResult; }

    // ── Public actions ────────────────────────────────────────────────────────

    public void startJsAnalysis() {
        String targetUrl = ui.hostTextField().getText().trim();

        if (targetUrl.isEmpty()) {
            statusSetter.accept("Please enter a target URL");
            return;
        }

        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
            ui.hostTextField().setText(targetUrl);
        }

        jsAnalysisInProgress = true;

        statusSetter.accept("Starting JavaScript analysis...");
        jsAnalysisTask = createJavaScriptAnalysisTask(targetUrl);

        ui.scanButton().setDisable(true);
        if (ui.jsAnalysisRunButton() != null) ui.jsAnalysisRunButton().setDisable(true);
        ui.stopButton().setDisable(false);
        ui.progressBar().setVisible(true);
        ui.jsResultsCard().setVisible(false);

        Thread thread = new Thread(jsAnalysisTask);
        thread.setDaemon(true);
        thread.start();
    }

    public void cancelCurrentTask() {
        if (jsAnalysisInProgress && jsAnalysisTask != null && !jsAnalysisTask.isDone()) {
            jsAnalysisTask.cancel(true);
            jsAnalysisInProgress = false;
        }
    }

    public void onJsExportClick() {
        if (lastJsAnalysisResult != null) {
            exportHandler.exportJavaScriptAnalysis(lastJsAnalysisResult, getJsAnalysisDetails());
        }
    }

    public void onJsClearClick() {
        if (isJsAnalysisMode) {
            ui.consoleTextArea().clear();
            clearJsAnalysisResults();
            statusSetter.accept("JavaScript analysis results cleared");
            switchToPortScannerMode();
        }
    }

    public void refreshResultCountLabel() {
        LanguageManager lm = LanguageManager.getInstance();
        if (isJsAnalysisMode) {
            ui.resultCountLabel().setText(lm.get("result.analysisCompleted"));
        } else {
            int n = results.size();
            ui.resultCountLabel().setText(
                n == 0 ? lm.get("result.noResults") :
                n == 1 ? lm.get("result.onePort") :
                String.format(lm.get("result.manyPorts"), n)
            );
        }
    }

    // ── Private: task creation ────────────────────────────────────────────────

    private Task<Void> createJavaScriptAnalysisTask(String targetUrl) {
        return new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                try {
                    Platform.runLater(() -> statusSetter.accept("Analyzing JavaScript files..."));

                    JavaScriptAnalysisResult result = jsAnalyzer.analyzeTarget(targetUrl, JavaScriptSecurityAnalyzer.AnalysisDepth.COMPREHENSIVE);

                    Platform.runLater(() -> {
                        lastJsAnalysisResult = result;
                        displayJsAnalysisResults(result);
                        statusSetter.accept("JavaScript analysis completed");
                        jsAnalysisInProgress = false;
                        resetScanUiCallback.run();
                    });

                } catch (Exception e) {
                    Platform.runLater(() -> {
                        statusSetter.accept("JavaScript analysis failed: " + e.getMessage());
                        jsAnalysisInProgress = false;
                        resetScanUiCallback.run();
                    });
                }
                return null;
            }
        };
    }

    // ── Private: display results ──────────────────────────────────────────────

    private void displayJsAnalysisResults(JavaScriptAnalysisResult result) {
        ui.jsEndpointsLabel().setText(String.valueOf(result.getEndpoints().size()));
        ui.jsDataStructuresLabel().setText(String.valueOf(result.getDataStructures().size()));
        ui.jsDbSchemasLabel().setText(String.valueOf(result.getDatabaseSchemas().size()));
        ui.jsSensitiveInfoLabel().setText(String.valueOf(result.getSensitiveInfo().size()));
        ui.jsArchitectureLabel().setText(result.getArchitecture() != null ?
            result.getArchitecture().getFramework().toString() : "Unknown");

        populateStructureTree(result.getDataStructures());

        StringBuilder detailedResults = new StringBuilder();
        detailedResults.append(result.getSummary()).append("\n\n");

        detailedResults.append("=== DISCOVERED SOURCES ===\n");
        if (result.getJsFiles() != null && !result.getJsFiles().isEmpty()) {
            result.getJsFiles().forEach(file ->
                detailedResults.append("• ").append(file).append("\n"));
        } else {
            detailedResults.append("• No JavaScript sources found\n");
        }

        detailedResults.append("\n=== ATTACK SURFACE (RISK CLASSIFICATION) ===\n");
        appendAttackSurfaceSection(detailedResults, result);

        detailedResults.append("\n=== DYNAMIC ENDPOINTS (FUZZING TARGETS) ===\n");
        appendDynamicEndpointsSection(detailedResults, result);

        detailedResults.append("\n=== DISCOVERED ENDPOINTS ===\n");
        result.getEndpoints().forEach(endpoint ->
            detailedResults.append("• ").append(endpoint.toString()).append("\n"));

        detailedResults.append("\n=== ENTITY MAP ===\n");
        appendEntityMapSection(detailedResults, result);

        detailedResults.append("\n=== DATA STRUCTURES ===\n");
        result.getDataStructures().forEach(structure ->
            detailedResults.append("• ").append(structure.toString()).append("\n"));

        detailedResults.append("\n=== INFERRED DATABASE SCHEMAS ===\n");
        result.getDatabaseSchemas().forEach(schema ->
            detailedResults.append("• ").append(schema.toString()).append("\n"));

        detailedResults.append("\n=== SCHEMA INFERENCE (DEEP) ===\n");
        appendSchemaInferenceDeepSection(detailedResults, result);

        detailedResults.append("\n=== SENSITIVE INFORMATION ===\n");
        appendSensitiveInfoSection(detailedResults, result.getSensitiveInfo(), result.getArchitecture());

        detailedResults.append("\n=== SENSITIVE DEEP-DIVE ===\n");
        appendSensitiveDeepDiveSection(detailedResults, result);

        detailedResults.append("\n=== DEPENDENCY TREE ===\n");
        appendDependencyTreeSection(detailedResults, result);

        if (result.getArchitecture() != null) {
            detailedResults.append("\n=== ARCHITECTURE ANALYSIS ===\n");
            detailedResults.append("• ").append(result.getArchitecture().toString()).append("\n");
            detailedResults.append("• Services: ").append(result.getArchitecture().getServices()).append("\n");
            detailedResults.append("• Middlewares: ").append(result.getArchitecture().getMiddlewares()).append("\n");
        }

        if (result.getArchitecture() != null && result.getArchitecture().getInfrastructureInfo() != null) {
            ArchitectureInfo.InfrastructureInfo infra = result.getArchitecture().getInfrastructureInfo();
            if (infra.hasFindings()) {
                detailedResults.append("\n=== INFRASTRUCTURE INFERENCE ===\n");

                ArchitectureInfo.InfrastructureInfo.ContainerRuntime cr = infra.getContainerRuntime();
                if (cr != ArchitectureInfo.InfrastructureInfo.ContainerRuntime.NONE &&
                    cr != ArchitectureInfo.InfrastructureInfo.ContainerRuntime.UNKNOWN) {
                    detailedResults.append(String.format("• Containerization : %s (confidence %.0f%%)%n",
                        cr, infra.getContainerConfidence() * 100));
                }

                ArchitectureInfo.InfrastructureInfo.Orchestrator orch = infra.getOrchestrator();
                if (orch != ArchitectureInfo.InfrastructureInfo.Orchestrator.NONE &&
                    orch != ArchitectureInfo.InfrastructureInfo.Orchestrator.UNKNOWN) {
                    detailedResults.append(String.format("• Orchestration    : %s (confidence %.0f%%)%n",
                        orch, infra.getOrchestratorConfidence() * 100));
                }

                ArchitectureInfo.InfrastructureInfo.ProxyGateway pg = infra.getProxyGateway();
                if (pg != ArchitectureInfo.InfrastructureInfo.ProxyGateway.NONE &&
                    pg != ArchitectureInfo.InfrastructureInfo.ProxyGateway.UNKNOWN) {
                    detailedResults.append(String.format("• Proxy/Gateway    : %s%n", pg));
                }

                if (infra.getEvidence() != null && !infra.getEvidence().isEmpty()) {
                    detailedResults.append("• Evidence:\n");
                    infra.getEvidence().forEach(e -> detailedResults.append("    - ").append(e).append("\n"));
                }
            }
        }

        detailedResults.append("\n=== ANALYSIS TIMING ===\n");
        appendAnalysisTimingSection(detailedResults, result);

        if (!result.getErrors().isEmpty()) {
            detailedResults.append("\n=== ERRORS ===\n");
            result.getErrors().forEach(error ->
                detailedResults.append("• ").append(error).append("\n"));
        }

        String output = detailedResults.toString();
        if (ui.jsAnalysisTextArea() != null) {
            ui.jsAnalysisTextArea().setText(output);
            ui.jsAnalysisTextArea().setScrollTop(0);
        }
        ui.jsResultsCard().setVisible(true);

        switchToJsAnalysisMode();
    }

    // ── Private: append sections ──────────────────────────────────────────────

    private void appendAttackSurfaceSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<EndpointInfo> endpoints = result.getEndpoints() != null ? result.getEndpoints() : java.util.Collections.emptyList();
        if (endpoints.isEmpty()) {
            sb.append("  No endpoints discovered.\n");
            return;
        }

        Set<String> authKeywords = Set.of("login", "auth", "password", "qr_auth", "get_anonym_token");
        Set<String> knownExternal = Set.of(
            "tns-counter.ru", "googletagmanager.com", "facebook.net",
            "mail.ru", "top-fwz1.mail.ru", "vk-analytics.net"
        );

        List<EndpointInfo> authEndpoints = new java.util.ArrayList<>();
        Map<String, List<EndpointInfo>> internalServices = new java.util.LinkedHashMap<>();
        Map<String, List<EndpointInfo>> thirdParty = new java.util.LinkedHashMap<>();

        String targetHost = extractHost(result.getTargetUrl());
        String targetRoot = normalizeRootDomain(targetHost);

        for (EndpointInfo ep : endpoints) {
            String urlLower = ep.getUrl() != null ? ep.getUrl().toLowerCase(Locale.ROOT) : "";
            if (authKeywords.stream().anyMatch(urlLower::contains)) {
                authEndpoints.add(ep);
            }

            String host = extractHost(ep.getUrl());
            if (host == null || host.isBlank()) continue;

            if (isInternalServiceHost(host, targetHost, targetRoot)) {
                internalServices.computeIfAbsent(host, k -> new java.util.ArrayList<>()).add(ep);
            }
            if (isThirdPartyHost(host, targetRoot, knownExternal)) {
                thirdParty.computeIfAbsent(host, k -> new java.util.ArrayList<>()).add(ep);
            }
        }

        sb.append("  Auth Endpoints: ").append(authEndpoints.size()).append("\n");
        for (EndpointInfo ep : authEndpoints) {
            sb.append("    • ").append(ep).append("\n");
        }

        sb.append("  Internal Services (microservice subdomains): ").append(internalServices.size()).append("\n");
        internalServices.forEach((host, eps) -> {
            sb.append("    • ").append(host).append("  (").append(eps.size()).append(" endpoint(s))\n");
        });

        sb.append("  Third-party Data Leakage Targets: ").append(thirdParty.size()).append("\n");
        thirdParty.forEach((host, eps) -> {
            sb.append("    • ").append(host).append("  (").append(eps.size()).append(" call(s))\n");
        });

        if (result.getArchitecture() != null) {
            sb.append("  Microservice Map: ");
            List<String> services = result.getArchitecture().getServices();
            sb.append((services == null || services.isEmpty()) ? "none detected" : String.join(", ", services));
            sb.append("\n");

            sb.append("  Middleware Stack: ");
            List<String> mids = result.getArchitecture().getMiddlewares();
            sb.append((mids == null || mids.isEmpty()) ? "none detected" : String.join(", ", mids));
            sb.append("\n");
        }
    }

    private void appendDynamicEndpointsSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<EndpointInfo> endpoints = result.getEndpoints() != null ? result.getEndpoints() : java.util.Collections.emptyList();
        if (endpoints.isEmpty()) {
            sb.append("  No endpoints for dynamic/fuzzing analysis.\n");
            return;
        }

        List<EndpointInfo> dynamic = endpoints.stream().filter(EndpointInfo::isDynamic).toList();
        if (dynamic.isEmpty()) {
            sb.append("  No dynamic URL templates detected.\n");
        } else {
            sb.append("  Dynamic Templates:\n");
            for (EndpointInfo ep : dynamic) {
                String params = (ep.getParameters() == null || ep.getParameters().isEmpty())
                    ? "(params: n/a)"
                    : "(params: " + String.join(", ", ep.getParameters()) + ")";
                sb.append("    • ").append(ep.getHttpMethod()).append(" ")
                    .append(ep.getUrl()).append(" ").append(params).append("\n");
                sb.append("      ").append(ep.toCurlCommand()).append("\n");
            }
        }

        String[] hiddenPanels = {"/bugs?act=reporter", "/settings?f=chgpass", "/al_loader_part_configs.php"};
        sb.append("  Hidden Admin Panels / Internal Tooling:\n");
        boolean found = false;
        for (EndpointInfo ep : endpoints) {
            String u = ep.getUrl() != null ? ep.getUrl().toLowerCase(Locale.ROOT) : "";
            for (String panel : hiddenPanels) {
                if (u.contains(panel.toLowerCase(Locale.ROOT))) {
                    sb.append("    • ").append(ep).append("\n");
                    found = true;
                }
            }
        }
        if (!found) {
            sb.append("    • Not found in discovered endpoint set\n");
        }
    }

    private void appendEntityMapSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<DataStructureInfo> structures = result.getDataStructures() != null ? result.getDataStructures() : java.util.Collections.emptyList();
        if (structures.isEmpty()) {
            sb.append("  No data structures available for entity mapping.\n");
            return;
        }

        Set<String> userFields = Set.of("user_id", "screen_name", "id_iframe_params", "access_token");
        Set<String> mediaFields = Set.of("audio_id", "track_id", "album", "playlist", "duration", "playback_duration");

        List<String> userHits = collectEntityFieldHits(structures, userFields);
        List<String> mediaHits = collectEntityFieldHits(structures, mediaFields);

        sb.append("  User Profile Construction:\n");
        if (userHits.isEmpty()) sb.append("    • No direct user profile fields found\n");
        else userHits.forEach(hit -> sb.append("    • ").append(hit).append("\n"));

        sb.append("  Media & Metadata:\n");
        if (mediaHits.isEmpty()) sb.append("    • No media-specific structures found\n");
        else mediaHits.forEach(hit -> sb.append("    • ").append(hit).append("\n"));

        sb.append("  Error Tracking Structures:\n");
        boolean foundErrorTracking = false;
        for (DataStructureInfo ds : structures) {
            Set<String> keys = ds.getProperties().keySet().stream()
                .map(k -> k.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toSet());
            if (keys.contains("lineno") && keys.contains("colno") && keys.contains("source")) {
                foundErrorTracking = true;
                sb.append("    • ").append(ds.getName())
                    .append(" -> lineno/colno/source present (possible client error report payload)\n");
            }
        }
        if (!foundErrorTracking) {
            sb.append("    • No explicit request_payload with lineno/colno/source detected\n");
        }
    }

    private void appendSchemaInferenceDeepSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<DatabaseSchemaInfo> schemas = result.getDatabaseSchemas() != null ? result.getDatabaseSchemas() : java.util.Collections.emptyList();
        if (schemas.isEmpty()) {
            sb.append("  No inferred schemas.\n");
            return;
        }

        for (DatabaseSchemaInfo schema : schemas) {
            sb.append("  • ").append(schema.getDatabaseType())
                .append(" :: ").append(schema.getTableName())
                .append("  [confidence: ").append(String.format("%.0f%%", schema.getConfidence() * 100)).append("]\n");

            if (!schema.getColumns().isEmpty()) {
                sb.append("      Fields (type inference):\n");
                schema.getColumns().forEach((col, type) ->
                    sb.append("        - ").append(col).append(" : ").append(type).append("\n"));
                appendSchemaSemanticGroups(sb, schema.getColumns());
            }

            if (!schema.getRelationships().isEmpty()) {
                sb.append("      Cross-links / foreign keys:\n");
                schema.getRelationships().forEach(rel ->
                    sb.append("        - ").append(rel).append("\n"));
            }
        }
    }

    private void appendSchemaSemanticGroups(StringBuilder sb, Map<String, String> columns) {
        if (columns == null || columns.isEmpty()) return;

        Set<String> logSessionPattern = Set.of("msg", "loc", "module", "host", "id", "realloc", "lang");
        List<String> matched = new java.util.ArrayList<>();
        for (String key : columns.keySet()) {
            if (logSessionPattern.contains(key.toLowerCase(Locale.ROOT))) {
                matched.add(key + ":" + columns.get(key));
            }
        }
        if (!matched.isEmpty()) {
            sb.append("      Variable relation map (log/session-like payload):\n");
            matched.forEach(m -> sb.append("        - ").append(m).append("\n"));
        }

        List<String> objects = columns.entrySet().stream()
            .filter(e -> "object".equalsIgnoreCase(e.getValue()))
            .map(Map.Entry::getKey).toList();
        List<String> arrays = columns.entrySet().stream()
            .filter(e -> "array".equalsIgnoreCase(e.getValue()))
            .map(Map.Entry::getKey).toList();
        List<String> numbers = columns.entrySet().stream()
            .filter(e -> "number".equalsIgnoreCase(e.getValue()))
            .map(Map.Entry::getKey).toList();

        if (!objects.isEmpty() || !arrays.isEmpty() || !numbers.isEmpty()) {
            sb.append("      Type classes:\n");
            if (!objects.isEmpty()) sb.append("        - object: ").append(String.join(", ", objects)).append("\n");
            if (!arrays.isEmpty()) sb.append("        - array: ").append(String.join(", ", arrays)).append("\n");
            if (!numbers.isEmpty()) sb.append("        - number: ").append(String.join(", ", numbers)).append("\n");
        }
    }

    private void appendSensitiveDeepDiveSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<LeakInfo> leaks = result.getSensitiveInfo() != null ? result.getSensitiveInfo() : java.util.Collections.emptyList();
        if (leaks.isEmpty()) {
            sb.append("  No sensitive findings for deep-dive.\n");
            return;
        }

        int shown = 0;
        for (LeakInfo leak : leaks) {
            if (shown >= 25) break;
            String module = leak.getService() != null ? leak.getService() : inferModuleFromLeak(leak);
            sb.append("  • [").append(module).append("] ")
              .append(leak.getType()).append(" -> ")
              .append(truncate(leak.getValue(), 140));

            if (leak.isPlaceholder()) sb.append("  [Default/Placeholder]");

            if (leak.getType() != null && leak.getType().toLowerCase(Locale.ROOT).contains("access token")) {
                String tokenType = inferTokenType(leak);
                if (tokenType != null) sb.append("  [TokenType: ").append(tokenType).append("]");
            }
            sb.append("\n");
            shown++;
        }

        List<String> historyRoutes = leaks.stream()
            .filter(l -> l.getType() != null && l.getType().toLowerCase(Locale.ROOT).contains("history locations"))
            .map(LeakInfo::getValue)
            .filter(v -> v != null && !v.isBlank())
            .toList();
        if (!historyRoutes.isEmpty()) {
            sb.append("  History Locations:\n");
            historyRoutes.forEach(v -> sb.append("    • ").append(v).append("\n"));
        }
    }

    private void appendDependencyTreeSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        List<LeakInfo> leaks = result.getSensitiveInfo() != null ? result.getSensitiveInfo() : java.util.Collections.emptyList();
        List<DataStructureInfo> structures = result.getDataStructures() != null ? result.getDataStructures() : java.util.Collections.emptyList();
        List<EndpointInfo> endpoints = result.getEndpoints() != null ? result.getEndpoints() : java.util.Collections.emptyList();

        List<LeakInfo> tokenLeaks = leaks.stream()
            .filter(l -> {
                String t = l.getType() != null ? l.getType().toLowerCase(Locale.ROOT) : "";
                String v = l.getValue() != null ? l.getValue().toLowerCase(Locale.ROOT) : "";
                return t.contains("token") || v.contains("access_token");
            })
            .limit(5)
            .toList();

        if (tokenLeaks.isEmpty()) {
            sb.append("  No token-centered dependency chain detected.\n");
            return;
        }

        for (LeakInfo tokenLeak : tokenLeaks) {
            String tokenType = inferTokenType(tokenLeak);
            sb.append("  • Token: ").append(tokenType != null ? tokenType : "generic").append("\n");
            sb.append("    ├─ Leak: ").append(truncate(tokenLeak.getValue(), 110)).append("\n");

            List<EndpointInfo> linkedEndpoints = endpoints.stream()
                .filter(ep -> {
                    String u = ep.getUrl() != null ? ep.getUrl().toLowerCase(Locale.ROOT) : "";
                    String c = ep.getContext() != null ? ep.getContext().toLowerCase(Locale.ROOT) : "";
                    return u.contains("token") || c.contains("token") || c.contains("authorization");
                })
                .limit(3).toList();
            if (!linkedEndpoints.isEmpty()) {
                linkedEndpoints.forEach(ep -> sb.append("    ├─ Endpoint: ").append(ep).append("\n"));
            }

            List<DataStructureInfo> linkedStructures = structures.stream()
                .filter(ds -> ds.getProperties().keySet().stream()
                    .map(k -> k.toLowerCase(Locale.ROOT))
                    .anyMatch(k -> k.contains("token") || k.equals("access_token")))
                .limit(3).toList();
            if (!linkedStructures.isEmpty()) {
                linkedStructures.forEach(ds -> sb.append("    └─ Structure: ").append(ds.getName()).append("\n"));
            }
        }
    }

    private void appendAnalysisTimingSection(StringBuilder sb, JavaScriptAnalysisResult result) {
        sb.append("  Processing time: ").append(result.getAnalysisTime()).append(" ms\n");
        int endpointCount = result.getEndpoints() != null ? result.getEndpoints().size() : 0;
        int structureCount = result.getDataStructures() != null ? result.getDataStructures().size() : 0;
        int leakCount = result.getSensitiveInfo() != null ? result.getSensitiveInfo().size() : 0;
        sb.append("  Scale: endpoints=").append(endpointCount)
            .append(", structures=").append(structureCount)
            .append(", leaks=").append(leakCount).append("\n");
    }

    private void appendSensitiveInfoSection(StringBuilder sb, List<LeakInfo> leaks, ArchitectureInfo arch) {
        if (leaks == null || leaks.isEmpty()) {
            sb.append("  No sensitive information detected.\n");
            return;
        }

        boolean isMicroservices = arch != null
            && arch.getPattern() == ArchitectureInfo.ArchitecturePattern.MICROSERVICES;

        List<LeakInfo> critical  = new java.util.ArrayList<>();
        List<LeakInfo> important = new java.util.ArrayList<>();
        List<LeakInfo> lowRisk   = new java.util.ArrayList<>();

        for (LeakInfo l : leaks) {
            if (l.getPriority() >= 8)      critical.add(l);
            else if (l.getPriority() >= 5) important.add(l);
            else                           lowRisk.add(l);
        }
        java.util.Comparator<LeakInfo> byPriorityDesc = java.util.Comparator
            .comparingInt(LeakInfo::getPriority).reversed()
            .thenComparing(l -> l.getType() != null ? l.getType() : "");
        critical.sort(byPriorityDesc);
        important.sort(byPriorityDesc);
        lowRisk.sort(byPriorityDesc);

        java.util.function.BiConsumer<String, List<LeakInfo>> renderTier =
            (header, items) -> {
                if (items.isEmpty()) return;
                sb.append("\n  ── ").append(header).append(" ").append("─".repeat(Math.max(0, 46 - header.length()))).append("\n");
                if (isMicroservices) {
                    Map<String, List<LeakInfo>> byService = new java.util.LinkedHashMap<>();
                    for (LeakInfo l : items) {
                        String svc = l.getService() != null ? l.getService() : "general";
                        byService.computeIfAbsent(svc, k -> new java.util.ArrayList<>()).add(l);
                    }
                    byService.forEach((svc, svcLeaks) -> {
                        sb.append("    [").append(svc.toUpperCase()).append("]\n");
                        for (LeakInfo l : svcLeaks) renderLeakLine(sb, l);
                    });
                } else {
                    for (LeakInfo l : items) renderLeakLine(sb, l);
                }
            };

        renderTier.accept("Critical (P8–P10)", critical);
        renderTier.accept("Important (P5–P7)", important);
        renderTier.accept("Low Risk (P1–P4)",  lowRisk);
    }

    private void renderLeakLine(StringBuilder sb, LeakInfo leak) {
        String rawValue = leak.getValue() != null ? leak.getValue() : "";
        String conf = switch (leak.getConfidence()) {
            case HIGH   -> "HIGH";
            case MEDIUM -> "MED ";
            case LOW    -> "LOW ";
        };

        sb.append("  [P").append(String.format("%2d", leak.getPriority())).append("] ")
          .append("[").append(conf).append("] ")
          .append(String.format("[RS:%4.1f] ", leak.riskScore()))
          .append(leak.getType()).append(":");

        if (leak.isPlaceholder()) sb.append("  [Default/Placeholder]");
        if (leak.getCount() > 1)  sb.append("  (×").append(leak.getCount()).append(")");

        if (rawValue.contains("\n") || rawValue.length() > 80) {
            sb.append("\n");
            for (String line : rawValue.split("\n", -1)) {
                sb.append("      ").append(line).append("\n");
            }
        } else {
            sb.append(" ").append(rawValue).append("\n");
        }
    }

    // ── Private: JS results clear + SQL display ───────────────────────────────

    private void clearJsAnalysisResults() {
        ui.jsEndpointsLabel().setText("0");
        ui.jsDataStructuresLabel().setText("0");
        ui.jsDbSchemasLabel().setText("0");
        ui.jsSensitiveInfoLabel().setText("0");
        ui.jsArchitectureLabel().setText("-");
        lastJsAnalysisResult = null;
        if (ui.jsStructureTree() != null) ui.jsStructureTree().setRoot(null);
        if (ui.jsAnalysisTextArea() != null) ui.jsAnalysisTextArea().clear();
    }

    private String getJsAnalysisDetails() {
        if (ui.jsAnalysisTextArea() != null && !ui.jsAnalysisTextArea().getText().isBlank()) {
            return ui.jsAnalysisTextArea().getText();
        }
        return ui.consoleTextArea() != null ? ui.consoleTextArea().getText() : "";
    }

    // ── Private: structure tree ───────────────────────────────────────────────

    private void populateStructureTree(List<DataStructureInfo> structures) {
        if (ui.jsStructureTree() == null) return;

        TreeItem<String> root = new TreeItem<>("root");
        root.setExpanded(true);

        Map<DataStructureInfo.DataType, List<DataStructureInfo>> byType = new java.util.LinkedHashMap<>();
        for (DataStructureInfo ds : structures) {
            byType.computeIfAbsent(ds.getType(), k -> new java.util.ArrayList<>()).add(ds);
        }

        for (Map.Entry<DataStructureInfo.DataType, List<DataStructureInfo>> entry : byType.entrySet()) {
            String categoryLabel = entry.getKey().name().replace("_", " ")
                                   + "  (" + entry.getValue().size() + ")";
            TreeItem<String> categoryNode = new TreeItem<>(categoryLabel);
            categoryNode.setExpanded(true);

            for (DataStructureInfo ds : entry.getValue()) {
                int optCount = ds.getOptionalProperties().size();
                String structLabel = ds.getName()
                    + "  — " + ds.getProperties().size() + " fields"
                    + (optCount > 0 ? "  [" + optCount + " optional]" : "");
                TreeItem<String> structNode = new TreeItem<>(structLabel);
                structNode.setExpanded(false);

                for (Map.Entry<String, String> prop : ds.getProperties().entrySet()) {
                    boolean optional = ds.isOptional(prop.getKey());
                    String fieldLabel = prop.getKey() + " : " + prop.getValue()
                        + (optional ? "  [optional]" : "");
                    structNode.getChildren().add(new TreeItem<>(fieldLabel));
                }

                categoryNode.getChildren().add(structNode);
            }
            root.getChildren().add(categoryNode);
        }

        ui.jsStructureTree().setRoot(root);
    }

    // ── Private: mode switching ───────────────────────────────────────────────

    private void switchToJsAnalysisMode() {
        Platform.runLater(() -> {
            LanguageManager lm = LanguageManager.getInstance();
            isJsAnalysisMode = true;
            ui.consoleHeaderLabel().setText(lm.get("console.headerJs"));
            ui.resultCountLabel().setText(lm.get("result.analysisCompleted"));

            ui.exportButton().setVisible(false);
            ui.jsExportButton().setVisible(true);
            ui.jsExportButton().setDisable(false);
            ui.clearButton().setDisable(false);
        });
    }

    public void switchToPortScannerMode() {
        Platform.runLater(() -> {
            LanguageManager lm = LanguageManager.getInstance();
            isJsAnalysisMode = false;
            ui.consoleHeaderLabel().setText(lm.get("console.header"));
            refreshResultCountLabel();

            ui.exportButton().setVisible(true);
            ui.jsExportButton().setVisible(false);

            boolean hasResults = !results.isEmpty();
            ui.clearButton().setDisable(!hasResults);
            ui.exportButton().setDisable(!hasResults);
        });
    }

    // ── Private: utility helpers ──────────────────────────────────────────────

    private List<String> collectEntityFieldHits(List<DataStructureInfo> structures, Set<String> interestingFields) {
        List<String> hits = new java.util.ArrayList<>();
        for (DataStructureInfo ds : structures) {
            for (Map.Entry<String, String> entry : ds.getProperties().entrySet()) {
                String key = entry.getKey().toLowerCase(Locale.ROOT);
                if (interestingFields.contains(key)) {
                    hits.add(ds.getName() + "." + entry.getKey() + " : " + entry.getValue());
                }
            }
        }
        return hits;
    }

    private String inferModuleFromLeak(LeakInfo leak) {
        String combined = (leak.getType() + " " + leak.getValue() + " " + leak.getContext()).toLowerCase(Locale.ROOT);
        if (combined.contains("auth") || combined.contains("login") || combined.contains("token")) return "auth";
        if (combined.contains("payment") || combined.contains("billing") || combined.contains("checkout")) return "payment";
        if (combined.contains("order")) return "order";
        if (combined.contains("cart")) return "cart";
        if (combined.contains("profile") || combined.contains("user")) return "user";
        return "general";
    }

    private String inferTokenType(LeakInfo leak) {
        String combined = (leak.getValue() + " " + leak.getContext());
        String[] markers = {
            "VKSDKGeneralSuperAppToken", "VKSDKRequestSuperAppToken", "SuperAppToken", "Bearer", "JWT", "OAuth"
        };
        for (String marker : markers) {
            if (combined.contains(marker)) return marker;
        }
        return null;
    }

    private static String extractHost(String url) {
        if (url == null || url.isBlank() || !url.startsWith("http")) return null;
        try {
            URI uri = new URI(url);
            return uri.getHost() != null ? uri.getHost().toLowerCase(Locale.ROOT) : null;
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static String normalizeRootDomain(String host) {
        if (host == null || host.isBlank()) return null;
        String[] parts = host.split("\\.");
        if (parts.length < 2) return host;
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private static boolean isInternalServiceHost(String host, String targetHost, String targetRoot) {
        if (host == null) return false;
        if (host.contains(".ms.")) return true;
        if (targetRoot == null) return false;
        return host.endsWith("." + targetRoot) && targetHost != null && !host.equals(targetHost);
    }

    private static boolean isThirdPartyHost(String host, String targetRoot, Set<String> knownExternal) {
        if (host == null) return false;
        for (String external : knownExternal) {
            if (host.endsWith(external)) return true;
        }
        if (targetRoot == null) return false;
        return !host.equals(targetRoot) && !host.endsWith("." + targetRoot);
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max) + "...";
    }
}
