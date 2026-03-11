package it.r2u.anibus.model;

import it.r2u.anibus.service.WebSourceAnalyzer;
import java.util.List;

/**
 * Comprehensive result of JavaScript source code analysis for security research.
 */
public class JavaScriptAnalysisResult {
    
    private final String targetUrl;
    private final long analysisTime;
    private final List<EndpointInfo> endpoints;
    private final List<DataStructureInfo> dataStructures;
    private final List<DatabaseSchemaInfo> databaseSchemas;
    private final List<WebSourceAnalyzer.LeakInfo> sensitiveInfo;
    private final ArchitectureInfo architecture;
    private final List<String> jsFiles;
    private final List<String> errors;
    private final String htmlSource;

    public JavaScriptAnalysisResult(String targetUrl, long analysisTime,
                                  List<EndpointInfo> endpoints,
                                  List<DataStructureInfo> dataStructures,
                                  List<DatabaseSchemaInfo> databaseSchemas,
                                  List<WebSourceAnalyzer.LeakInfo> sensitiveInfo,
                                  ArchitectureInfo architecture,
                                  List<String> jsFiles,
                                  List<String> errors) {
        this(targetUrl, analysisTime, endpoints, dataStructures, databaseSchemas,
                sensitiveInfo, architecture, jsFiles, errors, null);
    }

    public JavaScriptAnalysisResult(String targetUrl, long analysisTime,
                                  List<EndpointInfo> endpoints,
                                  List<DataStructureInfo> dataStructures,
                                  List<DatabaseSchemaInfo> databaseSchemas,
                                  List<WebSourceAnalyzer.LeakInfo> sensitiveInfo,
                                  ArchitectureInfo architecture,
                                  List<String> jsFiles,
                                  List<String> errors,
                                  String htmlSource) {
        this.targetUrl = targetUrl;
        this.analysisTime = analysisTime;
        this.endpoints = endpoints;
        this.dataStructures = dataStructures;
        this.databaseSchemas = databaseSchemas;
        this.sensitiveInfo = sensitiveInfo;
        this.architecture = architecture;
        this.jsFiles = jsFiles;
        this.errors = errors;
        this.htmlSource = htmlSource;
    }

    public String getTargetUrl() { return targetUrl; }
    public long getAnalysisTime() { return analysisTime; }
    public List<EndpointInfo> getEndpoints() { return endpoints; }
    public List<DataStructureInfo> getDataStructures() { return dataStructures; }
    public List<DatabaseSchemaInfo> getDatabaseSchemas() { return databaseSchemas; }
    public List<WebSourceAnalyzer.LeakInfo> getSensitiveInfo() { return sensitiveInfo; }
    public ArchitectureInfo getArchitecture() { return architecture; }
    public List<String> getJsFiles() { return jsFiles; }
    public List<String> getErrors() { return errors; }
    public String getHtmlSource() { return htmlSource; }

    public String getSummary() {
        try {
            String architectureText = "Not analyzed";
            String targetUrlText = "unknown";
            int endpointsCount = 0;
            int dataStructuresCount = 0;
            int databaseSchemasCount = 0;
            int sensitiveInfoCount = 0;
            
            // Safe extraction of all data
            if (targetUrl != null) {
                targetUrlText = targetUrl;
            }
            
            if (endpoints != null) {
                endpointsCount = endpoints.size();
            }
            
            if (dataStructures != null) {
                dataStructuresCount = dataStructures.size();
            }
            
            if (databaseSchemas != null) {
                databaseSchemasCount = databaseSchemas.size();
            }
            
            if (sensitiveInfo != null) {
                sensitiveInfoCount = sensitiveInfo.size();
            }
            
            if (architecture != null) {
                try {
                    architectureText = architecture.toString();
                } catch (Exception e) {
                    architectureText = "Architecture error: " + e.getMessage();
                }
            }
            
            return String.format(
                "Analysis Summary for %s:%n" +
                "- %d endpoints discovered%n" +
                "- %d data structures identified%n" +
                "- %d database tables inferred%n" +
                "- %d sensitive information leaks found%n" +
                "- Architecture: %s%n" +
                "- Analysis time: %d ms",
                targetUrlText,
                endpointsCount,
                dataStructuresCount, 
                databaseSchemasCount,
                sensitiveInfoCount,
                architectureText, 
                analysisTime
            );
        } catch (Exception e) {
            return "Analysis Summary Error: " + e.getMessage() + " for URL: " + (targetUrl != null ? targetUrl : "unknown");
        }
    }
}