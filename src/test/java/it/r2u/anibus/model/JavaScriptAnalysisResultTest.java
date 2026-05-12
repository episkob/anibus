package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class JavaScriptAnalysisResultTest {

    @Test
    void summaryHandlesNullCollectionsAndReportsCounts() {
        JavaScriptAnalysisResult result = new JavaScriptAnalysisResult(
                "https://example.test",
                1234L,
                List.of(new EndpointInfo("https://example.test/api", "https://example.test", "/api", "GET", List.of("id"), Map.of(), "ctx", false)),
                List.of(new DataStructureInfo("Req", DataStructureInfo.DataType.REQUEST_PAYLOAD, Map.of("id", "number"), List.of(), "ctx", false)),
                List.of(new DatabaseSchemaInfo("users", DatabaseSchemaInfo.DatabaseType.SQL, Map.of("id", "number"), List.of(), List.of(), "ctx", 0.9)),
                List.of(),
                null,
                List.of("https://example.test/app.js"),
                List.of());

        String summary = result.getSummary();
        assertTrue(summary.contains("Analysis Summary for https://example.test"));
        assertTrue(summary.contains("1 endpoints discovered"));
        assertTrue(summary.contains("1 data structures identified"));
        assertTrue(summary.contains("1 database tables inferred"));
        assertTrue(summary.contains("Analysis time: 1234 ms"));
    }

    @Test
    void summarySurvivesBrokenArchitectureToString() {
        ArchitectureInfo brokenArchitecture = new ArchitectureInfo(
                ArchitectureInfo.ArchitecturePattern.UNKNOWN,
                ArchitectureInfo.StateManagement.UNKNOWN,
                ArchitectureInfo.Framework.UNKNOWN,
                ArchitectureInfo.CMS.UNKNOWN,
                List.of(),
                Map.of(),
                List.of(),
                "ctx",
                0.1) {
            @Override
            public String toString() {
                throw new RuntimeException("boom");
            }
        };

        JavaScriptAnalysisResult result = new JavaScriptAnalysisResult(
                "https://example.test",
                1L,
                null,
                null,
                null,
                null,
                brokenArchitecture,
                List.of(),
                List.of());

        String summary = result.getSummary();
        assertTrue(summary.contains("Architecture error: boom"));
    }
}