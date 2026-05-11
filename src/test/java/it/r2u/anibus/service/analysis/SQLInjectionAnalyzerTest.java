package it.r2u.anibus.service.analysis;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import it.r2u.anibus.model.EndpointInfo;

class SQLInjectionAnalyzerTest {

    @Test
    void loadsPayloadCategoriesFromResources() {
        SQLInjectionAnalyzer analyzer = new SQLInjectionAnalyzer();

        // If resource loading fails, analyzer falls back to 4 hardcoded payloads.
        assertTrue(analyzer.getPayloadCount() > 4,
                "Expected payloads from resource files, not only fallback defaults");
    }

    @Test
    void loadsCmsProfilesFromResources() {
        SQLInjectionAnalyzer analyzer = new SQLInjectionAnalyzer();

        var cmsTypes = analyzer.getSupportedCmsTypes();
        assertTrue(cmsTypes.contains("WordPress"));
        assertTrue(cmsTypes.contains("Generic"));
        assertTrue(cmsTypes.size() >= 5);
    }

    @Test
    void generatesCmsEndpointsForWordPress() {
        SQLInjectionAnalyzer analyzer = new SQLInjectionAnalyzer();

        List<EndpointInfo> endpoints = analyzer.generateCmsEndpoints("WordPress", "https://example.com");

        assertFalse(endpoints.isEmpty());
        assertTrue(endpoints.stream().allMatch(e -> e.getUrl() != null && !e.getUrl().isBlank()));
        assertTrue(endpoints.stream().anyMatch(e -> e.getContext() != null && e.getContext().contains("WordPress")));
    }
}
