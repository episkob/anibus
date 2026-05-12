package it.r2u.anibus.handlers;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class SecurityAnalysisHandlerTest {

    @Test
    void ensuresHttpUrlAndExtractsHostConsistently() {
        assertEquals("", SecurityAnalysisHandler.ensureHttpUrl(null));
        assertEquals("", SecurityAnalysisHandler.ensureHttpUrl("   "));
        assertEquals("https://example.test", SecurityAnalysisHandler.ensureHttpUrl("example.test"));
        assertEquals("http://example.test/a", SecurityAnalysisHandler.ensureHttpUrl("http://example.test/a"));
        assertEquals("https://example.test/path?q=1", SecurityAnalysisHandler.ensureHttpUrl("https://example.test/path?q=1"));

        assertEquals("", SecurityAnalysisHandler.extractHostOrDomain(null));
        assertEquals("", SecurityAnalysisHandler.extractHostOrDomain("   "));
        assertEquals("example.test", SecurityAnalysisHandler.extractHostOrDomain("https://example.test/a"));
        assertEquals("example.test", SecurityAnalysisHandler.extractHostOrDomain("example.test"));
        assertEquals("not a uri", SecurityAnalysisHandler.extractHostOrDomain("not a uri"));
    }

    @Test
    void resolvesPortFromSupplierOrFallsBackToDefault() throws Exception {
        Method resolvePort = SecurityAnalysisHandler.class
                .getDeclaredMethod("resolvePort", Supplier.class, int.class);
        resolvePort.setAccessible(true);

        assertEquals(443, (int) resolvePort.invoke(null, null, 443));
        assertEquals(443, (int) resolvePort.invoke(null, (Supplier<Integer>) () -> null, 443));
        assertEquals(443, (int) resolvePort.invoke(null, (Supplier<Integer>) () -> 0, 443));
        assertEquals(443, (int) resolvePort.invoke(null, (Supplier<Integer>) () -> -5, 443));
        assertEquals(8443, (int) resolvePort.invoke(null, (Supplier<Integer>) () -> 8443, 443));
    }

    @Test
    void earlyGuardsSetHelpfulStatusMessages() {
        List<String> statuses = new ArrayList<>();

        SecurityAnalysisHandler handler = SecurityAnalysisHandler.builder()
                .targetUrlSupplier(() -> "")
                .targetHostSupplier(() -> "")
                .consoleTextSupplier(() -> "")
                .setStatus(statuses::add)
                .build();

        handler.runJwtAnalysis();
        handler.runCorsCheck();
        handler.runXssScan();

        assertEquals(3, statuses.size());
        assertTrue(statuses.stream().anyMatch(s -> s.contains("Run JS Analysis first")));
        assertTrue(statuses.stream().anyMatch(s -> s.contains("CORS check")));
        assertTrue(statuses.stream().anyMatch(s -> s.contains("XSS scan")));
    }
}
