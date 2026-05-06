package it.r2u.anibus.service.analysis;

import it.r2u.anibus.model.LeakInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class WebSourceAnalyzerTest {

    // ── Database connection strings ────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
        "mongodb://user:pass@mongo.example.com:27017/mydb",
        "postgresql://user:secret@db.example.com:5432/app",
        "redis://default:token123@redis.example.com:6379"
    })
    void detectsDatabaseConnectionStrings(String source) {
        List<LeakInfo> leaks = WebSourceAnalyzer.analyzeSource(source);
        assertFalse(leaks.isEmpty(), "Should detect leak in: " + source);
    }

    @Test
    void detectsMongoDbConnection() {
        String js = "const db = 'mongodb://admin:realpass123@mongo.prod.internal:27017/users';";
        List<LeakInfo> leaks = WebSourceAnalyzer.analyzeSource(js);
        assertTrue(leaks.stream().anyMatch(l -> l.getType().contains("MongoDB")));
    }

    @Test
    void detectsAwsAccessKey() {
        String js = "const key = 'AKIAIOSFODNN7EXAMPLE';";
        List<LeakInfo> leaks = WebSourceAnalyzer.analyzeSource(js);
        assertTrue(leaks.stream().anyMatch(l -> l.getType().contains("AWS")));
    }

    @Test
    void detectsInternalIpAddress() {
        String js = "const host = '192.168.1.100';";
        List<LeakInfo> leaks = WebSourceAnalyzer.analyzeSource(js);
        assertTrue(leaks.stream().anyMatch(l -> l.getType().contains("Internal IP")));
    }

    @Test
    void cleanSourceProducesNoLeaks() {
        String js = "const x = 5; function add(a, b) { return a + b; }";
        List<LeakInfo> leaks = WebSourceAnalyzer.analyzeSource(js);
        assertTrue(leaks.isEmpty(), "Clean JS should not produce leaks");
    }

    @Test
    void emptySourceProducesNoLeaks() {
        List<LeakInfo> leaks = WebSourceAnalyzer.analyzeSource("");
        assertNotNull(leaks);
        assertTrue(leaks.isEmpty());
    }
}
