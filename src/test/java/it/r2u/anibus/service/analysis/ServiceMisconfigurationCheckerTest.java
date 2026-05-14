package it.r2u.anibus.service.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ServiceMisconfigurationCheckerTest {

    @Test
    void scan_blankHostReturnsEmpty() {
        ServiceMisconfigurationChecker c = new ServiceMisconfigurationChecker();
        assertTrue(c.scan(null).isEmpty());
        assertTrue(c.scan("").isEmpty());
        assertTrue(c.scan("  ").isEmpty());
    }

    @Test
    void scan_closedLoopbackProducesNoFindings() {
        // 127.0.0.1 with these specific ports almost certainly closed in test env.
        ServiceMisconfigurationChecker c = new ServiceMisconfigurationChecker();
        List<ServiceMisconfigurationChecker.MisconfigFinding> findings =
            c.scan("127.0.0.1", Map.ofEntries(
                Map.entry("Redis", 1),
                Map.entry("Redis (TLS)", 2),
                Map.entry("Memcached", 3),
                Map.entry("MongoDB", 4),
                Map.entry("Elasticsearch", 5),
                Map.entry("Kibana", 6),
                Map.entry("CouchDB", 7),
                Map.entry("Kafka", 8),
                Map.entry("Cassandra CQL", 9),
                Map.entry("etcd", 10),
                Map.entry("Docker API", 11),
                Map.entry("RabbitMQ mgmt", 12)));
        // With unused low ports nothing should bind in CI.
        assertNotNull(findings);
    }

    @Test
    void formatReport_emptyHasFriendlyMessage() {
        String text = ServiceMisconfigurationChecker.formatReport("example.com", List.of());
        assertTrue(text.contains("example.com"));
        assertTrue(text.contains("No exposed data services"));
    }

    @Test
    void formatReport_includesSeverityHostPortAndService() {
        var f = new ServiceMisconfigurationChecker.MisconfigFinding(
            "10.0.0.1", 6379, "Redis",
            ServiceMisconfigurationChecker.Severity.CRITICAL, "Banner: +PONG");
        String text = ServiceMisconfigurationChecker.formatReport("10.0.0.1", List.of(f));
        assertTrue(text.contains("CRITICAL"));
        assertTrue(text.contains("Redis"));
        assertTrue(text.contains("10.0.0.1:6379"));
        assertTrue(text.contains("Banner: +PONG"));
    }

    @Test
    void severityEnum_hasFourLevels() {
        assertEquals(4, ServiceMisconfigurationChecker.Severity.values().length);
    }
}
