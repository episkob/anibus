package it.r2u.anibus.service.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class ContainerExposureCheckerTest {

    @Test
    void scan_blankHostReturnsEmptyReport() {
        ContainerExposureChecker.ContainerExposureReport r =
            new ContainerExposureChecker().scan("  ");
        assertEquals("", r.target());
        assertTrue(r.findings().isEmpty());
    }

    @Test
    void scan_unreachableHostProducesNoFalsePositives() {
        // 127.0.0.1 with random high port range — none of the well-known
        // container ports listen on a typical developer machine.
        ContainerExposureChecker.ContainerExposureReport r =
            new ContainerExposureChecker().scan("127.0.0.1");
        assertNotNull(r);
        assertEquals("127.0.0.1", r.target());
        // On a developer box none of 2375/2376/6443/8080/10250/10255/2379/4001
        // should produce a HIGH-severity finding without a running orchestrator.
        assertFalse(r.findings().stream()
            .anyMatch(f -> f.severity() == ContainerExposureChecker.Severity.HIGH));
    }

    @Test
    void scan_stripsSchemeAndPathFromTarget() {
        ContainerExposureChecker.ContainerExposureReport r =
            new ContainerExposureChecker().scan("https://example.com:8443/path");
        assertEquals("example.com", r.target());
    }

    @Test
    void formatReport_emptyShowsNoExposureLine() {
        ContainerExposureChecker.ContainerExposureReport r =
            new ContainerExposureChecker.ContainerExposureReport("host.example", List.of());
        String text = ContainerExposureChecker.formatReport(r);
        assertTrue(text.contains("CONTAINER EXPOSURE"));
        assertTrue(text.contains("host.example"));
        assertTrue(text.contains("No exposed"));
    }

    @Test
    void formatReport_withFindingsListsAllAndSeverityCounts() {
        ContainerExposureChecker.ExposureFinding hi = new ContainerExposureChecker.ExposureFinding(
            "Docker Engine API", "http://h:2375/_ping", 200,
            ContainerExposureChecker.Severity.HIGH, "Server: docker");
        ContainerExposureChecker.ExposureFinding med = new ContainerExposureChecker.ExposureFinding(
            "Kubelet", "http://h:10255/pods", 200,
            ContainerExposureChecker.Severity.MEDIUM, "no fingerprint");
        ContainerExposureChecker.ContainerExposureReport r =
            new ContainerExposureChecker.ContainerExposureReport("h",
                List.of(hi, med));
        String text = ContainerExposureChecker.formatReport(r);
        assertTrue(text.contains("HIGH: 1"));
        assertTrue(text.contains("MEDIUM: 1"));
        assertTrue(text.contains("Docker Engine API"));
        assertTrue(text.contains("Kubelet"));
        assertTrue(text.contains("http://h:2375/_ping"));
    }

    @Test
    void countSeverity_aggregatesCorrectly() {
        ContainerExposureChecker.ContainerExposureReport r =
            new ContainerExposureChecker.ContainerExposureReport("h", List.of(
                new ContainerExposureChecker.ExposureFinding("etcd v2 API", "u1", 200,
                    ContainerExposureChecker.Severity.HIGH, ""),
                new ContainerExposureChecker.ExposureFinding("etcd v3 API", "u2", 200,
                    ContainerExposureChecker.Severity.HIGH, ""),
                new ContainerExposureChecker.ExposureFinding("Kubelet", "u3", 200,
                    ContainerExposureChecker.Severity.MEDIUM, "")));
        assertEquals(2, r.countSeverity(ContainerExposureChecker.Severity.HIGH));
        assertEquals(1, r.countSeverity(ContainerExposureChecker.Severity.MEDIUM));
        assertEquals(0, r.countSeverity(ContainerExposureChecker.Severity.INFO));
    }
}
