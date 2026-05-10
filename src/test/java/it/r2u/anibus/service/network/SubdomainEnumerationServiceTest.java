package it.r2u.anibus.service.network;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class SubdomainEnumerationServiceTest {

    @Test
    void formatReportShowsNoResultsMessage() {
        String report = SubdomainEnumerationService.formatReport(List.of(), "example.com");
        assertEquals("No live subdomains found for example.com.", report);
    }

    @Test
    void formatReportIncludesEntriesAndHeader() {
        List<SubdomainEnumerationService.SubdomainResult> results = List.of(
                new SubdomainEnumerationService.SubdomainResult("api.example.com", "1.2.3.4", "crt.sh"),
                new SubdomainEnumerationService.SubdomainResult("dev.example.com", "5.6.7.8", "brute-force")
        );

        String report = SubdomainEnumerationService.formatReport(results, "example.com");

        assertTrue(report.contains("Subdomain Enumeration: example.com"));
        assertTrue(report.contains("api.example.com"));
        assertTrue(report.contains("dev.example.com"));
        assertTrue(report.contains("[crt.sh]"));
        assertTrue(report.contains("[brute-force]"));
    }
}
