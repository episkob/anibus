package it.r2u.anibus.service.analysis;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class JwtAnalyzerTest {

    @Test
    void classifiesTokensByRiskAndDeduplicatesThem() {
        JwtAnalyzer analyzer = new JwtAnalyzer();
        long now = Instant.now().getEpochSecond();

        String noneAlg = jwt("{\"alg\":\"none\",\"typ\":\"JWT\"}",
                "{\"sub\":\"1\",\"exp\":" + (now + 3600) + "}");
        String expired = jwt("{\"alg\":\"HS256\"}",
                "{\"sub\":\"2\",\"exp\":" + (now - 60) + "}");
        String missingExp = jwt("{\"alg\":\"HS384\"}",
                "{\"sub\":\"3\"}");
        String weak = jwt("{\"alg\":\"HS256\"}",
                "{\"sub\":\"4\",\"exp\":" + (now + 3600) + "}");
        String valid = jwt("{\"alg\":\"RS256\"}",
                "{\"sub\":\"5\",\"exp\":" + (now + 3600) + "}");
        String suspiciousKid = jwt("{\"alg\":\"RS256\",\"kid\":\"../../etc/passwd\"}",
                "{\"sub\":\"6\",\"exp\":" + (now + 3600) + "}");

        List<JwtAnalyzer.JwtFinding> findings = analyzer.analyzeFromText(
                "prefix " + noneAlg + " " + expired + " " + missingExp + " " + weak + " " + valid + " " + suspiciousKid + " " + noneAlg);

        assertEquals(6, findings.size());
        assertTrue(findings.stream().anyMatch(f -> f.risk() == JwtAnalyzer.JwtRisk.CRITICAL));
        assertTrue(findings.stream().anyMatch(f -> f.risk() == JwtAnalyzer.JwtRisk.HIGH));
        assertTrue(findings.stream().anyMatch(f -> f.risk() == JwtAnalyzer.JwtRisk.MEDIUM));
        assertTrue(findings.stream().anyMatch(f -> f.risk() == JwtAnalyzer.JwtRisk.LOW));
        assertTrue(findings.stream().anyMatch(f -> f.risk() == JwtAnalyzer.JwtRisk.INFO));
        assertTrue(findings.stream().anyMatch(f -> f.suspiciousKid()
                && "../../etc/passwd".equals(f.kid())));

        String report = JwtAnalyzer.formatReport(findings, "sample source");
        assertTrue(report.contains("JWT ANALYSIS: sample source"));
        assertTrue(report.contains("Found 6 JWT token(s)"));
        assertTrue(report.contains("Algorithm is 'none'"));
        assertTrue(report.contains("kid    : ../../etc/passwd"));
    }

    @Test
    void formatsEmptyJwtReport() {
        String report = JwtAnalyzer.formatReport(List.of(), "empty");
        assertTrue(report.contains("JWT ANALYSIS: empty"));
        assertTrue(report.contains("No JWT tokens found"));
    }

    @Test
    void detectsTokenStorageInBrowserStorageApis() {
        JwtAnalyzer analyzer = new JwtAnalyzer();

        List<JwtAnalyzer.JwtFinding> findings = analyzer.analyzeFromText(
                "localStorage.setItem('access_token', token); sessionStorage.getItem(\"jwt\");");

        assertTrue(findings.stream().anyMatch(f -> f.finding().contains("localStorage/sessionStorage")
                && f.finding().contains("access_token")));
        assertTrue(findings.stream().anyMatch(f -> f.finding().contains("localStorage/sessionStorage")
                && f.finding().contains("jwt")));
    }

    private static String jwt(String headerJson, String payloadJson) {
        return encode(headerJson) + "." + encode(payloadJson) + ".sig";
    }

    private static String encode(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}