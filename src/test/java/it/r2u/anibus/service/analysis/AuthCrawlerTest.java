package it.r2u.anibus.service.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthCrawlerTest {

    @Test
    void basicMode_setsAuthorizationHeaderAndReportsSuccess() {
        AuthCrawler ac = new AuthCrawler();
        // Probe unreachable host — just to verify report shape and auth setup.
        AuthCrawler.AuthCrawlReport r = ac.crawlWithBasic(
            "http://127.0.0.1:1", "admin", "secret", List.of("/admin"));
        assertEquals(AuthCrawler.Mode.BASIC, r.mode());
        assertTrue(r.authSucceeded(), "basic mode should always mark auth as configured");
        assertEquals(1, r.probes().size());
    }

    @Test
    void bearerMode_emptyTokenIsReportedAsFailure() {
        AuthCrawler ac = new AuthCrawler();
        AuthCrawler.AuthCrawlReport r = ac.crawlWithBearer("http://127.0.0.1:1", "  ", List.of("/x"));
        assertFalse(r.authSucceeded());
    }

    @Test
    void oauth2_invalidEndpointReturnsFailureReport() {
        AuthCrawler ac = new AuthCrawler();
        AuthCrawler.AuthCrawlReport r = ac.crawlWithOAuth2ClientCredentials(
            "http://127.0.0.1:1", "http://127.0.0.1:1/token",
            "id", "secret", "read", List.of("/"));
        assertFalse(r.authSucceeded());
        assertNotNull(r.authNote());
        assertTrue(r.probes().isEmpty());
    }

    @Test
    void formMode_emptyFieldsHandledGracefully() {
        AuthCrawler ac = new AuthCrawler();
        AuthCrawler.AuthCrawlReport r = ac.crawlWithFormLogin(
            "http://127.0.0.1:1", "http://127.0.0.1:1/login", Map.of(), List.of("/me"));
        assertFalse(r.authSucceeded());
    }

    @Test
    void formatReport_includesModeAndCounts() {
        AuthCrawler.ProbeResult ok = new AuthCrawler.ProbeResult("http://x/a", 200, 123, "OK");
        AuthCrawler.ProbeResult ko = new AuthCrawler.ProbeResult("http://x/b", 401, 0, "Unauthorized");
        AuthCrawler.AuthCrawlReport report = new AuthCrawler.AuthCrawlReport(
            AuthCrawler.Mode.BEARER, "http://x", true, "ok", List.of(ok, ko));
        String text = AuthCrawler.formatReport(report);
        assertTrue(text.contains("BEARER"));
        assertTrue(text.contains("1/2"));
        assertTrue(text.contains("http://x/a"));
        assertTrue(text.contains("[200]"));
        assertTrue(text.contains("[401]"));
    }

    @Test
    void probeResult_isAuthenticatedTreats2xxAnd3xxAsSuccess() {
        assertTrue(new AuthCrawler.ProbeResult("u", 200, 1, "").isAuthenticated());
        assertTrue(new AuthCrawler.ProbeResult("u", 204, 0, "").isAuthenticated());
        assertTrue(new AuthCrawler.ProbeResult("u", 302, 0, "").isAuthenticated());
        assertFalse(new AuthCrawler.ProbeResult("u", 401, 0, "").isAuthenticated());
        assertFalse(new AuthCrawler.ProbeResult("u", 404, 0, "").isAuthenticated());
        assertFalse(new AuthCrawler.ProbeResult("u", 500, 0, "").isAuthenticated());
    }
}
