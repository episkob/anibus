package it.r2u.anibus.model;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class EndpointInfoTest {

    @Test
    void buildsCurlForGetAndPostEndpoints() {
        EndpointInfo getEndpoint = new EndpointInfo(
                "https://example.test/api/search",
                "https://example.test",
                "/api/search",
                "GET",
                List.of("q", "page"),
                Map.of("Authorization", "Bearer token"),
                "test",
                false);

        String getCurl = getEndpoint.toCurlCommand();
        assertTrue(getCurl.contains("curl -X GET"));
        assertTrue(getCurl.contains("Authorization: Bearer token"));
        assertTrue(getCurl.contains("?q=FUZZ&page=FUZZ"));

        EndpointInfo postEndpoint = new EndpointInfo(
                "https://example.test/api/login",
                "https://example.test",
                "/api/login",
                "POST",
                List.of("username", "password"),
                Map.of(),
                "test",
                true);

        String postCurl = postEndpoint.toCurlCommand();
        assertTrue(postCurl.contains("curl -X POST"));
        assertTrue(postCurl.contains("-d 'username=FUZZ&password=FUZZ'"));

        assertTrue(postEndpoint.toString().contains("(dynamic)"));
    }
}