package it.r2u.anibus.service.analysis;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class SecretsValidationServiceTest {

    @Test
    void detectsNpmAndDockerHubTokens() {
        SecretsValidationService service = new SecretsValidationService();

        List<SecretsValidationService.ValidationResult> results = service.validateRaw(List.of(
                "npm_abcdefghijklmnopqrstuvwxyz1234567890AB",
                "dckr_pat_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
                "not-a-secret"));

        assertTrue(results.stream().anyMatch(r -> "NPM".equals(r.provider())
                && "Automation Token".equals(r.keyType())));
        assertTrue(results.stream().anyMatch(r -> "Docker".equals(r.provider())
                && "Docker Hub Personal Access Token".equals(r.keyType())));
    }

        @Test
        void detectsPemPrivateKeyBlocks() {
                SecretsValidationService service = new SecretsValidationService();

                List<SecretsValidationService.ValidationResult> results = service.validateRaw(List.of(
                                "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----",
                                "-----BEGIN RSA PRIVATE KEY-----\\nabc\\n-----END RSA PRIVATE KEY-----",
                                "-----BEGIN ENCRYPTED PRIVATE KEY-----\\nabc\\n-----END ENCRYPTED PRIVATE KEY-----"));

                assertTrue(results.stream().anyMatch(r -> "Generic".equals(r.provider())
                                && "Private Key Block (PEM)".equals(r.keyType())));
        }
}
