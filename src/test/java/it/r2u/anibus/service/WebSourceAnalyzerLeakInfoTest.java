package it.r2u.anibus.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class WebSourceAnalyzerLeakInfoTest {

    @Test
    void detectsPlaceholderForCompositeCredentialValues() {
        String composite = "Username: admin | Password: incorrect_password";
        assertTrue(WebSourceAnalyzer.LeakInfo.isPlaceholderValue(composite));
    }

    @Test
    void detectsPlaceholderForExactPasswordToken() {
        assertTrue(WebSourceAnalyzer.LeakInfo.isPlaceholderValue("password"));
    }

    @Test
    void doesNotMarkStrongCredentialAsPlaceholder() {
        String nonPlaceholder = "Username: admin | Password: S3cureProdKey_2026";
        assertFalse(WebSourceAnalyzer.LeakInfo.isPlaceholderValue(nonPlaceholder));
    }
}
