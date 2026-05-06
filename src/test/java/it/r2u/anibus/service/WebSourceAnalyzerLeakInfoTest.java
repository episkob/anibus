package it.r2u.anibus.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import it.r2u.anibus.model.LeakInfo;
import org.junit.jupiter.api.Test;

class WebSourceAnalyzerLeakInfoTest {

    @Test
    void detectsPlaceholderForCompositeCredentialValues() {
        String composite = "Username: admin | Password: incorrect_password";
        assertTrue(LeakInfo.isPlaceholderValue(composite));
    }

    @Test
    void detectsPlaceholderForExactPasswordToken() {
        assertTrue(LeakInfo.isPlaceholderValue("password"));
    }

    @Test
    void doesNotMarkStrongCredentialAsPlaceholder() {
        String nonPlaceholder = "Username: admin | Password: S3cureProdKey_2026";
        assertFalse(LeakInfo.isPlaceholderValue(nonPlaceholder));
    }
}
