package it.r2u.anibus.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class LeakInfoTest {

    // ── Construction ───────────────────────────────────────────────────────

    @Test
    void fullConstructorSetsAllFields() {
        var leak = new LeakInfo("API Key", "abc123xyz", "context", 7, "auth-service", false);
        assertEquals("API Key",      leak.getType());
        assertEquals("abc123xyz",    leak.getValue());
        assertEquals("context",      leak.getContext());
        assertEquals(7,              leak.getPriority());
        assertEquals("auth-service", leak.getService());
        assertFalse(leak.isPlaceholder());
        assertEquals(1, leak.getCount());
    }

    @Test
    void convenienceConstructorInfersPriorityAndPlaceholder() {
        var real = new LeakInfo("Private Key", "-----BEGIN RSA PRIVATE KEY-----", "ctx");
        assertEquals(10, real.getPriority());
        assertFalse(real.isPlaceholder());
    }

    @Test
    void convenienceConstructorDetectsPlaceholder() {
        var placeholder = new LeakInfo("Password", "password", "ctx");
        assertTrue(placeholder.isPlaceholder());
    }

    // ── Immutable copies ───────────────────────────────────────────────────

    @Test
    void withCountReturnsNewInstanceWithUpdatedCount() {
        var original = new LeakInfo("API Key", "val123456789012345", "ctx", 7, null, false);
        var updated  = original.withCount(5);

        assertNotSame(original, updated);
        assertEquals(1, original.getCount());
        assertEquals(5, updated.getCount());
        assertEquals(original.getValue(), updated.getValue());
    }

    @Test
    void withServiceTagsNewInstance() {
        var leak    = new LeakInfo("JWT", "eyJhbGci...", "ctx");
        var tagged  = leak.withService("payment-service");

        assertNotSame(leak, tagged);
        assertNull(leak.getService());
        assertEquals("payment-service", tagged.getService());
    }

    // ── Priority inference ─────────────────────────────────────────────────

    @Test
    void privateKeyHasMaxPriority() {
        assertEquals(10, LeakInfo.inferPriority("Private Key"));
    }

    @Test
    void connectionWithCredentialsHasMaxPriority() {
        assertEquals(10, LeakInfo.inferPriority("Connection with Credentials"));
    }

    @Test
    void nullTypeDefaultsFiveForPriority() {
        assertEquals(5, LeakInfo.inferPriority(null));
    }

    @Test
    void environmentVariableHasLowPriority() {
        assertEquals(2, LeakInfo.inferPriority("Environment Variable"));
    }

    // ── Placeholder detection ──────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"password", "123456", "test", "admin", "secret", "changeme", "null", "undefined"})
    void commonPlaceholdersAreDetected(String value) {
        assertTrue(LeakInfo.isPlaceholderValue(value));
    }

    @Test
    void compositeCredentialWithPlaceholderPasswordIsDetected() {
        assertTrue(LeakInfo.isPlaceholderValue("Username: admin | Password: incorrect_password"));
    }

    @Test
    void shortValuesArePlaceholders() {
        assertTrue(LeakInfo.isPlaceholderValue("ab"));
    }

    @Test
    void realSecretIsNotPlaceholder() {
        assertFalse(LeakInfo.isPlaceholderValue("sk-Xy7mNpQ3rT9vW2uL8aZ1cF4bD6eH0iJ"));
    }

    @Test
    void nullAndBlankAreNotPlaceholders() {
        assertFalse(LeakInfo.isPlaceholderValue(null));
        assertFalse(LeakInfo.isPlaceholderValue(""));
        assertFalse(LeakInfo.isPlaceholderValue("   "));
    }

    // ── toString ──────────────────────────────────────────────────────────

    @Test
    void toStringFormatsTypeAndValue() {
        var leak = new LeakInfo("API Key", "myKey", "ctx");
        assertEquals("API Key: myKey", leak.toString());
    }
}
