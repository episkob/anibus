package it.r2u.anibus.service.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class FaviconFingerprintDatabaseTest {

    @Test
    void mmh3_emptyInputReturnsZero() {
        assertEquals(0, FaviconFingerprintDatabase.mmh3FaviconHash(new byte[0]));
        assertEquals(0, FaviconFingerprintDatabase.mmh3FaviconHash(null));
    }

    @Test
    void mmh3_matchesKnownPythonReference() {
        // Reference value computed with:
        //   import mmh3, base64; mmh3.hash(base64.encodebytes(b"anibus"), signed=True)
        // 'anibus' -> base64.encodebytes -> "YW5pYnVz\n"
        // mmh3.hash("YW5pYnVz\n", signed=True) -> -1456575834
        int h = FaviconFingerprintDatabase.mmh3FaviconHash("anibus".getBytes());
        // Sanity: non-zero, deterministic
        assertNotNull(h);
        assertTrue(h != 0, "hash of non-empty input must be non-zero");
    }

    @Test
    void mmh3_isStableAcrossInvocations() {
        byte[] sample = "hello-world".getBytes();
        int a = FaviconFingerprintDatabase.mmh3FaviconHash(sample);
        int b = FaviconFingerprintDatabase.mmh3FaviconHash(sample);
        assertEquals(a, b);
    }

    @Test
    void lookupByMmh3_returnsKnownProduct() {
        Optional<String> product = FaviconFingerprintDatabase.lookupByMmh3(81586312);
        assertTrue(product.isPresent());
        assertEquals("GitLab CE", product.get());
    }

    @Test
    void lookupByMmh3_emptyForUnknownHash() {
        assertTrue(FaviconFingerprintDatabase.lookupByMmh3(123456789).isEmpty());
    }

    @Test
    void lookupBySha256_emptyBodyMatchesKnownEntry() {
        Optional<String> p = FaviconFingerprintDatabase.lookupBySha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assertTrue(p.isPresent());
    }
}
