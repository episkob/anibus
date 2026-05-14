package it.r2u.anibus.service.analysis;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class NtlmMessagesTest {

    @Test
    void md4_matchesRfc1320TestVector() {
        // RFC 1320 §A.5 test vector: MD4("") = "31d6cfe0d16ae931b73c59d7e0c089c0"
        byte[] empty = NtlmMessages.md4ForTesting(new byte[0]);
        assertEquals("31d6cfe0d16ae931b73c59d7e0c089c0", HexFormat.of().formatHex(empty));
    }

    @Test
    void md4_matchesRfc1320_abcVector() {
        // MD4("abc") = "a448017aaf21d8525fc10ae87aa6729d"
        byte[] abc = NtlmMessages.md4ForTesting("abc".getBytes(StandardCharsets.US_ASCII));
        assertEquals("a448017aaf21d8525fc10ae87aa6729d", HexFormat.of().formatHex(abc));
    }

    @Test
    void type1_hasValidNtlmsspSignatureAndTypeField() {
        byte[] msg = NtlmMessages.type1ForTesting();
        assertTrue(NtlmMessages.signatureOk(msg));
        // Type field at offset 8 is little-endian int = 1
        int type = (msg[8] & 0xff)
            | ((msg[9] & 0xff) << 8)
            | ((msg[10] & 0xff) << 16)
            | ((msg[11] & 0xff) << 24);
        assertEquals(1, type);
    }

    @Test
    void type3_buildsFromMinimalType2() {
        // Build a minimal valid Type-2 message (48 bytes).
        byte[] t2 = new byte[48];
        byte[] sig = "NTLMSSP\0".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(sig, 0, t2, 0, 8);
        t2[8] = 2; // type=2 little-endian
        // server challenge (8 bytes) at offset 24
        byte[] chal = {1, 2, 3, 4, 5, 6, 7, 8};
        System.arraycopy(chal, 0, t2, 24, 8);
        // targetInfo offset=48, length=0
        // (offsets/lengths default to 0 — no targetInfo)

        byte[] t3 = NtlmMessages.type3(t2, "admin", "secret", "WS01", "DOMAIN");
        assertNotNull(t3);
        assertTrue(NtlmMessages.signatureOk(t3));
        // Type field at offset 8 must be 3.
        int type = (t3[8] & 0xff)
            | ((t3[9] & 0xff) << 8)
            | ((t3[10] & 0xff) << 16)
            | ((t3[11] & 0xff) << 24);
        assertEquals(3, type);
        // Resulting message must include UTF-16LE encoded username and domain.
        byte[] userU = "admin".getBytes(StandardCharsets.UTF_16LE);
        byte[] domainU = "DOMAIN".getBytes(StandardCharsets.UTF_16LE);
        assertTrue(containsSubsequence(t3, userU));
        assertTrue(containsSubsequence(t3, domainU));
    }

    @Test
    void signatureOk_rejectsGarbage() {
        assertTrue(!NtlmMessages.signatureOk(new byte[0]));
        assertTrue(!NtlmMessages.signatureOk("garbage1".getBytes(StandardCharsets.US_ASCII)));
    }

    private static boolean containsSubsequence(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    @Test
    void md4_idempotent() {
        byte[] data = "anibus".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(
            NtlmMessages.md4ForTesting(data),
            NtlmMessages.md4ForTesting(data));
    }
}
