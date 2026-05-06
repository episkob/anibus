package it.r2u.anibus.service.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class PortScannerServiceTest {

    private final PortScannerService service = new PortScannerService();

    // ── Port range parsing ─────────────────────────────────────────────────

    @Test
    void parsesValidPortRange() {
        int[] range = service.parsePortsRange("1-1024");
        assertNotNull(range);
        assertEquals(1, range[0]);
        assertEquals(1024, range[1]);
    }

    @Test
    void returnsNullForMalformedInput() {
        assertNull(service.parsePortsRange("abc"));
        assertNull(service.parsePortsRange("80"));
        assertNull(service.parsePortsRange(""));
        assertNull(service.parsePortsRange(null));
    }

    @Test
    void returnsNullForInvertedRange() {
        assertNull(service.parsePortsRange("1024-80"));
    }

    @ParameterizedTest
    @CsvSource({"0-100", "1-65536", "0-0"})
    void returnsNullForOutOfBoundsRange(String range) {
        assertNull(service.parsePortsRange(range));
    }

    @Test
    void parsesMaxValidRange() {
        int[] range = service.parsePortsRange("1-65535");
        assertNotNull(range);
        assertEquals(1, range[0]);
        assertEquals(65535, range[1]);
    }

    // ── Version extraction delegation ──────────────────────────────────────

    @Test
    void extractsVersionFromBanner() {
        String result = service.extractVersion("Apache/2.4.51 (Debian)");
        assertNotNull(result);
        assertFalse(result.isBlank());
    }

    @Test
    void returnsEmptyVersionForNullBanner() {
        String result = service.extractVersion(null);
        assertNotNull(result); // must not throw
    }
}
