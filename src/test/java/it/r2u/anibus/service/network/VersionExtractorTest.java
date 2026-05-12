package it.r2u.anibus.service.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class VersionExtractorTest {

    @Test
    void extractsKnownBannerVersionsAndHandlesUnknownInput() {
        assertEquals("OpenSSH_8.4p1", VersionExtractor.extract("SSH-2.0-OpenSSH_8.4p1"));
        assertEquals("Apache/2.4.41", VersionExtractor.extract("Server: Apache/2.4.41 (Ubuntu)"));
        assertEquals("vsFTPd 3.0.5", VersionExtractor.extract("220 (vsFTPd 3.0.5)"));
        assertEquals("Postfix", VersionExtractor.extract("Postfix"));
        assertEquals("PHP/8.2.1", VersionExtractor.extract("X-Powered-By: PHP/8.2.1"));
        assertEquals("", VersionExtractor.extract("unknown banner"));
        assertEquals("", VersionExtractor.extract(null));
    }
}