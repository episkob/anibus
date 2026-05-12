package it.r2u.anibus.service.detection;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class OSDetectorTest {

    @Test
    void detectsCommonOperatingSystemsFromBanners() {
        OSDetector.OSInfo linux = OSDetector.detectFromBanner("Ubuntu Linux 5.15.0-91-generic");
        assertEquals("Ubuntu Linux", linux.getOsName());
        assertEquals("5.15.0-91-generic", linux.getKernelVersion());

        OSDetector.OSInfo windows = OSDetector.detectFromBanner("Microsoft Windows Server 2019");
        assertEquals("Windows Server 2019", windows.getOsName());

        OSDetector.OSInfo freebsd = OSDetector.detectFromBanner("FreeBSD 13.2-RELEASE");
        assertEquals("FreeBSD", freebsd.getOsName());
        assertEquals("13.2", freebsd.getKernelVersion());

        OSDetector.OSInfo mac = OSDetector.detectFromBanner("Darwin 23.1.0 macOS");
        assertEquals("macOS", mac.getOsName());

        OSDetector.OSInfo cisco = OSDetector.detectFromBanner("Cisco IOS Software");
        assertEquals("Cisco IOS", cisco.getOsName());

        OSDetector.OSInfo unixLike = OSDetector.detectFromBanner("Some Unix appliance");
        assertEquals("Unix-like", unixLike.getOsName());

        assertNull(OSDetector.detectFromBanner("mystery banner"));

        OSDetector.OSInfo preferred = OSDetector.detectOS("example.invalid", "Windows 11");
        assertEquals("Windows 11", preferred.getOsName());
        assertTrue(preferred.getConfidence() >= 90);
    }

    @Test
    void mapsTtlValuesToExpectedOsFamiliesViaPrivateHelper() throws Exception {
        Method method = OSDetector.class.getDeclaredMethod("analyzeOSFromTTL", int.class, String.class);
        method.setAccessible(true);

        assertEquals("Linux/Unix", invoke(method, 64).getOsName());
        assertEquals("Windows", invoke(method, 128).getOsName());
        assertEquals("Cisco IOS/Network Device", invoke(method, 254).getOsName());
        assertEquals("Windows 95/98", invoke(method, 31).getOsName());
        assertEquals("AIX/BSD", invoke(method, 205).getOsName());
        assertEquals("Unknown", invoke(method, 10).getOsName());
    }

    private static OSDetector.OSInfo invoke(Method method, int ttl) throws Exception {
        return (OSDetector.OSInfo) method.invoke(null, ttl, "TTL Analysis");
    }
}