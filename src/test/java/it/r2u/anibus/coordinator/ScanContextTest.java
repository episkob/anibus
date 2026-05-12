package it.r2u.anibus.coordinator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class ScanContextTest {

    @Test
    void builderSetsFieldsAndDefaultThreadCount() {
        NoopCallbacks callbacks = new NoopCallbacks();

        ScanContext withDefaultThreads = ScanContext.builder()
                .host("example.test")
                .startPort(1)
                .endPort(100)
                .callbacks(callbacks)
                .build();

        assertEquals("example.test", withDefaultThreads.getHost());
        assertEquals(1, withDefaultThreads.getStartPort());
        assertEquals(100, withDefaultThreads.getEndPort());
        assertEquals(10, withDefaultThreads.getThreadCount());
        assertSame(callbacks, withDefaultThreads.getCallbacks());

        ScanContext withCustomThreads = ScanContext.builder()
                .host("example.test")
                .startPort(10)
                .endPort(20)
                .threadCount(64)
                .callbacks(callbacks)
                .build();
        assertEquals(64, withCustomThreads.getThreadCount());
    }

    @Test
    void builderValidatesHostAndCallbacks() {
        IllegalStateException missingHost =
                assertThrows(IllegalStateException.class, () -> ScanContext.builder()
                        .startPort(1)
                        .endPort(2)
                        .callbacks(new NoopCallbacks())
                        .build());
        assertTrue(missingHost.getMessage().contains("Host is required"));

        IllegalStateException missingCallbacks =
                assertThrows(IllegalStateException.class, () -> ScanContext.builder()
                        .host("example.test")
                        .startPort(1)
                        .endPort(2)
                        .build());
        assertTrue(missingCallbacks.getMessage().contains("Callbacks are required"));
    }

    private static final class NoopCallbacks implements ScanContext.ScanCallbacks {
        @Override
        public void onHostResolved(String ip) {}

        @Override
        public void onScanStarted(String ip, String hostname, int totalPorts) {}

        @Override
        public void onResult(it.r2u.anibus.model.PortScanResult result) {}

        @Override
        public void onStatus(String message) {}

        @Override
        public void onCompleted() {}

        @Override
        public void onCancelled() {}

        @Override
        public void onFailed(String error) {}
    }
}
