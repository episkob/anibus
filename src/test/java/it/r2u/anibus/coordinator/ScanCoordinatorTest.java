package it.r2u.anibus.coordinator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;

class ScanCoordinatorTest {

    @Test
    void enforcesStrategySelectionAndDelegatesExecution() {
        ScanCoordinator coordinator = new ScanCoordinator();
        ScanContext context = ScanContext.builder()
                .host("example.test")
                .startPort(1)
                .endPort(10)
                .callbacks(new NoopCallbacks())
                .build();

        IllegalStateException noStrategy =
            assertThrows(IllegalStateException.class, () -> coordinator.executeScan(context));
        assertTrue(noStrategy.getMessage().contains("No strategy"));

        IllegalStateException noProgress =
            assertThrows(IllegalStateException.class, coordinator::progressProperty);
        assertTrue(noProgress.getMessage().contains("No strategy"));

        IllegalArgumentException unknown =
            assertThrows(IllegalArgumentException.class, () -> coordinator.setActiveStrategy("missing"));
        assertTrue(unknown.getMessage().contains("Unknown strategy"));

        FakeStrategy strategy = new FakeStrategy("[SD]");
        coordinator.registerStrategy("Service Detection", strategy);
        coordinator.setActiveStrategy("Service Detection");

        coordinator.executeScan(context);
        assertSame(context, strategy.lastContext);
        assertTrue(coordinator.isScanning());
        assertEquals("Service Detection", coordinator.getCurrentStrategyName());
        assertEquals("[SD]", coordinator.getCurrentStatusPrefix());
        assertSame(strategy.progress, coordinator.progressProperty());

        coordinator.cancelScan();
        assertTrue(strategy.cancelCalled);
        assertFalse(coordinator.isScanning());

        coordinator.shutdown();
        assertTrue(strategy.shutdownCalled);
        IllegalArgumentException afterShutdown =
            assertThrows(IllegalArgumentException.class, () -> coordinator.setActiveStrategy("Service Detection"));
        assertTrue(afterShutdown.getMessage().contains("Unknown strategy"));
    }

    @Test
    void returnsKnownAndUnknownDescriptions() {
        ScanCoordinator coordinator = new ScanCoordinator();

        assertTrue(coordinator.getStrategyDescription("Standard Scanning").contains("Basic TCP"));
        assertTrue(coordinator.getStrategyDescription("Service Detection").contains("Enhanced service"));
        assertEquals("Unknown scan mode", coordinator.getStrategyDescription("Other"));
    }

    private static final class FakeStrategy implements ScanStrategy {
        private final DoubleProperty progress = new SimpleDoubleProperty(0.5);
        private final String statusPrefix;
        private ScanContext lastContext;
        private boolean running;
        private boolean cancelCalled;
        private boolean shutdownCalled;

        private FakeStrategy(String statusPrefix) {
            this.statusPrefix = statusPrefix;
        }

        @Override
        public void executeScan(ScanContext context) {
            this.lastContext = context;
            this.running = true;
        }

        @Override
        public void cancel() {
            this.cancelCalled = true;
            this.running = false;
        }

        @Override
        public boolean isRunning() {
            return running;
        }

        @Override
        public DoubleProperty progressProperty() {
            return progress;
        }

        @Override
        public String getStrategyName() {
            return "fake";
        }

        @Override
        public String getStatusPrefix() {
            return statusPrefix;
        }

        @Override
        public void shutdown() {
            this.shutdownCalled = true;
            this.running = false;
        }
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
