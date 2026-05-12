package it.r2u.anibus.coordinator;

import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.core.PortScannerService;
import javafx.application.Platform;

class ScanCoordinatorStandardScanStrategyIT {

    private static final AtomicBoolean FX_STARTED = new AtomicBoolean(false);

    @Test
    void coordinatorRunsStandardStrategyAgainstLocalhost() throws Exception {
        ensureFxRuntime();

        int targetPort = 22;
        ServerSocket testServer = null;

        // Prefer localhost:22 (as in TODO), but fallback to an ephemeral local port
        // to keep the test deterministic across environments.
        if (!isOpen("127.0.0.1", 22, 150)) {
            testServer = new ServerSocket(0);
            targetPort = testServer.getLocalPort();
            ServerSocket finalServer = testServer;
            Thread acceptor = new Thread(() -> keepAccepting(finalServer, Duration.ofSeconds(8)));
            acceptor.setDaemon(true);
            acceptor.start();
        }

        try {
            ScanCoordinator coordinator = new ScanCoordinator();
            coordinator.registerStrategy("Standard Scanning", new StandardScanStrategy(new PortScannerService()));
            coordinator.setActiveStrategy("Standard Scanning");

            CountDownLatch completed = new CountDownLatch(1);
            AtomicReference<PortScanResult> firstResult = new AtomicReference<>();
            AtomicReference<String> failure = new AtomicReference<>();

            ScanContext context = ScanContext.builder()
                    .host("127.0.0.1")
                    .startPort(targetPort)
                    .endPort(targetPort)
                    .threadCount(1)
                    .callbacks(new ScanContext.ScanCallbacks() {
                        @Override
                        public void onHostResolved(String ip) {}

                        @Override
                        public void onScanStarted(String ip, String hostname, int totalPorts) {}

                        @Override
                        public void onResult(PortScanResult result) {
                            firstResult.compareAndSet(null, result);
                        }

                        @Override
                        public void onStatus(String message) {}

                        @Override
                        public void onCompleted() {
                            completed.countDown();
                        }

                        @Override
                        public void onCancelled() {
                            completed.countDown();
                        }

                        @Override
                        public void onFailed(String error) {
                            failure.set(error);
                            completed.countDown();
                        }
                    })
                    .build();

            coordinator.executeScan(context);

            assertTrue(completed.await(15, TimeUnit.SECONDS), "Scan did not finish in time");
            assertFalse(coordinator.isScanning(), "Coordinator should not remain in scanning state");
            assertTrue(failure.get() == null || failure.get().isBlank(), "Unexpected failure: " + failure.get());

            PortScanResult result = firstResult.get();
            assertNotNull(result, "Expected at least one open-port result");
            assertTrue(result.getPort() == targetPort);
        } finally {
            if (testServer != null) {
                testServer.close();
            }
        }
    }

    private static boolean isOpen(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static void keepAccepting(ServerSocket server, Duration duration) {
        long deadline = System.currentTimeMillis() + duration.toMillis();
        try {
            server.setSoTimeout(200);
            while (System.currentTimeMillis() < deadline && !server.isClosed()) {
                try (Socket socket = server.accept()) {
                    // Accept and immediately close; scanner only needs successful connect.
                    if (socket.isConnected()) {
                        socket.getOutputStream().flush();
                    }
                } catch (IOException e) {
                    e.getMessage();
                    // Timeout or transient accept error.
                }
            }
        } catch (IOException e) {
            e.getMessage();
            // Server closed.
        }
    }

    private static void ensureFxRuntime() {
        if (GraphicsEnvironment.isHeadless()) {
            throw new TestAbortedException("Skipping JavaFX-dependent integration test in headless environment");
        }
        if (FX_STARTED.compareAndSet(false, true)) {
            try {
                Platform.startup(() -> {
                    // initialize JavaFX runtime once for ScanTask callbacks
                });
            } catch (UnsupportedOperationException e) {
                throw new TestAbortedException("JavaFX runtime unavailable in headless environment", e);
            } catch (IllegalStateException e) {
                e.getMessage();
                // JavaFX runtime already initialized by another test.
            }
        }
    }
}
