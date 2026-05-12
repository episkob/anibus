package it.r2u.anibus.handlers;

import java.awt.GraphicsEnvironment;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.analysis.ParamMinerService;
import it.r2u.anibus.service.analysis.SourceMapAnalyzer;
import it.r2u.anibus.service.core.PortScannerService;
import it.r2u.anibus.service.core.ScanSchedulerService;
import it.r2u.anibus.service.core.UdpScannerService;
import it.r2u.anibus.service.export.ScanDiffService;
import it.r2u.anibus.service.network.SubdomainEnumerationService;
import it.r2u.anibus.ui.ConsoleViewManager;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

class ExtraScanHandlerTest {

    private static final AtomicBoolean FX_STARTED = new AtomicBoolean(false);

    @Test
    void helperMethodsNormalizeInputsAndBuildDriftMessages() throws Exception {
        ensureFxRuntime();

        Method normalize = ExtraScanHandler.class.getDeclaredMethod("normalizeRootDomain", String.class);
        normalize.setAccessible(true);
        Method buildDrift = ExtraScanHandler.class.getDeclaredMethod("buildDriftMessage", String.class, java.util.Set.class, java.util.Set.class);
        buildDrift.setAccessible(true);

        assertEquals(null, normalize.invoke(null, new Object[]{null}));
        assertEquals(null, normalize.invoke(null, "   "));
        assertEquals("example.com", normalize.invoke(null, "api.example.com"));
        assertEquals("localhost", normalize.invoke(null, "localhost"));

        String drift = (String) buildDrift.invoke(null, "example.com", java.util.Set.of(80, 443), java.util.Set.of(22));
        assertTrue(drift.contains("SECURITY DRIFT DETECTED"));
        assertTrue(drift.contains("[OPENED] ports: [80, 443]"));
        assertTrue(drift.contains("[CLOSED] ports: [22]"));
    }

    @Test
    void runSourceMapAndSqlMetadataGuardOnMissingInputs() {
        ensureFxRuntime();

        List<String> statuses = new ArrayList<>();
        TestContext context = new TestContext(statuses::add);

        context.handler.runSourceMapAnalysis();
        context.handler.runSqlMetadataExtraction();

        assertEquals(2, statuses.size());
        assertTrue(statuses.get(0).contains("Run JavaScript analysis first"));
        assertTrue(statuses.get(1).contains("Enter a host first"));
    }

    @Test
    void startScheduledScanWiresIntervalTaskAndCallbacks() {
        ensureFxRuntime();

        List<String> statuses = new ArrayList<>();
        TestScheduler scheduler = new TestScheduler();
        TestScanner scanner = new TestScanner();
        TestContext context = new TestContext(statuses::add, scheduler, scanner);
        context.hostTextField.setText("api.example.com");
        context.portsTextField.setText("20-25");

        context.handler.startScheduledScan();

        assertTrue(scheduler.scheduled);
        assertEquals(Duration.ofMinutes(30), scheduler.interval);
        assertNotNull(scheduler.task);
        assertNotNull(scheduler.onResults);
        assertNotNull(scheduler.onError);
        assertTrue(statuses.contains("Scheduled scan started (every 30 minutes)"));
    }

    @Test
    void runShowScanHistoryReturnsSilentlyWhenServiceMissing() {
        ensureFxRuntime();

        List<String> statuses = new ArrayList<>();
        TestContext context = new TestContext(statuses::add);

        context.handler.runShowScanHistory();

        assertTrue(statuses.isEmpty());
    }

    private static void ensureFxRuntime() {
        if (GraphicsEnvironment.isHeadless()) {
            throw new TestAbortedException("Skipping JavaFX-dependent handler tests in headless environment");
        }
        if (FX_STARTED.compareAndSet(false, true)) {
            try {
                Platform.startup(() -> {
                    // initialize JavaFX runtime once for handler tests
                });
            } catch (UnsupportedOperationException e) {
                throw new TestAbortedException("JavaFX runtime unavailable in headless environment", e);
            } catch (IllegalStateException e) {
                // already initialized by another test
            }
        }
    }

    private static final class TestContext {
        private final TextField hostTextField = new TextField();
        private final TextField portsTextField = new TextField();
        private final ProgressBar progressBar = new ProgressBar();
        private final TextArea consoleTextArea = new TextArea();
        private final ObservableList<PortScanResult> results = FXCollections.observableArrayList();
        private final ConsoleViewManager consoleViewManager = new ConsoleViewManager(consoleTextArea);
        private final ExtraScanHandler handler;

        private TestContext(Consumer<String> statusSink) {
            this(statusSink, new TestScheduler(), new TestScanner());
        }

        private TestContext(Consumer<String> statusSink, TestScheduler scheduler, TestScanner scanner) {
            this.handler = new ExtraScanHandler(
                    hostTextField,
                    portsTextField,
                    progressBar,
                    consoleTextArea,
                    consoleViewManager,
                    results,
                    statusSink,
                    () -> null,
                    new UdpScannerService(),
                    new SubdomainEnumerationService(),
                    new SourceMapAnalyzer(),
                    new ParamMinerService(),
                    new ScanDiffService(),
                    scheduler,
                    null,
                    scanner);
        }
    }

    private static final class TestScheduler extends ScanSchedulerService {
        private boolean scheduled;
        private Duration interval;
        private ScanTask task;
        private Consumer<ScanResults> onResults;
        private Consumer<String> onError;

        @Override
        public synchronized void schedule(Duration interval, ScanTask task, Consumer<ScanResults> onResults, Consumer<String> onError) {
            this.scheduled = true;
            this.interval = interval;
            this.task = task;
            this.onResults = onResults;
            this.onError = onError;
        }

        @Override
        public synchronized void cancel() {
            // no-op for tests
        }

        @Override
        public boolean isRunning() {
            return false;
        }

        @Override
        public String statusString() {
            return "Scheduler: inactive";
        }
    }

    private static final class TestScanner extends PortScannerService {
        @Override
        public int[] parsePortsRange(String portsRange) {
            return new int[]{20, 25};
        }

        @Override
        public long measurePortLatency(String host, int port) {
            return 1;
        }

        @Override
        public String getBanner(String host, int port) {
            return "banner";
        }

        @Override
        public String getServiceName(int port) {
            return "service";
        }

        @Override
        public String getProtocol(int port, String banner) {
            return "TCP";
        }

        @Override
        public String extractVersion(String banner) {
            return "1.0";
        }
    }
}
