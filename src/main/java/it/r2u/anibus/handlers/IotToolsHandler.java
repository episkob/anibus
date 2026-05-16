package it.r2u.anibus.handlers;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import it.r2u.anibus.service.detection.IoTDetector;
import it.r2u.anibus.service.iot.AdbProbeService;
import it.r2u.anibus.service.iot.OnvifProbeService;
import it.r2u.anibus.service.iot.RtspProbeService;
import it.r2u.anibus.ui.ConsoleViewManager;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

/**
 * Manual IoT tooling for GUI Actions menu.
 * Provides RTSP/ONVIF/ADB probes and a small IoT quick-scan.
 */
public class IotToolsHandler {

    private final TextField hostTextField;
    private final TextField portsTextField;
    private final ProgressBar progressBar;
    private final TextArea consoleTextArea;
    private final ConsoleViewManager consoleViewManager;
    private final Consumer<String> statusSetter;

    private final RtspProbeService rtspProbeService;
    private final AdbProbeService adbProbeService;
    private final OnvifProbeService onvifProbeService;

    public IotToolsHandler(
            TextField hostTextField,
            TextField portsTextField,
            ProgressBar progressBar,
            TextArea consoleTextArea,
            ConsoleViewManager consoleViewManager,
            Consumer<String> statusSetter
    ) {
        this.hostTextField = hostTextField;
        this.portsTextField = portsTextField;
        this.progressBar = progressBar;
        this.consoleTextArea = consoleTextArea;
        this.consoleViewManager = consoleViewManager;
        this.statusSetter = statusSetter;
        this.rtspProbeService = new RtspProbeService(3000);
        this.adbProbeService = new AdbProbeService(3000);
        this.onvifProbeService = new OnvifProbeService(3000);
    }

    public void runRtspProbe() {
        String host = SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText());
        if (host.isBlank()) {
            statusSetter.accept("Enter a host or URL before RTSP probe");
            return;
        }

        int port = 554;
        try {
            String portsRaw = portsTextField != null ? portsTextField.getText() : "";
            if (portsRaw != null && portsRaw.trim().matches("^\\d{1,5}$")) {
                port = Integer.parseInt(portsRaw.trim());
            }
        } catch (Exception ignored) {}

        int finalPort = port;
        Task<String> task = new Task<>() {
            @Override
            protected String call() {
                RtspProbeService.RtspProbeResult res = rtspProbeService.probe(host, finalPort);
                StringBuilder sb = new StringBuilder();
                sb.append("=== RTSP PROBE ===\n");
                sb.append("Target: ").append(host).append(":").append(finalPort).append("\n");
                sb.append("OK: ").append(res.ok()).append("\n");
                if (res.statusLine() != null) sb.append("Status: ").append(res.statusLine()).append("\n");
                if (res.serverHeader() != null) sb.append("Server: ").append(res.serverHeader()).append("\n");
                if (res.publicHeader() != null) sb.append("Public: ").append(res.publicHeader()).append("\n");
                if (res.manufacturerGuess() != null) sb.append("Guess: ").append(res.manufacturerGuess()).append("\n");
                if (res.suggestedRtspUrl() != null) sb.append("Suggested URL: ").append(res.suggestedRtspUrl()).append("\n");
                if (res.rawResponse() != null && !res.rawResponse().isBlank()) {
                    sb.append("\n--- Raw response ---\n").append(res.rawResponse()).append("\n");
                }
                return sb.toString();
            }
        };

        bindAndRun(task, "Running RTSP probe on " + host + ":" + finalPort + "...");
    }

    public void runAdbProbe() {
        String host = SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText());
        if (host.isBlank()) {
            statusSetter.accept("Enter a host or URL before ADB probe");
            return;
        }

        int port = 5555;
        try {
            String portsRaw = portsTextField != null ? portsTextField.getText() : "";
            if (portsRaw != null && portsRaw.trim().matches("^\\d{1,5}$")) {
                port = Integer.parseInt(portsRaw.trim());
            }
        } catch (Exception ignored) {}

        int finalPort = port;
        Task<String> task = new Task<>() {
            @Override
            protected String call() {
                AdbProbeService.AdbProbeResult res = adbProbeService.probe(host, finalPort);
                StringBuilder sb = new StringBuilder();
                sb.append("=== ADB PROBE ===\n");
                sb.append("Target: ").append(host).append(":").append(finalPort).append("\n");
                sb.append("OK: ").append(res.ok()).append("\n");
                if (res.version() != null) sb.append("Version: ").append(res.version()).append("\n");
                if (res.unauthorizedOrExposed()) sb.append("[WARN] ADB over TCP exposed\n");
                return sb.toString();
            }
        };

        bindAndRun(task, "Running ADB probe on " + host + ":" + finalPort + "...");
    }

    public void runOnvifProbe() {
        String host = SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText());
        if (host.isBlank()) {
            statusSetter.accept("Enter a host or URL before ONVIF probe");
            return;
        }

        Task<String> task = new Task<>() {
            @Override
            protected String call() {
                OnvifProbeService.OnvifProbeResult res = onvifProbeService.probeHost(host);
                StringBuilder sb = new StringBuilder();
                sb.append("=== ONVIF PROBE ===\n");
                sb.append("Target: ").append(host).append("\n");
                sb.append("Detected: ").append(res.detected()).append("\n");
                if (res.hint() != null) sb.append("Hint: ").append(res.hint()).append("\n");
                if (res.attempts() != null && !res.attempts().isEmpty()) {
                    sb.append("\n--- Attempts ---\n");
                    for (String a : res.attempts()) sb.append(a).append("\n");
                }
                return sb.toString();
            }
        };

        bindAndRun(task, "Probing ONVIF endpoints for " + host + "...");
    }

    /**
     * Runs IoTDetector on a small set of common IoT ports (TCP only).
     * Uses IoTDetector's heuristics when the port is reachable.
     */
    public void runIotQuickScan() {
        String host = SecurityAnalysisHandler.extractHostOrDomain(hostTextField.getText());
        if (host.isBlank()) {
            statusSetter.accept("Enter a host or URL before IoT quick-scan");
            return;
        }

        int[] ports = {554, 80, 443, 8443, 8000, 8080, 37777, 34567, 9527, 23, 2323, 1883, 8883, 5555};

        Task<String> task = new Task<>() {
            @Override
            protected String call() {
                StringBuilder sb = new StringBuilder();
                sb.append("=== IOT QUICK-SCAN ===\n");
                sb.append("Target: ").append(host).append("\n");
                List<String> hits = new ArrayList<>();

                int checked = 0;
                for (int p : ports) {
                    checked++;
                    updateProgress(checked, ports.length);

                    boolean open = isTcpOpen(host, p, 800);
                    if (!open) continue;

                    IoTDetector.IoTDevice dev = IoTDetector.detectIoTDevice(host, p, "");
                    if (dev != null) {
                        hits.add("Port " + p + ":\n" + dev.toString());
                    } else {
                        hits.add("Port " + p + ": open (no IoT fingerprint)");
                    }
                }

                if (hits.isEmpty()) {
                    sb.append("No IoT hits on common ports.\n");
                } else {
                    sb.append("Hits: ").append(hits.size()).append("\n\n");
                    for (String h : hits) {
                        sb.append(h).append("\n\n");
                    }
                }
                return sb.toString().trim();
            }
        };

        bindAndRun(task, "Running IoT quick-scan on " + host + "...");
    }

    private void bindAndRun(Task<String> task, String status) {
        progressBar.progressProperty().unbind();
        progressBar.progressProperty().bind(task.progressProperty());
        progressBar.setVisible(true);
        statusSetter.accept(status);

        task.setOnSucceeded(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            String out = task.getValue();
            if (out != null && !out.isBlank()) {
                consoleViewManager.appendRawText("\n" + out + "\n");
            }
            statusSetter.accept("Done");
        });

        task.setOnFailed(ev -> {
            progressBar.progressProperty().unbind();
            progressBar.setVisible(false);
            Throwable ex = task.getException();
            statusSetter.accept("Failed: " + (ex != null ? ex.getMessage() : "unknown error"));
        });

        Thread worker = new Thread(task);
        worker.setDaemon(true);
        worker.start();
    }

    private static boolean isTcpOpen(String host, int port, int timeoutMs) {
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new java.net.InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

