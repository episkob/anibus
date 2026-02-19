package it.r2u.anibus;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

public class HelloController {

    /* ── FXML fields ─────────────────────────────────── */
    @FXML private TextField hostTextField;
    @FXML private TextField portsTextField;
    @FXML private Spinner<Integer> threadSpinner;
    @FXML private Label resolvedHostLabel;
    @FXML private Label statusLabel;
    @FXML private Label resultCountLabel;
    @FXML private ProgressIndicator progressIndicator;
    @FXML private ProgressBar progressBar;
    @FXML private Button scanButton;
    @FXML private Button stopButton;
    @FXML private Button exportButton;
    @FXML private Button clearButton;

    /* ── Info card labels ────────────────────────────── */
    @FXML private VBox infoCard;
    @FXML private Label infoIpLabel;
    @FXML private Label infoHostnameLabel;
    @FXML private Label infoScanTimeLabel;
    @FXML private Label infoPortsScannedLabel;
    @FXML private Label infoOpenPortsLabel;
    @FXML private Label infoAvgLatencyLabel;

    /* ── Table ───────────────────────────────────────── */
    @FXML private TableView<PortScanResult> resultTableView;
    @FXML private TableColumn<PortScanResult, Integer> portColumn;
    @FXML private TableColumn<PortScanResult, String> stateColumn;
    @FXML private TableColumn<PortScanResult, String> serviceColumn;
    @FXML private TableColumn<PortScanResult, String> versionColumn;
    @FXML private TableColumn<PortScanResult, String> protocolColumn;
    @FXML private TableColumn<PortScanResult, Long>   latencyColumn;
    @FXML private TableColumn<PortScanResult, String> bannerColumn;

    /* ── Internal state ──────────────────────────────── */
    private Task<Void> scanTask;
    private ExecutorService executor;
    private final ObservableList<PortScanResult> results = FXCollections.observableArrayList();
    private final PortScannerService portScannerService = new PortScannerService();
    private Instant scanStartTime;

    /* ── Initialization ──────────────────────────────── */
    @FXML
    public void initialize() {
        // Column bindings
        portColumn.setCellValueFactory(new PropertyValueFactory<>("port"));
        stateColumn.setCellValueFactory(new PropertyValueFactory<>("state"));
        serviceColumn.setCellValueFactory(new PropertyValueFactory<>("service"));
        versionColumn.setCellValueFactory(new PropertyValueFactory<>("version"));
        protocolColumn.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        latencyColumn.setCellValueFactory(new PropertyValueFactory<>("latency"));
        bannerColumn.setCellValueFactory(new PropertyValueFactory<>("banner"));
        resultTableView.setItems(results);

        // Latency column: show "X ms"
        latencyColumn.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(Long val, boolean empty) {
                super.updateItem(val, empty);
                setText(empty || val == null ? "" : val + " ms");
            }
        });

        // State column: color-coded
        stateColumn.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String val, boolean empty) {
                super.updateItem(val, empty);
                if (empty || val == null) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(val);
                    setStyle("-fx-text-fill: #34C759; -fx-font-weight: 600;");
                }
            }
        });

        // Thread spinner (10 – 500, default 100)
        threadSpinner.setValueFactory(
                new SpinnerValueFactory.IntegerSpinnerValueFactory(10, 500, 100, 10));

        // Row factory
        resultTableView.setRowFactory(tv -> {
            TableRow<PortScanResult> row = new TableRow<>();
            row.setStyle("-fx-background-color: transparent; -fx-border-width: 0 0 0.5 0; -fx-border-color: #E5E5EA;");
            return row;
        });

        // Placeholder
        Label placeholder = new Label("No results yet — start a scan above");
        placeholder.setStyle("-fx-text-fill: #AEAEB2; -fx-font-size: 15;");
        resultTableView.setPlaceholder(placeholder);

        // Live result count + button states
        results.addListener((javafx.collections.ListChangeListener<PortScanResult>) c -> {
            updateResultCount();
            updateInfoCard();
            Platform.runLater(() -> {
                boolean hasResults = !results.isEmpty();
                exportButton.setDisable(!hasResults);
                clearButton.setDisable(!hasResults);
            });
        });

        // Context menu
        MenuItem copyItem    = new MenuItem("Copy row");
        copyItem.setOnAction(e -> handleCopyAction());
        MenuItem copyAllItem = new MenuItem("Copy all results");
        copyAllItem.setOnAction(e -> handleCopyAllAction());
        ContextMenu ctx = new ContextMenu(copyItem, new SeparatorMenuItem(), copyAllItem);
        resultTableView.setContextMenu(ctx);

        // Resolve host on focus lost
        hostTextField.focusedProperty().addListener((obs, wasFocused, isFocused) -> {
            if (!isFocused) resolveHost();
        });

        updateResultCount();
    }

    /* ── DNS resolve helper ──────────────────────────── */
    private void resolveHost() {
        String host = hostTextField.getText().trim();
        if (host.isEmpty()) {
            resolvedHostLabel.setText("");
            return;
        }
        new Thread(() -> {
            try {
                InetAddress addr = InetAddress.getByName(host);
                String ip = addr.getHostAddress();
                Platform.runLater(() -> resolvedHostLabel.setText("Resolved: " + ip));
            } catch (UnknownHostException ex) {
                Platform.runLater(() -> resolvedHostLabel.setText("Unable to resolve host"));
            }
        }).start();
    }

    /* ── Result count badge ──────────────────────────── */
    private void updateResultCount() {
        Platform.runLater(() -> {
            int count = results.size();
            String text = count == 0 ? "No open ports"
                    : count == 1 ? "1 open port"
                    : count + " open ports";
            if (resultCountLabel != null) resultCountLabel.setText(text);
        });
    }

    /* ── Info card update ────────────────────────────── */
    private void updateInfoCard() {
        Platform.runLater(() -> {
            if (infoOpenPortsLabel != null) {
                infoOpenPortsLabel.setText(String.valueOf(results.size()));
            }
            if (infoAvgLatencyLabel != null && !results.isEmpty()) {
                double avgMs = results.stream()
                        .mapToLong(PortScanResult::getLatency)
                        .average().orElse(0);
                infoAvgLatencyLabel.setText(String.format("%.0f ms", avgMs));
            }
        });
    }

    private void showInfoCard(String ip, String hostname, int totalPorts) {
        Platform.runLater(() -> {
            infoCard.setVisible(true);
            infoCard.setManaged(true);
            infoIpLabel.setText(ip);
            infoHostnameLabel.setText(hostname);
            infoPortsScannedLabel.setText(String.valueOf(totalPorts));
            infoOpenPortsLabel.setText("0");
            infoAvgLatencyLabel.setText("-");
            infoScanTimeLabel.setText("scanning…");
        });
    }

    private void finalizeScanTime() {
        if (scanStartTime == null) return;
        long seconds = Duration.between(scanStartTime, Instant.now()).getSeconds();
        String elapsed = seconds < 60
                ? seconds + "s"
                : (seconds / 60) + "m " + (seconds % 60) + "s";
        Platform.runLater(() -> infoScanTimeLabel.setText(elapsed));
    }

    /* ── Status bar helper ───────────────────────────── */
    private void setStatus(String msg) {
        Platform.runLater(() -> {
            if (statusLabel != null) statusLabel.setText(msg);
        });
    }

    /* ── About window ────────────────────────────────── */
    @FXML
    protected void onAboutClick() {
        showModernAlert("About Anibus",
                "Anibus Port Scanner  v1.1\n\n"
                        + "A modern iOS-inspired port scanning\n"
                        + "application built with JavaFX.\n\n"
                        + "\u00A9 2026 r2u",
                Alert.AlertType.INFORMATION);
    }

    /* ── Start scan ──────────────────────────────────── */
    @FXML
    protected void onScanButtonClick() {
        results.clear();
        String host      = hostTextField.getText().trim();
        String portsRange = portsTextField.getText().trim();

        if (host.isEmpty() || portsRange.isEmpty()) {
            showModernAlert("Missing input", "Please enter both hostname and port range.", Alert.AlertType.WARNING);
            return;
        }

        int threadCount = threadSpinner.getValue();

        int[] ports = portScannerService.parsePortsRange(portsRange);
        if (ports == null || ports[0] > ports[1]) {
            showModernAlert("Invalid range", "Use format start-end (1–65535), e.g. 1-1024 or 1-65535.", Alert.AlertType.ERROR);
            return;
        }

        // UI into scanning mode
        scanButton.setDisable(true);
        stopButton.setDisable(false);
        progressIndicator.setVisible(true);
        progressBar.setVisible(true);
        progressBar.setProgress(0);
        setStatus("Resolving " + host + " …");

        int startPort  = ports[0];
        int endPort    = ports[1];
        int totalPorts = endPort - startPort + 1;

        scanStartTime = Instant.now();

        scanTask = new Task<>() {
            @Override
            protected Void call() throws Exception {
                try {
                    InetAddress ipAddress = InetAddress.getByName(host);
                    String targetIp = ipAddress.getHostAddress();
                    String canonicalHost = ipAddress.getCanonicalHostName();

                    Platform.runLater(() ->
                            resolvedHostLabel.setText("Resolved: " + targetIp));
                    showInfoCard(targetIp, canonicalHost, totalPorts);
                    setStatus("Scanning " + host + " (" + targetIp + ") — ports " + startPort + "–" + endPort);

                    final CountDownLatch latch = new CountDownLatch(totalPorts);
                    ThreadFactory daemonFactory = r -> {
                        Thread t = new Thread(r);
                        t.setDaemon(true);
                        return t;
                    };
                    executor = Executors.newFixedThreadPool(threadCount, daemonFactory);

                    for (int port = startPort; port <= endPort; port++) {
                        if (isCancelled()) break;
                        final int p = port;
                        executor.submit(() -> {
                            try {
                                long latency = portScannerService.measurePortLatency(targetIp, p);
                                if (latency >= 0) {
                                    String banner   = portScannerService.getBanner(targetIp, p);
                                    String service  = portScannerService.getServiceName(p);
                                    String protocol = portScannerService.getProtocolAndEncryption(p, banner);
                                    String version  = portScannerService.extractVersion(banner);
                                    String state    = "Open";

                                    Platform.runLater(() ->
                                            results.add(new PortScanResult(
                                                    p, service, banner, protocol,
                                                    latency, version, state)));
                                }
                            } finally {
                                latch.countDown();
                                updateProgress(totalPorts - latch.getCount(), totalPorts);
                            }
                        });
                    }
                    latch.await();
                } catch (UnknownHostException e) {
                    setStatus("Error: unknown host " + host);
                    throw e;
                } finally {
                    if (executor != null && !executor.isShutdown()) executor.shutdownNow();
                }
                return null;
            }

            @Override protected void succeeded() {
                super.succeeded();
                finalizeScanTime();
                setStatus("Scan complete — " + results.size() + " open port(s) found");
                resetUI();
            }
            @Override protected void cancelled() {
                super.cancelled();
                finalizeScanTime();
                setStatus("Scan stopped by user");
                resetUI();
            }
            @Override protected void failed() {
                super.failed();
                finalizeScanTime();
                setStatus("Scan failed: " + getException().getMessage());
                resetUI();
            }
        };

        progressBar.progressProperty().bind(scanTask.progressProperty());
        new Thread(scanTask).start();
    }

    /* ── Stop scan ───────────────────────────────────── */
    @FXML
    protected void onStopButtonClick() {
        if (scanTask != null && scanTask.isRunning()) scanTask.cancel();
    }

    /* ── Export to CSV ───────────────────────────────── */
    @FXML
    protected void onExportClick() {
        if (results.isEmpty()) return;

        FileChooser fc = new FileChooser();
        fc.setTitle("Export Scan Results");
        fc.setInitialFileName("anibus-scan-" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")) + ".csv");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files", "*.csv"));

        File file = fc.showSaveDialog(resultTableView.getScene().getWindow());
        if (file != null) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
                pw.println("Port,State,Service,Version,Protocol,Latency(ms),Banner");
                for (PortScanResult r : results) {
                    pw.printf("%d,\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\"%n",
                            r.getPort(),
                            esc(r.getState()),
                            esc(r.getService()),
                            esc(r.getVersion()),
                            esc(r.getProtocol()),
                            r.getLatency(),
                            esc(r.getBanner()));
                }
                setStatus("Exported " + results.size() + " result(s) to " + file.getName());
            } catch (IOException e) {
                showModernAlert("Export failed", e.getMessage(), Alert.AlertType.ERROR);
            }
        }
    }

    private String esc(String s) { return s == null ? "" : s.replace("\"", "\"\""); }

    /* ── Clear results ───────────────────────────────── */
    @FXML
    protected void onClearClick() {
        results.clear();
        infoCard.setVisible(false);
        infoCard.setManaged(false);
        setStatus("Results cleared");
    }

    /* ── UI helpers ──────────────────────────────────── */
    private void resetUI() {
        Platform.runLater(() -> {
            scanButton.setDisable(false);
            stopButton.setDisable(true);
            progressIndicator.setVisible(false);
            progressBar.setVisible(false);
            progressBar.progressProperty().unbind();
        });
    }

    private void showModernAlert(String title, String message, Alert.AlertType type) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);

        DialogPane dp = alert.getDialogPane();
        dp.getStylesheets().add(
                getClass().getResource("ios-style.css").toExternalForm());
        dp.setStyle(
                "-fx-background-color: white;" +
                "-fx-background-radius: 16;" +
                "-fx-effect: dropshadow(gaussian, rgba(0,0,0,0.2), 24, 0, 0, 6);" +
                "-fx-font-family: 'SF Pro Display', 'Segoe UI', system-ui;");

        dp.lookupButton(ButtonType.OK).setStyle(
                "-fx-background-color: #007AFF;" +
                "-fx-background-radius: 10;" +
                "-fx-text-fill: white;" +
                "-fx-font-weight: 600;" +
                "-fx-padding: 10 20;");

        alert.showAndWait();
    }

    public void shutdownExecutor() {
        if (executor != null && !executor.isShutdown()) executor.shutdownNow();
    }

    /* ── Clipboard actions ───────────────────────────── */
    private void handleCopyAction() {
        PortScanResult sel = resultTableView.getSelectionModel().getSelectedItem();
        if (sel != null) {
            String text = String.format("Port: %d, State: %s, Service: %s, Version: %s, Protocol: %s, Latency: %dms, Banner: %s",
                    sel.getPort(), sel.getState(), sel.getService(), sel.getVersion(),
                    sel.getProtocol(), sel.getLatency(), sel.getBanner());
            copyToClipboard(text);
            setStatus("Copied to clipboard");
        }
    }

    private void handleCopyAllAction() {
        if (results.isEmpty()) return;
        StringBuilder sb = new StringBuilder();
        sb.append("Port\tState\tService\tVersion\tProtocol\tLatency\tBanner\n");
        for (PortScanResult r : results) {
            sb.append(r.getPort()).append('\t')
              .append(r.getState()).append('\t')
              .append(r.getService()).append('\t')
              .append(r.getVersion()).append('\t')
              .append(r.getProtocol()).append('\t')
              .append(r.getLatency()).append("ms\t")
              .append(r.getBanner()).append('\n');
        }
        copyToClipboard(sb.toString());
        setStatus("All results copied to clipboard");
    }

    private void copyToClipboard(String text) {
        ClipboardContent cc = new ClipboardContent();
        cc.putString(text);
        Clipboard.getSystemClipboard().setContent(cc);
    }
}