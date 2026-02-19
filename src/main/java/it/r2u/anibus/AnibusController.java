package it.r2u.anibus;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;

/**
 * UI controller: handles FXML events and delegates work
 * to focused service/helper classes.
 */
public class AnibusController {

    /* -- FXML fields ------------------------------------------ */
    @FXML private TextField         hostTextField;
    @FXML private TextField         portsTextField;
    @FXML private Spinner<Integer>  threadSpinner;
    @FXML private Label             resolvedHostLabel;
    @FXML private Label             statusLabel;
    @FXML private Label             resultCountLabel;
    @FXML private ProgressIndicator progressIndicator;
    @FXML private ProgressBar       progressBar;
    @FXML private Button            scanButton;
    @FXML private Button            stopButton;
    @FXML private Button            exportButton;
    @FXML private Button            clearButton;

    /* -- Info card labels ------------------------------------- */
    @FXML private VBox  infoCard;
    @FXML private Label infoIpLabel;
    @FXML private Label infoHostnameLabel;
    @FXML private Label infoScanTimeLabel;
    @FXML private Label infoPortsScannedLabel;
    @FXML private Label infoOpenPortsLabel;
    @FXML private Label infoAvgLatencyLabel;

    /* -- Table ------------------------------------------------ */
    @FXML private TableView<PortScanResult>            resultTableView;
    @FXML private TableColumn<PortScanResult, Integer> portColumn;
    @FXML private TableColumn<PortScanResult, String>  stateColumn;
    @FXML private TableColumn<PortScanResult, String>  serviceColumn;
    @FXML private TableColumn<PortScanResult, String>  versionColumn;
    @FXML private TableColumn<PortScanResult, String>  protocolColumn;
    @FXML private TableColumn<PortScanResult, Long>    latencyColumn;
    @FXML private TableColumn<PortScanResult, String>  bannerColumn;

    /* -- State ------------------------------------------------ */
    private ScanTask activeScanTask;
    private Instant  scanStartTime;
    private final ObservableList<PortScanResult> results       = FXCollections.observableArrayList();
    private final PortScannerService             scanner       = new PortScannerService();

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        TableConfigurator.setup(resultTableView,
                portColumn, stateColumn, serviceColumn,
                versionColumn, protocolColumn, latencyColumn, bannerColumn);
        resultTableView.setItems(results);

        threadSpinner.setValueFactory(
                new SpinnerValueFactory.IntegerSpinnerValueFactory(10, 500, 100, 10));

        results.addListener((javafx.collections.ListChangeListener<PortScanResult>) c -> {
            refreshResultCount();
            refreshInfoCard();
            Platform.runLater(() -> {
                boolean any = !results.isEmpty();
                exportButton.setDisable(!any);
                clearButton.setDisable(!any);
            });
        });

        setupContextMenu();
        hostTextField.focusedProperty().addListener((obs, was, is) -> { if (!is) resolveHost(); });
        refreshResultCount();
    }

    private void setupContextMenu() {
        MenuItem copyRow = new MenuItem("Copy row");
        copyRow.setOnAction(e -> copySelectedRow());
        MenuItem copyAll = new MenuItem("Copy all results");
        copyAll.setOnAction(e -> copyAllRows());
        resultTableView.setContextMenu(new ContextMenu(copyRow, new SeparatorMenuItem(), copyAll));
    }

    /* -- DNS resolve ------------------------------------------ */
    private void resolveHost() {
        String host = hostTextField.getText().trim();
        if (host.isEmpty()) { resolvedHostLabel.setText(""); return; }
        new Thread(() -> {
            try {
                String ip = InetAddress.getByName(host).getHostAddress();
                Platform.runLater(() -> resolvedHostLabel.setText("Resolved: " + ip));
            } catch (UnknownHostException ex) {
                Platform.runLater(() -> resolvedHostLabel.setText("Unable to resolve host"));
            }
        }).start();
    }

    /* -- Result count ----------------------------------------- */
    private void refreshResultCount() {
        Platform.runLater(() -> {
            int n = results.size();
            if (resultCountLabel != null)
                resultCountLabel.setText(n == 0 ? "No open ports" : n == 1 ? "1 open port" : n + " open ports");
        });
    }

    /* -- Info card -------------------------------------------- */
    private void refreshInfoCard() {
        Platform.runLater(() -> {
            if (infoOpenPortsLabel != null) infoOpenPortsLabel.setText(String.valueOf(results.size()));
            if (infoAvgLatencyLabel != null && !results.isEmpty()) {
                double avg = results.stream().mapToLong(PortScanResult::getLatency).average().orElse(0);
                infoAvgLatencyLabel.setText(String.format("%.0f ms", avg));
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
            infoScanTimeLabel.setText("scanning");
        });
    }

    private void finalizeScanTime() {
        if (scanStartTime == null) return;
        long s = Duration.between(scanStartTime, Instant.now()).getSeconds();
        String elapsed = s < 60 ? s + "s" : (s / 60) + "m " + (s % 60) + "s";
        Platform.runLater(() -> infoScanTimeLabel.setText(elapsed));
    }

    /* -- Status ----------------------------------------------- */
    private void setStatus(String msg) {
        Platform.runLater(() -> { if (statusLabel != null) statusLabel.setText(msg); });
    }

    /* -- Scan start ------------------------------------------- */
    @FXML
    protected void onScanButtonClick() {
        results.clear();
        String host      = hostTextField.getText().trim();
        String portsRange = portsTextField.getText().trim();

        if (host.isEmpty() || portsRange.isEmpty()) {
            AlertHelper.show("Missing input", "Please enter both hostname and port range.",
                    Alert.AlertType.WARNING, cssUrl());
            return;
        }

        int[] ports = scanner.parsePortsRange(portsRange);
        if (ports == null) {
            AlertHelper.show("Invalid range", "Use format start-end (1-65535), e.g. 1-1024 or 1-65535.",
                    Alert.AlertType.ERROR, cssUrl());
            return;
        }

        scanButton.setDisable(true);
        stopButton.setDisable(false);
        progressIndicator.setVisible(true);
        progressBar.setVisible(true);
        progressBar.setProgress(0);
        setStatus("Resolving " + host + " ");
        scanStartTime = Instant.now();

        activeScanTask = new ScanTask(host, ports[0], ports[1], threadSpinner.getValue(), scanner,
                new ScanTask.Callbacks() {
                    public void onHostResolved(String ip)                    { resolvedHostLabel.setText("Resolved: " + ip); }
                    public void onScanStarted(String ip, String hn, int tot) { showInfoCard(ip, hn, tot); }
                    public void onResult(PortScanResult r)                   { results.add(r); }
                    public void onStatus(String msg)                         { setStatus(msg); }
                    public void onCompleted() { finalizeScanTime(); setStatus("Scan complete  " + results.size() + " open port(s) found"); resetUI(); }
                    public void onCancelled() { finalizeScanTime(); setStatus("Scan stopped by user"); resetUI(); }
                    public void onFailed(String err) { finalizeScanTime(); setStatus("Scan failed: " + err); resetUI(); }
                });

        progressBar.progressProperty().bind(activeScanTask.progressProperty());
        new Thread(activeScanTask).start();
    }

    /* -- Scan stop -------------------------------------------- */
    @FXML
    protected void onStopButtonClick() {
        if (activeScanTask != null && activeScanTask.isRunning()) activeScanTask.cancel();
    }

    /* -- Export ----------------------------------------------- */
    @FXML
    protected void onExportClick() {
        new ExportService(results, resultTableView.getScene().getWindow(), cssUrl(), this::setStatus)
                .promptAndExport();
    }

    /* -- Clear ------------------------------------------------ */
    @FXML
    protected void onClearClick() {
        results.clear();
        infoCard.setVisible(false);
        infoCard.setManaged(false);
        setStatus("Results cleared");
    }

    /* -- About ------------------------------------------------ */
    @FXML
    protected void onAboutClick() {
        AlertHelper.show("About Anibus",
                "Anibus Design System  ›  Version: 1.0.0\n\nAuthor: Iaroslav Tsymbaliuk\n\nPosition: Intern (2025–2026) @ r2u",
                Alert.AlertType.INFORMATION, cssUrl());
    }

    /* -- Clipboard -------------------------------------------- */
    private void copySelectedRow() {
        PortScanResult sel = resultTableView.getSelectionModel().getSelectedItem();
        if (sel == null) return;
        ClipboardService.copy(ClipboardService.formatRow(sel));
        setStatus("Copied to clipboard");
    }

    private void copyAllRows() {
        if (results.isEmpty()) return;
        ClipboardService.copy(ClipboardService.formatAll(results));
        setStatus("All results copied to clipboard");
    }

    /* -- UI helpers ------------------------------------------- */
    private void resetUI() {
        Platform.runLater(() -> {
            scanButton.setDisable(false);
            stopButton.setDisable(true);
            progressIndicator.setVisible(false);
            progressBar.setVisible(false);
            progressBar.progressProperty().unbind();
        });
    }

    private java.net.URL cssUrl() {
        return getClass().getResource("anibus-style.css");
    }

    public void shutdownExecutor() {
        if (activeScanTask != null) activeScanTask.shutdown();
    }
}
