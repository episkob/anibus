package it.r2u.anibus;

import it.r2u.anibus.service.SQLInjectionAnalyzer;

import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.PrintWriter;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Controller for the SQL Injection Testing tab.
 * Standalone: discovers endpoints via internal crawler, then fires payloads.
 */
public class SqlInjectionController {

    /* -- FXML fields ------------------------------------------ */
    @FXML private TextField   sqlTargetUrlField;
    @FXML private Button      sqlRunButton;
    @FXML private Button      sqlStopButton;
    @FXML private ProgressBar sqlProgressBar;
    @FXML private VBox        sqlResultsCard;
    @FXML private Label       sqlEndpointsLabel;
    @FXML private Label       sqlVulnerableLabel;
    @FXML private Label       sqlPayloadsLabel;
    @FXML private Label       sqlStatusLabel;
    @FXML private Button      sqlExportButton;
    @FXML private Button      sqlClearButton;
    @FXML private TextArea    sqlConsoleArea;
    @FXML private TextArea    liveLogArea;

    /* -- State ------------------------------------------------ */
    private Task<Void> injectionTask;
    private String lastOutput;

    /* -- Services --------------------------------------------- */
    private SQLInjectionAnalyzer injectionAnalyzer;
    private Consumer<String>     statusSetter;

    /* -- Initialization --------------------------------------- */
    @FXML
    public void initialize() {
        sqlResultsCard.managedProperty().bind(sqlResultsCard.visibleProperty());
    }

    public void setContext(Consumer<String> statusSetter, java.net.URL cssUrl) {
        this.statusSetter  = statusSetter;
        this.injectionAnalyzer = new SQLInjectionAnalyzer();
    }

    /* -- FXML button actions ---------------------------------- */
    @FXML
    void onSqlRunButtonClick() {
        String url = sqlTargetUrlField.getText().trim();
        if (url.isEmpty()) {
            setStatus("Please enter a target URL");
            return;
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
            sqlTargetUrlField.setText(url);
        }

        setStatus("Starting SQL injection test...");
        injectionTask = createInjectionTask(url);

        sqlRunButton.setDisable(true);
        sqlStopButton.setDisable(false);
        sqlProgressBar.setVisible(true);
        sqlResultsCard.setVisible(false);

        Thread thread = new Thread(injectionTask);
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    void onSqlStopButtonClick() {
        if (injectionTask != null && !injectionTask.isDone()) {
            injectionTask.cancel(true);
            setStatus("SQL injection test stopped");
        }
        resetUi();
    }

    @FXML
    void onSqlExportClick() {
        if (lastOutput == null || lastOutput.isEmpty()) return;
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export Injection Results");
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        chooser.setInitialFileName("injection-results.txt");
        File file = chooser.showSaveDialog(sqlConsoleArea.getScene().getWindow());
        if (file == null) return;
        try (PrintWriter pw = new PrintWriter(file, "UTF-8")) {
            pw.print(lastOutput);
            setStatus("Exported to " + file.getName());
        } catch (Exception e) {
            setStatus("Export failed: " + e.getMessage());
        }
    }

    @FXML
    void onSqlClearClick() {
        sqlConsoleArea.clear();
        liveLogArea.clear();
        sqlResultsCard.setVisible(false);
        sqlEndpointsLabel.setText("0");
        sqlVulnerableLabel.setText("0");
        sqlPayloadsLabel.setText("0");
        sqlStatusLabel.setText("");
        sqlExportButton.setDisable(true);
        sqlClearButton.setDisable(true);
        lastOutput = null;
        setStatus("SQL injection results cleared");
    }

    /* -- Task ------------------------------------------------- */
    private Task<Void> createInjectionTask(String targetUrl) {
        return new Task<>() {
            @Override
            protected Void call() {
                try {
                    appendLog("Started SQL injection test: " + targetUrl);
                    Map<String, List<SQLInjectionAnalyzer.InjectionResult>> results =
                            injectionAnalyzer.fullScan(
                                    Collections.emptyList(),
                                    targetUrl,
                                    msg -> { Platform.runLater(() -> setStatus(msg)); appendLog(msg); }
                            );

                    Platform.runLater(() -> {
                        displayResults(targetUrl, results);
                        resetUi();
                    });
                } catch (Exception e) {
                    appendLog("ERROR: " + e.getMessage());
                    Platform.runLater(() -> {
                        setStatus("Injection test failed: " + e.getMessage());
                        resetUi();
                    });
                }
                return null;
            }
        };
    }

    /* -- Display ---------------------------------------------- */
    private void displayResults(String targetUrl,
            Map<String, List<SQLInjectionAnalyzer.InjectionResult>> results) {

        int totalEndpoints = results.size();
        int vulnerableCount = (int) results.values().stream()
                .filter(list -> list.stream().anyMatch(SQLInjectionAnalyzer.InjectionResult::isVulnerable))
                .count();
        int payloadsFired = results.values().stream().mapToInt(List::size).sum();

        sqlEndpointsLabel.setText(String.valueOf(totalEndpoints));
        sqlVulnerableLabel.setText(String.valueOf(vulnerableCount));
        sqlPayloadsLabel.setText(String.valueOf(payloadsFired));

        String output = injectionAnalyzer.formatResults(results);

        // Prepend header
        StringBuilder full = new StringBuilder();
        full.append("╔══════════════════════════════════════════════════════╗\n");
        full.append("║              SQL INJECTION TEST RESULTS             ║\n");
        full.append("╚══════════════════════════════════════════════════════╝\n\n");
        full.append("  Target:    ").append(targetUrl).append("\n");
        full.append("  Endpoints: ").append(totalEndpoints).append("\n");
        full.append("  Payloads:  ").append(payloadsFired).append("\n");
        full.append("  Vulnerable:").append(vulnerableCount).append("\n\n");
        full.append(output);

        lastOutput = full.toString();
        sqlConsoleArea.setText(lastOutput);

        sqlResultsCard.setVisible(true);
        sqlStatusLabel.setText("Test completed");
        sqlExportButton.setDisable(false);
        sqlClearButton.setDisable(false);

        setStatus("SQL injection test completed — " + vulnerableCount + " vulnerable endpoint(s)");
        appendLog("Test complete — " + vulnerableCount + " vulnerable / " + totalEndpoints + " endpoints");
    }

    /* -- Helpers ---------------------------------------------- */
    private void setStatus(String msg) {
        if (statusSetter != null) statusSetter.accept(msg);
    }

    private static final DateTimeFormatter LOG_TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    void appendLog(String msg) {
        Platform.runLater(() -> {
            if (liveLogArea == null) return;
            liveLogArea.appendText("[" + LocalTime.now().format(LOG_TIME) + "] " + msg + "\n");
        });
    }

    private void resetUi() {
        Platform.runLater(() -> {
            sqlRunButton.setDisable(false);
            sqlStopButton.setDisable(true);
            sqlProgressBar.setVisible(false);
        });
    }



    public void shutdown() {
        if (injectionAnalyzer != null) injectionAnalyzer.shutdown();
    }
}
