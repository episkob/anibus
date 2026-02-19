package it.r2u.anibus;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.DialogPane;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Consumer;

/**
 * Handles CSV and XML export of scan results,
 * including a format-selection dialog.
 */
public class ExportService {

    private final List<PortScanResult> results;
    private final Window owner;
    private final URL cssUrl;
    private final Consumer<String> onStatus;

    public ExportService(List<PortScanResult> results, Window owner, URL cssUrl, Consumer<String> onStatus) {
        this.results  = results;
        this.owner    = owner;
        this.cssUrl   = cssUrl;
        this.onStatus = onStatus;
    }

    public void promptAndExport() {
        if (results.isEmpty()) return;

        ButtonType csvBtn  = new ButtonType("CSV");
        ButtonType xmlBtn  = new ButtonType("XML");
        ButtonType cancel  = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
        Alert fmt = new Alert(Alert.AlertType.NONE, "Choose export format:", csvBtn, xmlBtn, cancel);
        fmt.setTitle("Export Format");
        fmt.setHeaderText(null);
        styleDialog(fmt.getDialogPane());

        fmt.showAndWait().ifPresent(choice -> {
            if (choice == cancel) return;
            boolean isCsv = (choice == csvBtn);
            File file = pickFile(isCsv);
            if (file == null) return;
            try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
                if (isCsv) writeCsv(pw); else writeXml(pw);
                onStatus.accept("Exported " + results.size() + " result(s) to " + file.getName());
            } catch (IOException e) {
                AlertHelper.show("Export failed", e.getMessage(), Alert.AlertType.ERROR, cssUrl);
            }
        });
    }

    private File pickFile(boolean isCsv) {
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        FileChooser fc = new FileChooser();
        fc.setTitle("Export Scan Results");
        if (isCsv) {
            fc.setInitialFileName("anibus-scan-" + stamp + ".csv");
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files", "*.csv"));
        } else {
            fc.setInitialFileName("anibus-scan-" + stamp + ".xml");
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("XML Files", "*.xml"));
        }
        return fc.showSaveDialog(owner);
    }

    private void writeCsv(PrintWriter pw) {
        pw.println("Port,State,Service,Version,Protocol,Latency(ms),Banner");
        for (PortScanResult r : results) {
            pw.printf("%d,\"%s\",\"%s\",\"%s\",\"%s\",%d,\"%s\"%n",
                    r.getPort(), esc(r.getState()), esc(r.getService()),
                    esc(r.getVersion()), esc(r.getProtocol()),
                    r.getLatency(), esc(r.getBanner()));
        }
    }

    private void writeXml(PrintWriter pw) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));
        pw.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        pw.println("<scan>");
        pw.printf("  <meta timestamp=\"%s\" total=\"%d\"/>%n", ts, results.size());
        pw.println("  <results>");
        for (PortScanResult r : results) {
            pw.println("    <port>");
            pw.printf("      <number>%d</number>%n",     r.getPort());
            pw.printf("      <state>%s</state>%n",       x(r.getState()));
            pw.printf("      <service>%s</service>%n",   x(r.getService()));
            pw.printf("      <version>%s</version>%n",   x(r.getVersion()));
            pw.printf("      <protocol>%s</protocol>%n", x(r.getProtocol()));
            pw.printf("      <latency>%d</latency>%n",   r.getLatency());
            pw.printf("      <banner>%s</banner>%n",     x(r.getBanner()));
            pw.println("    </port>");
        }
        pw.println("  </results>");
        pw.println("</scan>");
    }

    private void styleDialog(DialogPane dp) {
        if (cssUrl != null) dp.getStylesheets().add(cssUrl.toExternalForm());
        dp.setStyle("-fx-background-color: white; -fx-background-radius: 16; " +
                "-fx-effect: dropshadow(gaussian,rgba(0,0,0,0.2),24,0,0,6); " +
                "-fx-font-family: 'SF Pro Display','Segoe UI',system-ui;");
    }

    private String esc(String s) { return s == null ? "" : s.replace("\"", "\"\""); }
    private String x(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                .replace("\"","&quot;").replace("'","&apos;");
    }
}
