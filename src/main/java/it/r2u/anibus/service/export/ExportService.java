package it.r2u.anibus.service.export;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Consumer;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.ui.AlertHelper;
import javafx.print.PrinterJob;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.DialogPane;
import javafx.scene.control.TextArea;
import javafx.stage.FileChooser;
import javafx.stage.Window;

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
        ButtonType htmlBtn = new ButtonType("HTML");
        ButtonType pdfBtn  = new ButtonType("PDF");
        ButtonType cancel  = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
        Alert fmt = new Alert(Alert.AlertType.NONE, "Choose export format:", csvBtn, xmlBtn, htmlBtn, pdfBtn, cancel);
        fmt.setTitle("Export Format");
        fmt.setHeaderText(null);
        styleDialog(fmt.getDialogPane());

        fmt.showAndWait().ifPresent(choice -> {
            if (choice == cancel) return;
            if (choice == pdfBtn) {
                exportPdfReport();
                return;
            }
            String ext = (choice == csvBtn) ? "csv" : (choice == htmlBtn) ? "html" : "xml";
            File file = pickFile(ext);
            if (file == null) return;
            try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
                if (choice == csvBtn)       writeCsv(pw);
                else if (choice == htmlBtn) writeHtml(pw);
                else                        writeXml(pw);
                onStatus.accept("Exported " + results.size() + " result(s) to " + file.getName());
            } catch (IOException e) {
                AlertHelper.show("Export failed", e.getMessage(), Alert.AlertType.ERROR, cssUrl);
            }
        });
    }

    private void exportPdfReport() {
        PrinterJob job = PrinterJob.createPrinterJob();
        if (job == null) {
            onStatus.accept("PDF export unavailable: no printer job support");
            return;
        }
        if (!job.showPrintDialog(owner)) {
            return;
        }

        TextArea printable = new TextArea(buildTextReport());
        printable.setWrapText(true);
        printable.setEditable(false);
        printable.setPrefColumnCount(120);
        printable.setPrefRowCount(Math.max(30, results.size() + 10));

        boolean ok = job.printPage(printable);
        if (ok) {
            job.endJob();
            onStatus.accept("Print/PDF export sent to printer successfully");
        } else {
            onStatus.accept("Print/PDF export failed");
        }
    }

    private String buildTextReport() {
        StringBuilder sb = new StringBuilder();
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        sb.append("ANIBUS SCAN REPORT\n");
        sb.append("Generated: ").append(ts).append("\n");
        sb.append("Total results: ").append(results.size()).append("\n\n");
        sb.append(String.format("%-8s %-8s %-18s %-18s %-10s %-10s %s%n",
            "Port", "State", "Service", "Version", "Protocol", "Latency", "Banner"));
        sb.append("-".repeat(120)).append("\n");
        for (PortScanResult r : results) {
            sb.append(String.format("%-8d %-8s %-18s %-18s %-10s %-10d %s%n",
                r.getPort(), safe(r.getState()), trim(safe(r.getService()), 18),
                trim(safe(r.getVersion()), 18), trim(safe(r.getProtocol()), 10),
                r.getLatency(), trim(safe(r.getBanner()), 60)));
        }
        return sb.toString();
    }

    private File pickFile(String ext) {
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        FileChooser fc = new FileChooser();
        fc.setTitle("Export Scan Results");
        fc.setInitialFileName("anibus-scan-" + stamp + "." + ext);
        String desc = switch (ext) {
            case "csv"  -> "CSV Files";
            case "html" -> "HTML Files";
            default     -> "XML Files";
        };
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter(desc, "*." + ext));
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

    private void writeHtml(PrintWriter pw) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        pw.println("<!DOCTYPE html>");
        pw.println("<html lang=\"en\">");
        pw.println("<head>");
        pw.println("  <meta charset=\"UTF-8\">");
        pw.println("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        pw.println("  <title>Anibus Scan Report</title>");
        pw.println("  <style>");
        pw.println("    body { font-family: 'Segoe UI', Arial, sans-serif; background:#0f1117; color:#e0e0e0; margin:0; padding:20px; }");
        pw.println("    h1   { color:#4db6ff; border-bottom:2px solid #4db6ff; padding-bottom:8px; }");
        pw.println("    .meta { color:#888; font-size:0.9em; margin-bottom:16px; }");
        pw.println("    table { border-collapse:collapse; width:100%; }");
        pw.println("    th    { background:#1e2230; color:#4db6ff; padding:10px 12px; text-align:left; border:1px solid #2a2d3d; }");
        pw.println("    td    { padding:8px 12px; border:1px solid #2a2d3d; vertical-align:top; }");
        pw.println("    tr:nth-child(even) { background:#141720; }");
        pw.println("    tr:hover           { background:#1a1f2e; }");
        pw.println("    .open   { color:#4caf50; font-weight:bold; }");
        pw.println("    .closed { color:#f44336; }");
        pw.println("    .filter { width:100%; padding:8px; margin-bottom:12px; background:#1e2230; color:#e0e0e0; border:1px solid #2a2d3d; border-radius:4px; }");
        pw.println("    footer  { margin-top:20px; color:#555; font-size:0.8em; text-align:center; }");
        pw.println("  </style>");
        pw.println("</head>");
        pw.println("<body>");
        pw.println("<h1>Anibus — Scan Report</h1>");
        pw.printf( "<p class=\"meta\">Generated: %s &nbsp;|&nbsp; Total results: %d</p>%n", ts, results.size());
        pw.println("<input class=\"filter\" type=\"text\" id=\"f\" onkeyup=\"filter()\" placeholder=\"Filter by port, service, version…\">");
        pw.println("<table id=\"t\">");
        pw.println("<thead><tr>");
        pw.println("  <th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Protocol</th><th>Latency (ms)</th><th>Banner</th>");
        pw.println("</tr></thead><tbody>");
        for (PortScanResult r : results) {
            String stateClass = "open".equalsIgnoreCase(r.getState()) ? "open" : "closed";
            pw.printf("<tr><td>%d</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>%n",
                r.getPort(), stateClass, h(r.getState()), h(r.getService()),
                h(r.getVersion()), h(r.getProtocol()), r.getLatency(), h(r.getBanner()));
        }
        pw.println("</tbody></table>");
        pw.println("<script>");
        pw.println("function filter(){var v=document.getElementById('f').value.toLowerCase();");
        pw.println("var rows=document.getElementById('t').tBodies[0].rows;");
        pw.println("for(var i=0;i<rows.length;i++){rows[i].style.display=rows[i].innerText.toLowerCase().includes(v)?'':'none';}}");
        pw.println("</script>");
        pw.println("<footer>Generated by Anibus Desktop Security Scanner</footer>");
        pw.println("</body></html>");
    }

    private void styleDialog(DialogPane dp) {
        if (cssUrl != null) dp.getStylesheets().add(cssUrl.toExternalForm());
        dp.getStyleClass().add("anibus-dialog");
    }

    private String h(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
    private String safe(String s) { return s == null ? "" : s; }
    private String trim(String s, int max) { return s.length() <= max ? s : s.substring(0, max - 1) + "…"; }
    private String esc(String s) { return s == null ? "" : s.replace("\"", "\"\""); }
    private String x(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }
}
