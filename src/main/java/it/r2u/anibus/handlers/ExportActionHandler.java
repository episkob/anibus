package it.r2u.anibus.handlers;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

import it.r2u.anibus.model.JavaScriptAnalysisResult;
import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.export.ExportService;
import javafx.collections.ObservableList;
import javafx.print.PrinterJob;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.DialogPane;
import javafx.scene.control.TextArea;
import javafx.stage.FileChooser;
import javafx.stage.Window;

/**
 * Handler for export operations.
 * Follows Single Responsibility and Command patterns.
 */
public class ExportActionHandler {
    
    private final Consumer<String> statusSetter;
    private final URL cssUrl;
    
    public ExportActionHandler(Consumer<String> statusSetter, URL cssUrl) {
        this.statusSetter = statusSetter;
        this.cssUrl = cssUrl;
    }
    
    /**
     * Export scan results to file with user prompt.
     */
    public void exportResults(ObservableList<PortScanResult> results, Window owner) {
        new ExportService(results, owner, cssUrl, statusSetter)
                .promptAndExport();
    }
    
    /**
     * Export JavaScript analysis results — CSV or XML, same flow as port scan export.
     */
    public void exportJavaScriptAnalysis(JavaScriptAnalysisResult result, String renderedReport) {
        exportJavaScriptAnalysis(result, renderedReport, null);
    }

    public void exportJavaScriptAnalysis(JavaScriptAnalysisResult result, String renderedReport, Window owner) {
        ButtonType csvBtn = new ButtonType("CSV");
        ButtonType xmlBtn = new ButtonType("XML");
        ButtonType pdfBtn = new ButtonType("PDF");
        ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
        Alert fmt = new Alert(Alert.AlertType.NONE, "Choose export format:", csvBtn, xmlBtn, pdfBtn, cancel);
        fmt.setTitle("Export JS Analysis");
        fmt.setHeaderText(null);
        styleDialog(fmt.getDialogPane());

        fmt.showAndWait().ifPresent(choice -> {
            if (choice == cancel) return;
            if (choice == pdfBtn) {
                exportJsPdf(renderedReport, owner);
                return;
            }
            boolean isCsv = (choice == csvBtn);
            File file = pickJsFile(isCsv, owner);
            if (file == null) return;
            try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
                if (isCsv) writeJsCsv(pw, result);
                else        writeJsXml(pw, result);
                statusSetter.accept("JS analysis exported to " + file.getName());
            } catch (IOException e) {
                statusSetter.accept("Export failed: " + e.getMessage());
            }
        });
    }

    private void exportJsPdf(String renderedReport, Window owner) {
        PrinterJob job = PrinterJob.createPrinterJob();
        if (job == null) {
            statusSetter.accept("PDF export unavailable: no printer job support");
            return;
        }
        if (!job.showPrintDialog(owner)) {
            return;
        }
        TextArea printable = new TextArea(renderedReport == null ? "" : renderedReport);
        printable.setWrapText(true);
        printable.setEditable(false);
        printable.setPrefColumnCount(120);
        printable.setPrefRowCount(60);

        boolean ok = job.printPage(printable);
        if (ok) {
            job.endJob();
            statusSetter.accept("JS analysis print/PDF export sent successfully");
        } else {
            statusSetter.accept("JS analysis print/PDF export failed");
        }
    }

    /**
     * Save the current text selection to a plain text file.
     */
    public void exportSelectedText(TextArea textArea, Window owner, String baseName) {
        if (textArea == null) {
            return;
        }

        String selectedText = textArea.getSelectedText();
        if (selectedText == null || selectedText.isBlank()) {
            statusSetter.accept("Select text first");
            return;
        }

        File file = pickTextFile(baseName, owner);
        if (file == null) {
            return;
        }

        try (PrintWriter pw = new PrintWriter(new FileWriter(file))) {
            pw.print(selectedText);
            statusSetter.accept("Selected text saved to " + file.getName());
        } catch (IOException e) {
            statusSetter.accept("Save failed: " + e.getMessage());
        }
    }

    private File pickJsFile(boolean isCsv, Window owner) {
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        FileChooser fc = new FileChooser();
        fc.setTitle("Export JS Analysis");
        if (isCsv) {
            fc.setInitialFileName("js-analysis-" + stamp + ".csv");
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files", "*.csv"));
        } else {
            fc.setInitialFileName("js-analysis-" + stamp + ".xml");
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("XML Files", "*.xml"));
        }
        return fc.showSaveDialog(owner);
    }

    private File pickTextFile(String baseName, Window owner) {
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        String prefix = (baseName == null || baseName.isBlank()) ? "anibus-text" : baseName;
        FileChooser fc = new FileChooser();
        fc.setTitle("Save Selected Text");
        fc.setInitialFileName(prefix + "-" + stamp + ".txt");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        return fc.showSaveDialog(owner);
    }

    private void writeJsCsv(PrintWriter pw, JavaScriptAnalysisResult r) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        pw.println("# JavaScript Security Analysis");
        pw.println("# Target: " + r.getTargetUrl());
        pw.println("# Date: " + ts);
        pw.println("# Analysis Time: " + r.getAnalysisTime() + " ms");
        pw.println();

        pw.println("## ENDPOINTS");
        pw.println("Method,URL,Dynamic");
        r.getEndpoints().forEach(ep ->
            pw.printf("%s,\"%s\",%s%n", esc(ep.getHttpMethod()), esc(ep.getUrl()), ep.isDynamic()));

        pw.println();
        pw.println("## SENSITIVE INFORMATION");
        pw.println("Type,Value,Priority,Placeholder");
        r.getSensitiveInfo().forEach(leak ->
            pw.printf("\"%s\",\"%s\",%d,%s%n",
                esc(leak.getType()), esc(leak.getValue()), leak.getPriority(), leak.isPlaceholder()));

        pw.println();
        pw.println("## DATABASE SCHEMAS");
        pw.println("Table,DatabaseType,Confidence,Columns");
        r.getDatabaseSchemas().forEach(schema -> {
            String cols = String.join("|", schema.getColumns().keySet());
            pw.printf("\"%s\",\"%s\",%.0f%%,\"%s\"%n",
                esc(schema.getTableName()), esc(schema.getDatabaseType().toString()),
                schema.getConfidence() * 100, esc(cols));
        });

        pw.println();
        pw.println("## DATA STRUCTURES");
        pw.println("Name,Type,Properties");
        r.getDataStructures().forEach(ds -> {
            String props = ds.getProperties().entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .reduce("", (a, b) -> a.isEmpty() ? b : a + "|" + b);
            pw.printf("\"%s\",\"%s\",\"%s\"%n", esc(ds.getName()), esc(ds.getType().toString()), esc(props));
        });

        if (r.getArchitecture() != null) {
            pw.println();
            pw.println("## ARCHITECTURE");
            pw.println("Framework,Pattern,StateManagement,Services,Middlewares");
            var a = r.getArchitecture();
            pw.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                esc(a.getFramework().toString()), esc(a.getPattern().toString()), esc(a.getStateManagement().toString()),
                esc(String.join("|", a.getServices())), esc(String.join("|", a.getMiddlewares())));
        }
    }

    private void writeJsXml(PrintWriter pw, JavaScriptAnalysisResult r) {
        String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));
        pw.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        pw.println("<jsAnalysis>");
        pw.printf("  <meta target=\"%s\" timestamp=\"%s\" analysisTimeMs=\"%d\"/>%n",
            x(r.getTargetUrl()), ts, r.getAnalysisTime());

        pw.println("  <endpoints>");
        r.getEndpoints().forEach(ep ->
            pw.printf("    <endpoint method=\"%s\" dynamic=\"%s\"><url>%s</url></endpoint>%n",
                x(ep.getHttpMethod()), ep.isDynamic(), x(ep.getUrl())));
        pw.println("  </endpoints>");

        pw.println("  <sensitiveInfo>");
        r.getSensitiveInfo().forEach(leak ->
            pw.printf("    <leak type=\"%s\" priority=\"%d\" placeholder=\"%s\"><value>%s</value></leak>%n",
                x(leak.getType()), leak.getPriority(), leak.isPlaceholder(), x(leak.getValue())));
        pw.println("  </sensitiveInfo>");

        pw.println("  <databaseSchemas>");
        r.getDatabaseSchemas().forEach(schema -> {
            pw.printf("    <schema table=\"%s\" dbType=\"%s\" confidence=\"%.2f\">%n",
                x(schema.getTableName()), x(schema.getDatabaseType().toString()), schema.getConfidence());
            schema.getColumns().forEach((col, type) ->
                pw.printf("      <column name=\"%s\" type=\"%s\"/>%n", x(col), x(type)));
            pw.println("    </schema>");
        });
        pw.println("  </databaseSchemas>");

        pw.println("  <dataStructures>");
        r.getDataStructures().forEach(ds -> {
            pw.printf("    <structure name=\"%s\" type=\"%s\">%n", x(ds.getName()), x(ds.getType().toString()));
            ds.getProperties().forEach((k, v) ->
                pw.printf("      <property key=\"%s\">%s</property>%n", x(k), x(v)));
            pw.println("    </structure>");
        });
        pw.println("  </dataStructures>");

        if (r.getArchitecture() != null) {
            var a = r.getArchitecture();
            pw.printf("  <architecture framework=\"%s\" pattern=\"%s\" stateManagement=\"%s\" confidence=\"%.2f\">%n",
                x(a.getFramework().toString()), x(a.getPattern().toString()), x(a.getStateManagement().toString()), a.getPatternConfidence());
            a.getServices().forEach(s -> pw.printf("    <service>%s</service>%n", x(s)));
            a.getMiddlewares().forEach(m -> pw.printf("    <middleware>%s</middleware>%n", x(m)));
            pw.println("  </architecture>");
        }

        if (!r.getErrors().isEmpty()) {
            pw.println("  <errors>");
            r.getErrors().forEach(e -> pw.printf("    <error>%s</error>%n", x(e)));
            pw.println("  </errors>");
        }

        pw.println("</jsAnalysis>");
    }

    private void styleDialog(DialogPane dp) {
        if (cssUrl != null) dp.getStylesheets().add(cssUrl.toExternalForm());
        dp.getStyleClass().add("anibus-dialog");
    }

    private String esc(String s) { return s == null ? "" : s.replace("\"", "\"\""); }
    private String x(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }
}
