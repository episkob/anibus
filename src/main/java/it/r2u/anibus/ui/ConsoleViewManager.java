package it.r2u.anibus.ui;

import it.r2u.anibus.model.PortScanResult;
import javafx.application.Platform;
import javafx.scene.control.TextArea;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Manages console view formatting and updates.
 */
public class ConsoleViewManager {
    
    private final TextArea consoleTextArea;
    private boolean isConsoleView;

    private static final int MAX_LINE_WIDTH = 100;
    
    public ConsoleViewManager(TextArea consoleTextArea) {
        this.consoleTextArea = consoleTextArea;
        this.isConsoleView = false;
    }
    
    public boolean isConsoleView() {
        return isConsoleView;
    }
    
    public void toggle() {
        this.isConsoleView = !this.isConsoleView;
    }
    
    public void setConsoleView(boolean consoleView) {
        this.isConsoleView = consoleView;
    }
    
    /**
     * Formats a single port scan result for console display.
     * Parses the enhanced banner into structured, labeled sections.
     */
    public String formatConsoleResult(PortScanResult result) {
        StringBuilder sb = new StringBuilder();

        // ── Header ──────────────────────────────────────────────────────────
        sb.append(String.format("┌─── Port %d ─── %s ─────────────────────────────────────────────────\n",
                result.getPort(), result.getState().toUpperCase()));
        appendField(sb, "Service",  result.getService(), "unknown");
        appendFieldIf(sb, "Version",  result.getVersion());
        appendFieldIf(sb, "Protocol", result.getProtocol());
        sb.append(String.format("│  %-10s %d ms\n", "Latency:", result.getLatency()));

        // ── Parse enhanced banner into sections ─────────────────────────────
        if (result.getBanner() != null && !result.getBanner().isEmpty()) {
            Map<String, List<String>> sections = parseBanner(result.getBanner());
            renderSections(sb, sections);
        }

        sb.append("└──────────────────────────────────────────────────────────────────────\n\n");
        return sb.toString();
    }

    // =====================================================================
    //  Banner parser — splits the flat enhanced banner into labeled sections
    // =====================================================================

    private static Map<String, List<String>> parseBanner(String banner) {
        Map<String, List<String>> sections = new LinkedHashMap<>();
        // Define section order/keys
        String currentSection = "BANNER";

        for (String rawLine : banner.split("\n")) {
            String line = rawLine.trim();
            if (line.isEmpty()) continue;

            // Detect section transitions by known tag prefixes
            if (line.startsWith("[OS]")) {
                currentSection = "OS";
                line = line.substring(4).trim();
            } else if (line.startsWith("[WARN] Found") && line.contains("vulnerabilit")) {
                currentSection = "VULNERABILITIES";
                line = line.substring(6).trim();      // strip [WARN]
            } else if (line.startsWith("[GEO]")) {
                currentSection = "GEOLOCATION";
                line = line.substring(5).trim();
            } else if (line.startsWith("[TITLE]")) {
                currentSection = "HTTP";
                line = line.substring(7).trim();
            } else if (line.startsWith("[CMS]")) {
                currentSection = "HTTP";
                line = line.substring(5).trim();
            } else if (line.startsWith("[TECH]")) {
                currentSection = "HTTP";
                line = line.substring(6).trim();
            } else if (line.startsWith("[SSL]")) {
                currentSection = "SSL";
                line = line.substring(5).trim();
            } else if (line.startsWith("[SECURE]") || line.startsWith("[INSECURE]")) {
                currentSection = "SECURITY HEADERS";
                line = line.replaceFirst("^\\[(IN)?SECURE\\]\\s*", "");
            } else if (line.startsWith("[IOT]")) {
                currentSection = "IOT DEVICE";
                line = line.substring(5).trim();
            } else if (line.startsWith("[KEYCLOAK]")) {
                currentSection = "KEYCLOAK IAM";
                line = line.substring(10).trim();
            } else if (line.startsWith("[CONTAINER]")) {
                currentSection = "CONTAINER";
                line = line.substring(11).trim();
            } else if (line.startsWith("[ORCHESTRATOR]")) {
                currentSection = "CONTAINER";
                line = line.substring(14).trim();
            } else if (line.startsWith("[INDICATORS]")) {
                currentSection = "CONTAINER";
                line = line.substring(12).trim();
            } else if (line.contains("[ALERT] LEAKS:")) {
                currentSection = "LEAKS";
                line = line.substring(line.indexOf("[ALERT] LEAKS:") + 14).trim();
            } else if (line.startsWith("[WARN]") && line.contains("Exposed APIs")) {
                currentSection = "CONTAINER";
                line = line.substring(6).trim();
            } else if (line.startsWith("[WARN]") && line.contains("CRITICAL")) {
                currentSection = "CRITICAL WARNINGS";
                line = line.replaceAll("\\[WARN\\]", "").trim();
            }

            // Remove leading "  " indentation from sub-lines of detectors
            line = line.replaceFirst("^\\s{2,4}", "");

            sections.computeIfAbsent(currentSection, k -> new ArrayList<>()).add(line);
        }

        return sections;
    }

    // =====================================================================
    //  Renderer — writes each section with its own sub-header
    // =====================================================================

    private static void renderSections(StringBuilder sb, Map<String, List<String>> sections) {
        for (Map.Entry<String, List<String>> entry : sections.entrySet()) {
            String section = entry.getKey();
            List<String> lines = entry.getValue();
            if (lines.isEmpty()) continue;

            switch (section) {
                case "BANNER" -> renderBannerSection(sb, lines);
                case "OS" -> renderSimpleSection(sb, "Operating System", lines);
                case "VULNERABILITIES" -> renderSimpleSection(sb, "Vulnerabilities", lines);
                case "GEOLOCATION" -> renderSimpleSection(sb, "Geolocation", lines);
                case "HTTP" -> renderSimpleSection(sb, "HTTP Analysis", lines);
                case "SSL" -> renderSimpleSection(sb, "SSL/TLS", lines);
                case "SECURITY HEADERS" -> renderSimpleSection(sb, "Security Headers", lines);
                case "IOT DEVICE" -> renderSimpleSection(sb, "IoT Device", lines);
                case "KEYCLOAK IAM" -> renderSimpleSection(sb, "Keycloak IAM", lines);
                case "CONTAINER" -> renderSimpleSection(sb, "Container / Orchestration", lines);
                case "LEAKS" -> renderLeaksSection(sb, lines);
                case "CRITICAL WARNINGS" -> renderSimpleSection(sb, "CRITICAL", lines);
                default -> renderSimpleSection(sb, section, lines);
            }
        }
    }

    /** Raw HTTP banner — truncate long header dumps to first 3 lines + char limit. */
    private static void renderBannerSection(StringBuilder sb, List<String> lines) {
        sb.append("│\n│  ── Banner ──────────────────────────────────────────────────────\n");
        int shown = 0;
        for (String line : lines) {
            if (shown >= 3) {
                sb.append(String.format("│     ... (%d more header lines)\n", lines.size() - shown));
                break;
            }
            sb.append(wrapLine("│     ", line));
            shown++;
        }
    }

    /** Leak data — show only summary + truncated first match. */
    private static void renderLeaksSection(StringBuilder sb, List<String> lines) {
        sb.append("│\n│  ── Detected Leaks ──────────────────────────────────────────────\n");
        for (String line : lines) {
            // Each leak line can be enormous (minified JS). Truncate aggressively.
            if (line.length() > 200) {
                sb.append(String.format("│     %s...\n", line.substring(0, 200)));
                sb.append(String.format("│     (truncated — %d chars total)\n", line.length()));
            } else {
                sb.append(wrapLine("│     ", line));
            }
        }
    }

    /** Standard named section with a sub-header. */
    private static void renderSimpleSection(StringBuilder sb, String title, List<String> lines) {
        sb.append(String.format("│\n│  ── %s ──\n", title));
        for (String line : lines) {
            sb.append(wrapLine("│     ", line));
        }
    }

    // =====================================================================
    //  Helpers
    // =====================================================================

    private static void appendField(StringBuilder sb, String label, String value, String fallback) {
        String v = (value != null && !value.isEmpty()) ? value : fallback;
        sb.append(String.format("│  %-10s %s\n", label + ":", v));
    }

    private static void appendFieldIf(StringBuilder sb, String label, String value) {
        if (value != null && !value.isEmpty()) {
            sb.append(String.format("│  %-10s %s\n", label + ":", value));
        }
    }

    /** Word-wrap a line respecting MAX_LINE_WIDTH, each continuation prefixed with indent. */
    private static String wrapLine(String indent, String text) {
        if (text == null || text.isEmpty()) return "";
        int maxPayload = MAX_LINE_WIDTH - indent.length();
        if (maxPayload <= 0 || text.length() <= maxPayload) {
            return indent + text + "\n";
        }
        StringBuilder wrapped = new StringBuilder();
        int pos = 0;
        while (pos < text.length()) {
            int end = Math.min(pos + maxPayload, text.length());
            wrapped.append(indent).append(text, pos, end).append("\n");
            pos = end;
        }
        return wrapped.toString();
    }
    
    /**
     * Updates console with all results (used when switching from table view).
     */
    public void updateConsoleWithAllResults(List<PortScanResult> results) {
        if (consoleTextArea == null) return;
        
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        sb.append("                        ANIBUS SCAN RESULTS                            \n");
        sb.append("═══════════════════════════════════════════════════════════════════════\n\n");
        
        if (results.isEmpty()) {
            sb.append("No results to display\n");
        } else {
            for (PortScanResult result : results) {
                sb.append(formatConsoleResult(result));
            }
        }
        
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        sb.append(String.format("Total: %d open port%s\n", results.size(), results.size() == 1 ? "" : "s"));
        sb.append("═══════════════════════════════════════════════════════════════════════\n");
        
        consoleTextArea.setText(sb.toString());
    }
    
    /**
     * Appends a single result to console (for live updates during scanning).
     */
    public void appendToConsole(PortScanResult result) {
        if (consoleTextArea == null || !isConsoleView) return;
        
        Platform.runLater(() -> {
            String current = consoleTextArea.getText();
            if (current.isEmpty()) {
                // First result - add header
                consoleTextArea.setText(
                    "═══════════════════════════════════════════════════════════════════════\n" +
                    "                        ANIBUS SCAN RESULTS                            \n" +
                    "═══════════════════════════════════════════════════════════════════════\n\n" +
                    formatConsoleResult(result)
                );
            } else {
                consoleTextArea.appendText(formatConsoleResult(result));
            }
            
            // Auto-scroll to bottom
            consoleTextArea.setScrollTop(Double.MAX_VALUE);
        });
    }
    
    /**
     * Clears the console text area.
     */
    public void clear() {
        if (consoleTextArea != null) {
            consoleTextArea.clear();
        }
    }
}
