package it.r2u.anibus.ui;

import it.r2u.anibus.model.PortScanResult;

import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;

import java.util.List;

/**
 * Utility for copying scan results to the system clipboard.
 */
public class ClipboardService {

    public static void copy(String text) {
        ClipboardContent cc = new ClipboardContent();
        cc.putString(text);
        Clipboard.getSystemClipboard().setContent(cc);
    }

    public static String formatRow(PortScanResult r) {
        return String.format(
                "Port: %d, State: %s, Service: %s, Version: %s, Protocol: %s, Latency: %dms, Banner: %s",
                r.getPort(), r.getState(), r.getService(), r.getVersion(),
                r.getProtocol(), r.getLatency(), r.getBanner());
    }

    public static String formatAll(List<PortScanResult> results) {
        StringBuilder sb = new StringBuilder("Port\tState\tService\tVersion\tProtocol\tLatency\tBanner\n");
        for (PortScanResult r : results) {
            sb.append(r.getPort()).append('\t')
              .append(r.getState()).append('\t')
              .append(r.getService()).append('\t')
              .append(r.getVersion()).append('\t')
              .append(r.getProtocol()).append('\t')
              .append(r.getLatency()).append("ms\t")
              .append(r.getBanner()).append('\n');
        }
        return sb.toString();
    }
}
