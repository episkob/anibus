package it.r2u.anibus.handlers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import it.r2u.anibus.service.network.TracerouteService;
import javafx.scene.control.Tab;
import javafx.scene.layout.Pane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.scene.shape.Line;
import javafx.scene.shape.Rectangle;
import javafx.scene.text.Text;

/**
 * Renders the traceroute topology graph (extracted from AnibusController).
 *
 * <p>Extended with ASN/Geo clustering: hops sharing the same /24 subnet prefix
 * are visually grouped in a labelled cluster box, and auto-layout + zoom-to-fit
 * adjusts the viewport so all nodes are always visible.
 */
public class TopologyHandler {

    private final Pane topologyGraphPane;
    private final Tab  tabTopology;

    public TopologyHandler(Pane topologyGraphPane, Tab tabTopology) {
        this.topologyGraphPane = topologyGraphPane;
        this.tabTopology       = tabTopology;
    }

    // ── Basic render (backward-compatible) ───────────────────────────────────

    public void renderTopologyGraph(TracerouteService.TraceRoute trace) {
        renderTopologyGraph(trace, false);
    }

    /**
     * Renders the topology graph.
     *
     * @param trace        traceroute result
     * @param clusterByAsn when true, hops sharing the same /24 prefix are
     *                     drawn inside a labelled ASN cluster box
     */
    public void renderTopologyGraph(TracerouteService.TraceRoute trace, boolean clusterByAsn) {
        if (topologyGraphPane == null || trace == null) return;
        topologyGraphPane.getChildren().clear();

        List<TracerouteService.Hop> hops = trace.getHops();
        if (hops.isEmpty()) {
            Text empty = new Text("No hops captured for traceroute to " + trace.getTargetHost());
            empty.setLayoutX(20);
            empty.setLayoutY(40);
            topologyGraphPane.getChildren().add(empty);
            return;
        }

        Text title = new Text("Target: " + trace.getTargetHost()
            + (trace.getTargetIP() != null ? " (" + trace.getTargetIP() + ")" : ""));
        title.setLayoutX(20);
        title.setLayoutY(24);
        topologyGraphPane.getChildren().add(title);

        if (clusterByAsn) {
            renderClustered(hops);
        } else {
            renderLinear(hops);
        }

        applyZoomToFit();
        tabTopology.getTabPane().getSelectionModel().select(tabTopology);
    }

    // ── Linear layout (original behaviour) ───────────────────────────────────

    private void renderLinear(List<TracerouteService.Hop> hops) {
        double x    = 60;
        double y    = 140;
        double step = 160;

        for (int i = 0; i < hops.size(); i++) {
            TracerouteService.Hop hop = hops.get(i);
            addHopNode(hop, x, y);

            if (i < hops.size() - 1) {
                Line edge = new Line(x + 20, y, x + step - 20, y);
                edge.setStroke(Color.web("#6c757d"));
                topologyGraphPane.getChildren().add(edge);
            }
            x += step;
        }
        topologyGraphPane.setPrefWidth(Math.max(1200, hops.size() * step + 120));
    }

    // ── Clustered layout (ASN / /24 grouping) ────────────────────────────────

    private void renderClustered(List<TracerouteService.Hop> hops) {
        // Group consecutive hops by /24 prefix
        Map<String, List<TracerouteService.Hop>> clusters = new LinkedHashMap<>();
        for (TracerouteService.Hop hop : hops) {
            String key = prefixKey(hop);
            clusters.computeIfAbsent(key, k -> new ArrayList<>()).add(hop);
        }

        double clusterX   = 40;
        double clusterY   = 60;
        double nodeSpacingX = 130;
        double clusterPad   = 20;
        double clusterH     = 120;
        String prevClusterEdgeX = null;

        for (Map.Entry<String, List<TracerouteService.Hop>> entry : clusters.entrySet()) {
            String clusterKey = entry.getKey();
            List<TracerouteService.Hop> group = entry.getValue();

            double clusterW = clusterPad * 2 + group.size() * nodeSpacingX;

            // Cluster background box
            Rectangle box = new Rectangle(clusterX, clusterY, clusterW, clusterH);
            box.setFill(Color.web("#1c1c1e40"));
            box.setStroke(Color.web("#48484a"));
            box.setArcWidth(12);
            box.setArcHeight(12);
            topologyGraphPane.getChildren().add(box);

            // Cluster label (AS group / prefix)
            if (!"??".equals(clusterKey)) {
                Text label = new Text(clusterKey);
                label.setLayoutX(clusterX + 6);
                label.setLayoutY(clusterY + 14);
                label.setStyle("-fx-font-size:10;");
                topologyGraphPane.getChildren().add(label);
            }

            // Nodes inside cluster
            double nodeX = clusterX + clusterPad;
            double nodeY = clusterY + clusterH / 2.0;
            String firstNodeX = null;
            String lastNodeX = null;

            for (int i = 0; i < group.size(); i++) {
                TracerouteService.Hop hop = group.get(i);
                addHopNode(hop, nodeX, nodeY);
                if (i == 0) firstNodeX = nodeX + "";
                lastNodeX = nodeX + "";

                if (i < group.size() - 1) {
                    Line edge = new Line(nodeX + 20, nodeY, nodeX + nodeSpacingX - 20, nodeY);
                    edge.setStroke(Color.web("#6c757d"));
                    topologyGraphPane.getChildren().add(edge);
                }
                nodeX += nodeSpacingX;
            }

            // Inter-cluster edge
            if (prevClusterEdgeX != null && firstNodeX != null) {
                double fx = Double.parseDouble(prevClusterEdgeX);
                double tx = Double.parseDouble(firstNodeX);
                if (tx > fx) {
                    Line edge = new Line(fx, clusterY + clusterH / 2.0,
                        tx - 20, clusterY + clusterH / 2.0);
                    edge.setStroke(Color.web("#636366"));
                    edge.getStrokeDashArray().addAll(6.0, 4.0);
                    topologyGraphPane.getChildren().add(edge);
                }
            }
            prevClusterEdgeX = lastNodeX;
            clusterX += clusterW + 30;
        }

        topologyGraphPane.setPrefWidth(Math.max(1200, clusterX + 60));
    }

    // ── Shared node drawing ───────────────────────────────────────────────────

    private void addHopNode(TracerouteService.Hop hop, double x, double y) {
        Circle node = new Circle(x, y, 18);
        node.setFill(hop.isTimeout() ? Color.web("#ff9f0a") : Color.web("#30d158"));

        Text hopNo = new Text(String.valueOf(hop.getHopNumber()));
        hopNo.setLayoutX(x - 4);
        hopNo.setLayoutY(y + 4);

        String host = hop.getIpAddress() != null ? hop.getIpAddress() : "timeout";
        long avg = hop.getAverageRTT();
        Text label = new Text(host + (avg >= 0 ? "  (" + avg + " ms)" : ""));
        label.setLayoutX(x - 50);
        label.setLayoutY(y + 34);

        topologyGraphPane.getChildren().addAll(node, hopNo, label);
    }

    // ── Zoom to fit ───────────────────────────────────────────────────────────

    /**
     * Scales the pane content so all nodes fit inside the visible viewport.
     * The parent's width is used as the available space.
     */
    private void applyZoomToFit() {
        double contentWidth = topologyGraphPane.getPrefWidth();
        if (contentWidth <= 0) return;
        double viewportWidth = topologyGraphPane.getParent() != null
            ? topologyGraphPane.getParent().getLayoutBounds().getWidth()
            : 1200;
        if (viewportWidth <= 0 || viewportWidth >= contentWidth) {
            topologyGraphPane.setScaleX(1.0);
            topologyGraphPane.setScaleY(1.0);
            return;
        }
        double scale = Math.max(0.2, viewportWidth / contentWidth);
        topologyGraphPane.setScaleX(scale);
        topologyGraphPane.setScaleY(scale);
        // Shift so the scaled content is left-aligned rather than centre-anchored
        topologyGraphPane.setTranslateX(-(contentWidth * (1 - scale)) / 2.0);
    }

    // ── Cluster key ──────────────────────────────────────────────────────────

    private String prefixKey(TracerouteService.Hop hop) {
        String ip = hop.getIpAddress();
        if (ip == null) return "??";
        // Use /24 prefix as cluster key (first three octets)
        String[] parts = ip.split("\\.");
        if (parts.length == 4) return parts[0] + "." + parts[1] + "." + parts[2] + ".x";
        return ip;
    }
}

