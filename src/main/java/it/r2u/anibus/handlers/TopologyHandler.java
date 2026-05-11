package it.r2u.anibus.handlers;

import it.r2u.anibus.service.network.TracerouteService;

import javafx.scene.control.Tab;
import javafx.scene.layout.Pane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.scene.shape.Line;
import javafx.scene.text.Text;

import java.util.List;

/**
 * Renders the traceroute topology graph (extracted from AnibusController).
 */
public class TopologyHandler {

    private final Pane topologyGraphPane;
    private final Tab  tabTopology;

    public TopologyHandler(Pane topologyGraphPane, Tab tabTopology) {
        this.topologyGraphPane = topologyGraphPane;
        this.tabTopology       = tabTopology;
    }

    public void renderTopologyGraph(TracerouteService.TraceRoute trace) {
        if (topologyGraphPane == null || trace == null) {
            return;
        }
        topologyGraphPane.getChildren().clear();

        List<TracerouteService.Hop> hops = trace.getHops();
        if (hops.isEmpty()) {
            Text empty = new Text("No hops captured for traceroute to " + trace.getTargetHost());
            empty.setLayoutX(20);
            empty.setLayoutY(40);
            topologyGraphPane.getChildren().add(empty);
            return;
        }

        double x    = 60;
        double y    = 140;
        double step = 160;

        Text title = new Text("Target: " + trace.getTargetHost()
            + (trace.getTargetIP() != null ? " (" + trace.getTargetIP() + ")" : ""));
        title.setLayoutX(20);
        title.setLayoutY(24);
        topologyGraphPane.getChildren().add(title);

        for (int i = 0; i < hops.size(); i++) {
            TracerouteService.Hop hop = hops.get(i);

            Circle node = new Circle(x, y, 18);
            node.setFill(hop.isTimeout()
                ? Color.web("#ff9f0a")
                : Color.web("#30d158"));

            Text hopNo = new Text(String.valueOf(hop.getHopNumber()));
            hopNo.setLayoutX(x - 4);
            hopNo.setLayoutY(y + 4);

            String host = hop.getIpAddress() != null ? hop.getIpAddress() : "timeout";
            long avg = hop.getAverageRTT();
            Text label = new Text(host + (avg >= 0 ? "  (" + avg + " ms)" : ""));
            label.setLayoutX(x - 50);
            label.setLayoutY(y + 34);

            topologyGraphPane.getChildren().addAll(node, hopNo, label);

            if (i < hops.size() - 1) {
                Line edge = new Line(x + 20, y, x + step - 20, y);
                edge.setStroke(Color.web("#6c757d"));
                topologyGraphPane.getChildren().add(edge);
            }
            x += step;
        }

        topologyGraphPane.setPrefWidth(Math.max(1200, hops.size() * step + 120));
        tabTopology.getTabPane().getSelectionModel().select(tabTopology);
    }
}
