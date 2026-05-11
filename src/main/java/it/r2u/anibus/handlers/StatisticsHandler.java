package it.r2u.anibus.handlers;

import it.r2u.anibus.model.PortScanResult;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;

import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Handles statistics dashboard rendering (extracted from AnibusController).
 */
public class StatisticsHandler {

    private final PieChart statsPortStateChart;
    private final BarChart<String, Number> statsServiceChart;
    private final BarChart<String, Number> statsRiskChart;
    private final ObservableList<PortScanResult> results;

    public StatisticsHandler(
            PieChart statsPortStateChart,
            BarChart<String, Number> statsServiceChart,
            BarChart<String, Number> statsRiskChart,
            ObservableList<PortScanResult> results) {
        this.statsPortStateChart = statsPortStateChart;
        this.statsServiceChart   = statsServiceChart;
        this.statsRiskChart      = statsRiskChart;
        this.results             = results;
    }

    public void updateStatisticsDashboard() {
        if (statsPortStateChart == null || statsServiceChart == null || statsRiskChart == null) {
            return;
        }

        long open   = results.stream().filter(r -> "Open".equalsIgnoreCase(r.getState())).count();
        long closed = Math.max(0, results.size() - open);
        statsPortStateChart.setData(FXCollections.observableArrayList(
            new PieChart.Data("Open", open),
            new PieChart.Data("Other", closed)
        ));

        Map<String, Long> byService = results.stream()
            .collect(Collectors.groupingBy(
                r -> {
                    String s = r.getService();
                    return (s == null || s.isBlank()) ? "unknown" : s;
                },
                Collectors.counting()
            ));

        XYChart.Series<String, Number> serviceSeries = new XYChart.Series<>();
        byService.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .limit(8)
            .forEach(e -> serviceSeries.getData().add(new XYChart.Data<>(e.getKey(), e.getValue())));
        serviceSeries.setName("Services");
        statsServiceChart.getData().setAll(serviceSeries);

        long highRisk   = results.stream().filter(this::isHighRiskPort).count();
        long mediumRisk = results.stream().filter(this::isMediumRiskPort).count();
        long lowRisk    = Math.max(0, results.size() - highRisk - mediumRisk);

        XYChart.Series<String, Number> riskSeries = new XYChart.Series<>();
        riskSeries.getData().add(new XYChart.Data<>("High", highRisk));
        riskSeries.getData().add(new XYChart.Data<>("Medium", mediumRisk));
        riskSeries.getData().add(new XYChart.Data<>("Low", lowRisk));
        riskSeries.setName("Risk");
        statsRiskChart.getData().setAll(riskSeries);
    }

    private boolean isHighRiskPort(PortScanResult r) {
        int port = r.getPort();
        String service = r.getService() != null ? r.getService().toLowerCase(Locale.ROOT) : "";
        return port == 23 || port == 445 || port == 3389
            || service.contains("telnet") || service.contains("rdp");
    }

    private boolean isMediumRiskPort(PortScanResult r) {
        int port = r.getPort();
        String service = r.getService() != null ? r.getService().toLowerCase(Locale.ROOT) : "";
        return port == 21 || port == 22 || port == 3306 || port == 5432
            || service.contains("ftp") || service.contains("ssh") || service.contains("mysql");
    }
}
