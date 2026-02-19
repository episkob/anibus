package it.r2u.anibus;

import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;

/**
 * Configures cell value factories, cell factories, row styles,
 * and placeholder for the results TableView.
 */
public class TableConfigurator {

    public static void setup(
            TableView<PortScanResult>            table,
            TableColumn<PortScanResult, Integer> portCol,
            TableColumn<PortScanResult, String>  stateCol,
            TableColumn<PortScanResult, String>  serviceCol,
            TableColumn<PortScanResult, String>  versionCol,
            TableColumn<PortScanResult, String>  protocolCol,
            TableColumn<PortScanResult, Long>    latencyCol,
            TableColumn<PortScanResult, String>  bannerCol) {

        portCol.setCellValueFactory(new PropertyValueFactory<>("port"));
        stateCol.setCellValueFactory(new PropertyValueFactory<>("state"));
        serviceCol.setCellValueFactory(new PropertyValueFactory<>("service"));
        versionCol.setCellValueFactory(new PropertyValueFactory<>("version"));
        protocolCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        latencyCol.setCellValueFactory(new PropertyValueFactory<>("latency"));
        bannerCol.setCellValueFactory(new PropertyValueFactory<>("banner"));

        latencyCol.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(Long val, boolean empty) {
                super.updateItem(val, empty);
                setText(empty || val == null ? "" : val + " ms");
            }
        });

        stateCol.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String val, boolean empty) {
                super.updateItem(val, empty);
                if (empty || val == null) { setText(null); setStyle(""); }
                else { setText(val); setStyle("-fx-text-fill: #34C759; -fx-font-weight: 600;"); }
            }
        });

        table.setRowFactory(tv -> {
            TableRow<PortScanResult> row = new TableRow<>();
            row.setStyle("-fx-background-color: transparent; -fx-border-width: 0 0 0.5 0; -fx-border-color: #E5E5EA;");
            return row;
        });

        Label placeholder = new Label("No results yet — start a scan above");
        placeholder.setStyle("-fx-text-fill: #AEAEB2; -fx-font-size: 15;");
        table.setPlaceholder(placeholder);
    }
}
