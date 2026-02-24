package it.r2u.anibus.ui;

import it.r2u.anibus.model.PortScanResult;

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
                getStyleClass().remove("state-open");
                if (empty || val == null) {
                    setText(null);
                } else {
                    setText(val);
                    getStyleClass().add("state-open");
                }
            }
        });

        serviceCol.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String val, boolean empty) {
                super.updateItem(val, empty);
                getStyleClass().removeAll("service-enhanced", "service-standard");
                if (empty || val == null) {
                    setText(null);
                } else {
                    setText(val);
                    TableRow<?> row = getTableRow();
                    if (row != null && row.getItem() instanceof PortScanResult result) {
                        if ("Service Detection".equals(result.getScanMode())) {
                            getStyleClass().add("service-enhanced");
                        } else {
                            getStyleClass().add("service-standard");
                        }
                    }
                }
            }
        });

        protocolCol.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String val, boolean empty) {
                super.updateItem(val, empty);
                getStyleClass().removeAll("protocol-enhanced");
                if (empty || val == null) {
                    setText(null);
                } else {
                    setText(val);
                    TableRow<?> row = getTableRow();
                    if (row != null && row.getItem() instanceof PortScanResult result) {
                        if ("Service Detection".equals(result.getScanMode())) {
                            getStyleClass().add("protocol-enhanced");
                        }
                    }
                }
            }
        });

        table.setRowFactory(tv -> {
            TableRow<PortScanResult> row = new TableRow<>() {
                @Override
                protected void updateItem(PortScanResult item, boolean empty) {
                    super.updateItem(item, empty);
                    getStyleClass().removeAll("result-row", "row-standard", "row-service-detection");
                    if (!empty && item != null) {
                        getStyleClass().add("result-row");
                        if ("Service Detection".equals(item.getScanMode())) {
                            getStyleClass().add("row-service-detection");
                        } else {
                            getStyleClass().add("row-standard");
                        }
                    }
                }
            };
            return row;
        });

        Label placeholder = new Label("No results yet — start a scan above");
        placeholder.getStyleClass().add("table-placeholder");
        table.setPlaceholder(placeholder);
    }
}
