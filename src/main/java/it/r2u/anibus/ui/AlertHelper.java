package it.r2u.anibus.ui;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.DialogPane;

import java.net.URL;

/**
 * Displays styled modal alerts using the Anibus design system.
 */
public class AlertHelper {

    public static void show(String title, String message, Alert.AlertType type, URL cssUrl) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);

        DialogPane dp = alert.getDialogPane();
        if (cssUrl != null) dp.getStylesheets().add(cssUrl.toExternalForm());
        dp.getStyleClass().add("anibus-dialog");
        dp.lookupButton(ButtonType.OK).getStyleClass().add("anibus-dialog-ok-button");

        alert.showAndWait();
    }
}
