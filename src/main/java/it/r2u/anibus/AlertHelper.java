package it.r2u.anibus;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.DialogPane;

import java.net.URL;

/**
 * Displays styled iOS-look modal alerts.
 */
public class AlertHelper {

    public static void show(String title, String message, Alert.AlertType type, URL cssUrl) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);

        DialogPane dp = alert.getDialogPane();
        if (cssUrl != null) dp.getStylesheets().add(cssUrl.toExternalForm());
        dp.setStyle(
                "-fx-background-color: white;" +
                "-fx-background-radius: 16;" +
                "-fx-effect: dropshadow(gaussian, rgba(0,0,0,0.2), 24, 0, 0, 6);" +
                "-fx-font-family: 'SF Pro Display', 'Segoe UI', system-ui;");
        dp.lookupButton(ButtonType.OK).setStyle(
                "-fx-background-color: #007AFF;" +
                "-fx-background-radius: 10;" +
                "-fx-text-fill: white;" +
                "-fx-font-weight: 600;" +
                "-fx-padding: 10 20;");

        alert.showAndWait();
    }
}
