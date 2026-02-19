package it.r2u.anibus;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class HelloApplication extends Application {

    private HelloController controller;

    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("hello-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 1200, 800);

        // Добавляем iOS-стиль CSS
        scene.getStylesheets().add(HelloApplication.class.getResource("ios-style.css").toExternalForm());

        controller = fxmlLoader.getController();

        stage.setTitle("Anibus - Port Scanner");
        stage.setScene(scene);
        stage.setMinWidth(800);
        stage.setMinHeight(600);
        stage.show();
    }

    @Override
    public void stop() throws Exception {
        super.stop();
        if (controller != null) {
            controller.shutdownExecutor();
        }
    }

    public static void main(String[] args) {
        launch();
    }
}
