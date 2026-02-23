module it.r2u.anibus {
    requires transitive javafx.base;
    requires transitive javafx.graphics;
    requires transitive javafx.controls;
    requires javafx.fxml;

    // Main package: FXML controller lives here
    opens it.r2u.anibus to javafx.fxml;

    // model: PropertyValueFactory uses reflection on PortScanResult
    opens it.r2u.anibus.model to javafx.base, javafx.controls;

    // service & ui: opened for potential future FXML use
    opens it.r2u.anibus.service to javafx.fxml;
    opens it.r2u.anibus.ui to javafx.fxml;

    exports it.r2u.anibus;
    exports it.r2u.anibus.model;
    exports it.r2u.anibus.service;
    exports it.r2u.anibus.ui;
}
