module it.r2u.anibus {
    requires transitive javafx.base;
    requires transitive javafx.graphics;
    requires transitive javafx.controls;
    requires javafx.fxml;
    requires java.logging;
    requires java.desktop;
    requires java.net.http;
    requires jdk.httpserver;
    requires java.naming;

    // Main package: FXML controller lives here
    opens it.r2u.anibus to javafx.fxml;

    // model: PropertyValueFactory uses reflection on PortScanResult
    opens it.r2u.anibus.model to javafx.base, javafx.controls;

    exports it.r2u.anibus;
    exports it.r2u.anibus.model;
    exports it.r2u.anibus.service.analysis;
    exports it.r2u.anibus.service.core;
    exports it.r2u.anibus.service.detection;
    exports it.r2u.anibus.service.iot;
    exports it.r2u.anibus.service.network;
    exports it.r2u.anibus.service.network.proxy;
    exports it.r2u.anibus.service.geo;
    exports it.r2u.anibus.service.export;
    exports it.r2u.anibus.ui;
    exports it.r2u.anibus.coordinator;
    exports it.r2u.anibus.handlers;
    exports it.r2u.anibus.network;
}
