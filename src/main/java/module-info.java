module it.r2u.anibus {
    // Import required JavaFX modules and external libraries
    requires transitive javafx.base;
    requires transitive javafx.graphics;
    requires transitive javafx.controls;
    requires javafx.fxml;

    // Open the it.r2u.anibus package to javafx.fxml.
    // This is necessary so the FXML loader can create controller instances
    // and access fields annotated with @FXML.
    opens it.r2u.anibus to javafx.fxml;

    // Export the package so that other modules (if any)
    // can use classes from it.
    // Not strictly necessary here, but good practice.
    exports it.r2u.anibus;
}
