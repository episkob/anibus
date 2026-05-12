package it.r2u.anibus.ui;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Validates that every FXML file in the classpath can be located and opened.
 * Does NOT load the FXML via FXMLLoader (which requires a JavaFX runtime) —
 * instead we verify that the resource path resolves and the stream is non-empty.
 * This catches typos in resource paths and missing files early, without a display.
 */
class FxmlResourceValidationTest {

    /** All FXML files known to the application. Add new entries here when new views are created. */
    static List<String> fxmlPaths() {
        return List.of(
                "/it/r2u/anibus/hello-view.fxml"
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("fxmlPaths")
    void fxmlFileIsLocatableOnClasspath(String path) throws Exception {
        try (InputStream is = FxmlResourceValidationTest.class.getResourceAsStream(path)) {
            assertNotNull(is, "FXML resource not found on classpath: " + path);
            int firstByte = is.read();
            if (firstByte == -1) {
                fail("FXML resource is empty: " + path);
            }
        }
    }

    @Test
    void allKnownFxmlPathsAreRegistered() {
        // Ensures the static list itself is not empty — prevents the test class
        // from becoming a no-op if someone accidentally clears the list.
        if (fxmlPaths().isEmpty()) {
            fail("fxmlPaths() must contain at least one path");
        }
    }
}
