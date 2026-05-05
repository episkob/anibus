package it.r2u.anibus;

import java.util.logging.LogManager;

/**
 * Launcher class for JavaFX application.
 * This class serves as a workaround for JavaFX modules in shaded JARs.
 */
public class AnibusLauncher {
    public static void main(String[] args) {
        // Suppress JavaFX unnamed module warning via logging config
        try {
            LogManager.getLogManager().readConfiguration(
                AnibusLauncher.class.getResourceAsStream("/logging.properties"));
        } catch (Exception ignored) {}
        AnibusApplication.main(args);
    }
}