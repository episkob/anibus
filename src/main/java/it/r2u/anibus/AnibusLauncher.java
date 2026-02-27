package it.r2u.anibus;

/**
 * Launcher class for JavaFX application.
 * This class serves as a workaround for JavaFX modules in shaded JARs.
 */
public class AnibusLauncher {
    public static void main(String[] args) {
        // Launch the JavaFX application
        AnibusApplication.main(args);
    }
}