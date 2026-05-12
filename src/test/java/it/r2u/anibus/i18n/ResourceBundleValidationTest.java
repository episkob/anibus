package it.r2u.anibus.i18n;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Verifies that all locale bundles (Messages_ru, Messages_it) contain exactly
 * the same keys as the default English bundle (Messages.properties).
 */
class ResourceBundleValidationTest {

    private static final String BASE = "/it/r2u/anibus/ui/Messages";

    @Test
    void allLocalesSynchronizedWithDefaultBundle() throws IOException {
        Set<String> base = loadKeys(BASE + ".properties");
        String[] locales = {"_ru", "_it"};

        List<String> violations = new ArrayList<>();
        for (String locale : locales) {
            Set<String> keys = loadKeys(BASE + locale + ".properties");

            Set<String> missing = new LinkedHashSet<>(base);
            missing.removeAll(keys);
            for (String key : missing) {
                violations.add("[" + locale + "] missing key: " + key);
            }

            Set<String> extra = new LinkedHashSet<>(keys);
            extra.removeAll(base);
            for (String key : extra) {
                violations.add("[" + locale + "] unexpected extra key: " + key);
            }
        }

        assertTrue(violations.isEmpty(),
                "Resource bundle key mismatches detected:\n" + String.join("\n", violations));
    }

    private static Set<String> loadKeys(String resourcePath) throws IOException {
        InputStream is = ResourceBundleValidationTest.class.getResourceAsStream(resourcePath);
        if (is == null) {
            throw new IOException("Resource not found: " + resourcePath);
        }
        Properties props = new Properties();
        try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
            props.load(reader);
        }
        return props.stringPropertyNames();
    }
}
