package it.r2u.anibus.ui;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

/**
 * Singleton language manager.
 * Supported locales: EN (default), IT, RU.
 *
 * Properties files live alongside this class (src/main/resources/it/r2u/anibus/ui/):
 *   Messages.properties      — English
 *   Messages_it.properties   — Italian
 *   Messages_ru.properties   — Russian
 */
public class LanguageManager {

    public enum Language {
        EN(Locale.ENGLISH,      "EN"),
        IT(Locale.ITALIAN,      "IT"),
        RU(Locale.of("ru"),     "RU");

        public final Locale locale;
        public final String code;

        Language(Locale locale, String code) {
            this.locale = locale;
            this.code   = code;
        }
    }

    private static final LanguageManager INSTANCE = new LanguageManager();

    private Language       currentLanguage = Language.EN;
    private ResourceBundle bundle;

    private LanguageManager() { loadBundle(Language.EN); }

    public static LanguageManager getInstance() { return INSTANCE; }

    public Language getLanguage() { return currentLanguage; }

    public void setLanguage(Language lang) {
        currentLanguage = lang;
        loadBundle(lang);
    }

    /** Return translated string for {@code key}, or the key itself on miss. */
    public String get(String key) {
        if (bundle == null) return key;
        try { return bundle.getString(key); }
        catch (MissingResourceException e) { return key; }
    }

    // ── Internal ──────────────────────────────────────────────────────────

    private void loadBundle(Language lang) {
        String suffix = (lang == Language.EN) ? "" : "_" + lang.locale.getLanguage();
        String name   = "Messages" + suffix + ".properties";
        InputStream is = LanguageManager.class.getResourceAsStream(name);
        if (is != null) {
            try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
                bundle = new PropertyResourceBundle(reader);
                return;
            } catch (IOException ignored) {}
        }
        // Fallback to English
        if (lang != Language.EN) loadBundle(Language.EN);
    }
}
