package it.r2u.anibus.model;

/**
 * Port registry backed by external property files in the {@code ports/} resource folder.
 *
 * <p>File format (one entry per line):
 * <pre>port=Service Name|Protocol String</pre>
 * Lines starting with {@code #} are treated as comments.
 *
 * <p>The registry reads {@code ports/index.txt} to discover which files to load.
 * If a port number is not listed in any file, {@link #getServiceName} returns
 * {@code "Unrecognized"} and {@link #getProtocol} falls back to banner-based
 * TLS detection or plain {@code "TCP"}.
 *
 */
public class PortRegistry {

    // -- Resource paths ------------------------------------------------------
    private static final String PORTS_BASE = "/it/r2u/anibus/ports/";
    private static final String INDEX_FILE = PORTS_BASE + "index.txt";

    // -- In-memory lookup maps (populated once from files) -------------------
    private static final java.util.Map<Integer, String> NAMES     = new java.util.HashMap<>();
    private static final java.util.Map<Integer, String> PROTOCOLS = new java.util.HashMap<>();

    // -- Banner keywords that imply an encrypted transport -------------------
    private static final String[] ENCRYPTION_KEYWORDS = {
        "starttls", "tls", "ssl", "https", "smtps", "imaps", "pop3s",
        "aes", "rsa", "sha", "gcm", "ecdhe", "dhe", "cipher", "certificate"
    };

    // -- Static initialiser: load all port files listed in index.txt ---------
    static {
        try (java.io.InputStream idx = PortRegistry.class.getResourceAsStream(INDEX_FILE)) {
            if (idx != null) {
                java.io.BufferedReader idxReader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(idx, java.nio.charset.StandardCharsets.UTF_8));
                String filename;
                while ((filename = idxReader.readLine()) != null) {
                    filename = filename.trim();
                    if (filename.isEmpty() || filename.startsWith("#")) continue;
                    loadPortFile(PORTS_BASE + filename);
                }
            }
        } catch (java.io.IOException ignored) {}
    }

    /** Parses a single port-definition file and populates NAMES / PROTOCOLS. */
    private static void loadPortFile(String resourcePath) {
        try (java.io.InputStream in = PortRegistry.class.getResourceAsStream(resourcePath)) {
            if (in == null) return;
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(in, java.nio.charset.StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                if (eq < 1) continue;
                try {
                    int port = Integer.parseInt(line.substring(0, eq).trim());
                    String rest = line.substring(eq + 1);
                    int pipe = rest.indexOf('|');
                    String name     = (pipe >= 0 ? rest.substring(0, pipe) : rest).trim();
                    String protocol = (pipe >= 0 ? rest.substring(pipe + 1) : "").trim();
                    NAMES.put(port, name);
                    if (!protocol.isEmpty()) PROTOCOLS.put(port, protocol);
                } catch (NumberFormatException ignored) {}
            }
        } catch (java.io.IOException ignored) {}
    }

    // -- Public API ----------------------------------------------------------

    /**
     * Returns the human-readable service name for {@code port}.
     * Returns {@code "Unrecognized"} if no port file covers this port number.
     */
    public static String getServiceName(int port) {
        return NAMES.getOrDefault(port, "Unrecognized");
    }

    /**
     * Returns a protocol / transport descriptor for {@code port}.
     * Resolution order:
     * <ol>
     *   <li>Protocol string stored in the port definition file.</li>
     *   <li>TLS/encryption keyword detected in {@code banner}.</li>
     *   <li>Default {@code "TCP"}.</li>
     * </ol>
     */
    public static String getProtocol(int port, String banner) {
        // 1. Use protocol stored in file
        String stored = PROTOCOLS.get(port);
        if (stored != null && !stored.isEmpty()) return stored;

        // 2. Banner-based encryption detection
        if (banner != null) {
            String lower = banner.toLowerCase();
            for (String kw : ENCRYPTION_KEYWORDS) {
                if (lower.contains(kw)) {
                    return kw.equals("starttls")
                            ? "TCP (STARTTLS)"
                            : "TCP (Encrypted: " + kw.toUpperCase() + ")";
                }
            }
        }

        // 3. Generic fallback
        return "TCP";
    }
}
