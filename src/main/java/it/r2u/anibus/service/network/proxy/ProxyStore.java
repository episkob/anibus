package it.r2u.anibus.service.network.proxy;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Persists the validated proxy pool to/from a local JSON file.
 *
 * <p>Format (line-delimited JSON objects, no external library required):
 * <pre>
 * {"host":"1.2.3.4","port":8080,"type":"HTTP","country":"DE","latency":312,"saved":"2026-05-08T01:30:00Z"}
 * ...
 * </pre>
 *
 * <p>Default location: {@code ~/.anibus/proxy-pool.json}
 */
public class ProxyStore {

    private static final Logger LOG = Logger.getLogger(ProxyStore.class.getName());

    private static final Path DEFAULT_PATH =
            Paths.get(System.getProperty("user.home"), ".anibus", "proxy-pool.json");

    private static final Pattern FIELD = Pattern.compile(
            "\"(host|port|type|country|latency)\"\\s*:\\s*\"?([^,\"\\}]+)\"?");

    private final Path storePath;

    public ProxyStore() {
        this(DEFAULT_PATH);
    }

    public ProxyStore(Path path) {
        this.storePath = path;
    }

    /** Returns the file path used for storage. */
    public Path getStorePath() { return storePath; }

    /** Returns true if a non-empty store file exists. */
    public boolean exists() {
        try {
            return Files.exists(storePath) && Files.size(storePath) > 0;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Save proxy set to file. Overwrites existing content.
     *
     * @param proxies validated proxy nodes
     */
    public void save(Set<ProxyNode> proxies) {
        try {
            Files.createDirectories(storePath.getParent());
            try (BufferedWriter w = Files.newBufferedWriter(storePath, StandardCharsets.UTF_8)) {
                String ts = Instant.now().toString();
                for (ProxyNode p : proxies) {
                    w.write(toJson(p, ts));
                    w.newLine();
                }
            }
            LOG.log(Level.INFO, "[ProxyStore] Saved {0} proxies → {1}", new Object[]{proxies.size(), storePath});
        } catch (IOException e) {
            LOG.log(Level.WARNING, "[ProxyStore] Save failed: {0}", e.getMessage());
        }
    }

    /**
     * Load proxy set from file.
     *
     * @return set of proxy nodes, empty if file missing or unreadable
     */
    public Set<ProxyNode> load() {
        Set<ProxyNode> result = new HashSet<>();
        if (!exists()) return result;

        try (BufferedReader r = Files.newBufferedReader(storePath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                ProxyNode node = parseLine(line);
                if (node != null) result.add(node);
            }
            LOG.log(Level.INFO, "[ProxyStore] Loaded {0} proxies ← {1}", new Object[]{result.size(), storePath});
        } catch (IOException e) {
            LOG.log(Level.WARNING, "[ProxyStore] Load failed: {0}", e.getMessage());
        }
        return result;
    }

    // ── Serialization helpers ─────────────────────────────────────────────────

    private static String toJson(ProxyNode p, String timestamp) {
        return "{\"host\":\"" + p.host()
                + "\",\"port\":" + p.port()
                + ",\"type\":\"" + p.type()
                + "\",\"country\":\"" + p.countryCode()
                + "\",\"latency\":" + p.latencyMs()
                + ",\"saved\":\"" + timestamp + "\"}";
    }

    private static ProxyNode parseLine(String line) {
        try {
            String host = null;
            int port = -1;
            ProxyType type = ProxyType.HTTP;
            String country = "XX";
            long latency = -1;

            Matcher m = FIELD.matcher(line);
            while (m.find()) {
                switch (m.group(1)) {
                    case "host"    -> host    = m.group(2).trim();
                    case "port"    -> port    = Integer.parseInt(m.group(2).trim());
                    case "type"    -> type    = ProxyType.valueOf(m.group(2).trim());
                    case "country" -> country = m.group(2).trim();
                    case "latency" -> latency = Long.parseLong(m.group(2).trim());
                    default        -> { /* ignored */ }
                }
            }

            if (host == null || port < 1) return null;
            return new ProxyNode(host, port, type, country, latency);
        } catch (IllegalArgumentException | NullPointerException e) {
            LOG.log(Level.FINE, "[ProxyStore] Skipping malformed line: {0}", line);
            return null;
        }
    }
}
