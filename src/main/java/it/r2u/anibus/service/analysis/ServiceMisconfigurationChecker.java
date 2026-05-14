package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Probes for data-services exposed without authentication.
 *
 * <p>Covers the most frequently mis-configured stacks: Redis, MongoDB,
 * Elasticsearch, Kafka, Memcached, CouchDB and Cassandra. The check sends a
 * single benign probe (e.g. {@code PING\r\n} for Redis) and inspects the
 * response banner — no destructive commands are issued.
 */
public class ServiceMisconfigurationChecker {

    private static final int TIMEOUT_MS = 4000;

    /** Outcome for a single (host, port, service) tuple. */
    public record MisconfigFinding(
        String host,
        int port,
        String service,
        Severity severity,
        String evidence
    ) {}

    /** Finding severity. */
    public enum Severity { INFO, MEDIUM, HIGH, CRITICAL }

    private record ProbeSpec(String service, int port, byte[] payload, String expectMarker, Severity severity) {}

    private static final List<ProbeSpec> PROBES = List.of(
        new ProbeSpec("Redis",         6379, "*1\r\n$4\r\nPING\r\n".getBytes(StandardCharsets.US_ASCII), "+PONG",       Severity.CRITICAL),
        new ProbeSpec("Redis (TLS)",   6380, "*1\r\n$4\r\nPING\r\n".getBytes(StandardCharsets.US_ASCII), "+PONG",       Severity.CRITICAL),
        new ProbeSpec("Memcached",    11211, "stats\r\n".getBytes(StandardCharsets.US_ASCII),           "STAT pid",    Severity.HIGH),
        new ProbeSpec("MongoDB",      27017, mongoIsMaster(),                                          "ismaster",    Severity.CRITICAL),
        new ProbeSpec("Elasticsearch", 9200, esGetRoot(),                                              "cluster_name",Severity.HIGH),
        new ProbeSpec("Kibana",        5601, esGetRoot(),                                              "kibana",      Severity.MEDIUM),
        new ProbeSpec("CouchDB",       5984, esGetRoot(),                                              "couchdb",     Severity.HIGH),
        new ProbeSpec("Kafka",         9092, new byte[0],                                              null,          Severity.MEDIUM),
        new ProbeSpec("Cassandra CQL", 9042, new byte[0],                                              null,          Severity.MEDIUM),
        new ProbeSpec("etcd",          2379, esGetRoot(),                                              "etcdserver",  Severity.HIGH),
        new ProbeSpec("Docker API",    2375, dockerVersionRequest(),                                   "ApiVersion",  Severity.CRITICAL),
        new ProbeSpec("RabbitMQ mgmt", 15672, esGetRoot(),                                             "RabbitMQ",    Severity.MEDIUM)
    );

    /** Runs the full probe matrix against the given host. */
    public List<MisconfigFinding> scan(String host) {
        return scan(host, Map.of());
    }

    /**
     * Runs the probe matrix; {@code portOverrides} lets callers swap the
     * default port of any service (e.g. Redis on 16379 in containerised setups).
     */
    public List<MisconfigFinding> scan(String host, Map<String, Integer> portOverrides) {
        if (host == null || host.isBlank()) return List.of();
        List<MisconfigFinding> out = new ArrayList<>();
        for (ProbeSpec probe : PROBES) {
            int port = portOverrides.getOrDefault(probe.service, probe.port);
            probe(host, port, probe).ifPresent(out::add);
        }
        return out;
    }

    private java.util.Optional<MisconfigFinding> probe(String host, int port, ProbeSpec spec) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            s.setSoTimeout(TIMEOUT_MS);
            if (spec.payload().length > 0) {
                s.getOutputStream().write(spec.payload());
                s.getOutputStream().flush();
            }
            byte[] buf = new byte[2048];
            int read;
            try {
                read = s.getInputStream().read(buf);
            } catch (IOException e) {
                read = -1;
            }
            String banner = read > 0 ? new String(buf, 0, read, StandardCharsets.ISO_8859_1) : "";
            String marker = spec.expectMarker();
            if (marker == null) {
                // Probe with no marker — port-open alone is the signal (Kafka/Cassandra
                // bind only to internal NIC by default; public exposure is suspicious).
                return java.util.Optional.of(new MisconfigFinding(host, port, spec.service(),
                    spec.severity(),
                    "TCP open without authentication challenge — service likely reachable"));
            }
            if (banner.toLowerCase(Locale.ROOT).contains(marker.toLowerCase(Locale.ROOT))) {
                String snippet = banner.length() > 240 ? banner.substring(0, 240) + "..." : banner;
                return java.util.Optional.of(new MisconfigFinding(host, port, spec.service(),
                    spec.severity(),
                    "Unauthenticated banner match: " + snippet.replaceAll("\\s+", " ")));
            }
            return java.util.Optional.empty();
        } catch (IOException e) {
            return java.util.Optional.empty();
        }
    }

    /** Formats findings as a console-ready report. */
    public static String formatReport(String host, List<MisconfigFinding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== SERVICE MISCONFIGURATION CHECK: ").append(host).append(" ===\n");
        if (findings.isEmpty()) {
            sb.append("  No exposed data services detected on the probed port matrix.\n");
            return sb.toString();
        }
        sb.append("  ").append(findings.size()).append(" exposed service(s) found:\n\n");
        for (MisconfigFinding f : findings) {
            sb.append(String.format("  [%-8s] %s:%d  %s%n", f.severity(), f.host(), f.port(), f.service()));
            sb.append("            ").append(f.evidence()).append('\n');
        }
        return sb.toString();
    }

    /* ---------- payload builders ---------- */

    private static byte[] mongoIsMaster() {
        // OP_QUERY for {ismaster: 1} on admin.$cmd — kept literal to avoid BSON deps.
        // 0x3a 00 00 00 — message length (58 bytes)
        // 01 00 00 00 — requestID
        // 00 00 00 00 — responseTo
        // d4 07 00 00 — opcode = OP_QUERY (2004)
        // 00 00 00 00 — flags
        // "admin.$cmd\0" — fullCollectionName
        // 00 00 00 00 — numberToSkip
        // 01 00 00 00 — numberToReturn
        // BSON {ismaster:1}: 1c000000 10 "ismaster\0" 01000000 00
        return new byte[] {
            0x3a, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            (byte) 0xd4, 0x07, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            'a', 'd', 'm', 'i', 'n', '.', '$', 'c', 'm', 'd', 0,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x1c, 0x00, 0x00, 0x00,
            0x10,
            'i', 's', 'm', 'a', 's', 't', 'e', 'r', 0,
            0x01, 0x00, 0x00, 0x00,
            0x00
        };
    }

    private static byte[] esGetRoot() {
        return "GET / HTTP/1.1\r\nHost: anibus\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] dockerVersionRequest() {
        return "GET /version HTTP/1.1\r\nHost: anibus\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    }
}
