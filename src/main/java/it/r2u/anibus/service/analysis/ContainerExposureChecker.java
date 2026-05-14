package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import it.r2u.anibus.util.HttpClientFactory;
import it.r2u.anibus.util.HttpClientFactory.TimeoutProfile;

/**
 * Detects publicly exposed container/orchestration management endpoints:
 * unauthenticated Docker Engine API, Kubernetes API server, etcd client API
 * and Kubelet read-only / metrics ports.
 *
 * <p>Each probe is content-based: an HTTP 200 alone is not enough — the
 * response body or banner has to contain a fingerprint specific to the
 * product to mark the finding as {@code HIGH}, otherwise {@code MEDIUM}
 * (HTTP code matches but body is empty/unrecognised).
 *
 * <p>No credentials are sent; no destructive endpoints are touched
 * (e.g. {@code /containers/create}, {@code /api/v1/namespaces/.../pods}
 * are never POSTed). Read-only GETs only.
 */
public class ContainerExposureChecker {

    /** Severity of a single finding. */
    public enum Severity { HIGH, MEDIUM, INFO }

    /** Single probe outcome. */
    public record ExposureFinding(String product, String url, int statusCode,
                                  Severity severity, String evidence) {}

    /** Aggregated report. */
    public record ContainerExposureReport(String target, List<ExposureFinding> findings) {
        public long countSeverity(Severity s) {
            return findings.stream().filter(f -> f.severity() == s).count();
        }
    }

    private static final int TCP_TIMEOUT_MS = 1500;

    /**
     * Probes the well-known management ports/paths of a target host.
     *
     * @param host bare host or IP (e.g. {@code 10.0.0.1} or {@code example.com})
     * @return aggregated report. Always non-null; {@code findings} is empty
     *         when nothing exposed.
     */
    public ContainerExposureReport scan(String host) {
        if (host == null || host.isBlank()) {
            return new ContainerExposureReport("", List.of());
        }
        String h = stripScheme(host).trim();
        List<ExposureFinding> all = new ArrayList<>();
        // Docker Engine API — TCP 2375 (cleartext) and 2376 (mTLS, but often
        // exposed without client-cert verification).
        all.addAll(probeDocker(h, 2375, "http"));
        all.addAll(probeDocker(h, 2376, "https"));
        // Kubernetes API server — 6443 (secure) and 8080 (insecure, removed
        // in K8s 1.20+ but still found on legacy clusters).
        all.addAll(probeKubeApi(h, 6443, "https"));
        all.addAll(probeKubeApi(h, 8080, "http"));
        // Kubelet — read-only port 10255 (deprecated but still on the wire),
        // and main port 10250 (requires auth, but many clusters misconfigure).
        all.addAll(probeKubelet(h, 10255, "http"));
        all.addAll(probeKubelet(h, 10250, "https"));
        // etcd client API — 2379 (secure) and 4001 (legacy CoreOS port).
        all.addAll(probeEtcd(h, 2379, "https"));
        all.addAll(probeEtcd(h, 2379, "http"));
        all.addAll(probeEtcd(h, 4001, "http"));
        return new ContainerExposureReport(h, all);
    }

    /* ---------- Docker ---------- */

    private List<ExposureFinding> probeDocker(String host, int port, String scheme) {
        if (!tcpOpen(host, port)) return List.of();
        List<ExposureFinding> out = new ArrayList<>();
        // /_ping returns "OK" with X-Docker-* response headers.
        String pingUrl = scheme + "://" + host + ":" + port + "/_ping";
        String pingBody = httpGet(pingUrl, "Server");
        if (pingBody != null) {
            Severity s = pingBody.toLowerCase(Locale.ROOT).contains("ok")
                ? Severity.HIGH : Severity.MEDIUM;
            out.add(new ExposureFinding("Docker Engine API", pingUrl, 200, s,
                "Server header: " + truncate(pingBody, 120)));
        }
        // /version exposes engine version + git commit — definitive fingerprint.
        String verUrl = scheme + "://" + host + ":" + port + "/version";
        String verBody = httpGet(verUrl, null);
        if (verBody != null && verBody.toLowerCase(Locale.ROOT).contains("\"version\"")) {
            out.add(new ExposureFinding("Docker Engine API", verUrl, 200, Severity.HIGH,
                "version JSON: " + truncate(verBody, 160)));
        }
        return out;
    }

    /* ---------- Kubernetes API ---------- */

    private List<ExposureFinding> probeKubeApi(String host, int port, String scheme) {
        if (!tcpOpen(host, port)) return List.of();
        List<ExposureFinding> out = new ArrayList<>();
        // /version is unauthenticated by design on most clusters.
        String url = scheme + "://" + host + ":" + port + "/version";
        String body = httpGet(url, null);
        if (body != null && body.toLowerCase(Locale.ROOT).contains("\"gitversion\"")) {
            out.add(new ExposureFinding("Kubernetes API server", url, 200, Severity.HIGH,
                "kube version: " + truncate(body, 160)));
        }
        // /api lists API groups — anonymous access here is a config error.
        String api = scheme + "://" + host + ":" + port + "/api";
        String apiBody = httpGet(api, null);
        if (apiBody != null && apiBody.toLowerCase(Locale.ROOT).contains("\"serveraddress\"")) {
            out.add(new ExposureFinding("Kubernetes API server", api, 200, Severity.HIGH,
                "anonymous /api enumeration: " + truncate(apiBody, 160)));
        }
        return out;
    }

    /* ---------- Kubelet ---------- */

    private List<ExposureFinding> probeKubelet(String host, int port, String scheme) {
        if (!tcpOpen(host, port)) return List.of();
        List<ExposureFinding> out = new ArrayList<>();
        // /pods on either read-only or main port returns a JSON PodList.
        String url = scheme + "://" + host + ":" + port + "/pods";
        String body = httpGet(url, null);
        if (body != null && body.toLowerCase(Locale.ROOT).contains("\"kind\":\"podlist\"")) {
            out.add(new ExposureFinding("Kubelet", url, 200, Severity.HIGH,
                "anonymous Pod list dump: " + truncate(body, 160)));
        } else if (body != null) {
            out.add(new ExposureFinding("Kubelet", url, 200, Severity.MEDIUM,
                "responded 200 but no PodList fingerprint: " + truncate(body, 80)));
        }
        return out;
    }

    /* ---------- etcd ---------- */

    private List<ExposureFinding> probeEtcd(String host, int port, String scheme) {
        if (!tcpOpen(host, port)) return List.of();
        List<ExposureFinding> out = new ArrayList<>();
        // etcd v2 HTTP API:  /v2/keys/?recursive=true  — full dump if no auth.
        String v2 = scheme + "://" + host + ":" + port + "/v2/keys/";
        String v2Body = httpGet(v2, null);
        if (v2Body != null && v2Body.toLowerCase(Locale.ROOT).contains("\"node\"")) {
            out.add(new ExposureFinding("etcd v2 API", v2, 200, Severity.HIGH,
                "key tree visible: " + truncate(v2Body, 160)));
        }
        // etcd v3 health endpoint.
        String v3 = scheme + "://" + host + ":" + port + "/health";
        String v3Body = httpGet(v3, null);
        if (v3Body != null && v3Body.toLowerCase(Locale.ROOT).contains("\"health\"")) {
            out.add(new ExposureFinding("etcd v3 API", v3, 200, Severity.HIGH,
                "health endpoint reachable: " + truncate(v3Body, 160)));
        }
        return out;
    }

    /* ---------- helpers ---------- */

    private boolean tcpOpen(String host, int port) {
        try (Socket s = new Socket()) {
            s.connect(new java.net.InetSocketAddress(host, port), TCP_TIMEOUT_MS);
            return true;
        } catch (IOException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Returns the response body (or named header) if the request succeeds
     * with status &lt; 400; {@code null} otherwise.
     */
    private String httpGet(String url, String headerNameOrNull) {
        try {
            HttpURLConnection conn = HttpClientFactory.open(url, TimeoutProfile.FAST);
            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(false);
            int sc = conn.getResponseCode();
            if (sc >= 400) {
                conn.disconnect();
                return null;
            }
            if (headerNameOrNull != null) {
                String h = conn.getHeaderField(headerNameOrNull);
                conn.disconnect();
                return h == null ? "" : h;
            }
            byte[] body;
            try (var in = conn.getInputStream()) {
                body = in.readNBytes(8192);
            }
            conn.disconnect();
            return new String(body, StandardCharsets.UTF_8);
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    private String stripScheme(String s) {
        int colon = s.indexOf("://");
        String body = colon >= 0 ? s.substring(colon + 3) : s;
        int slash = body.indexOf('/');
        if (slash >= 0) body = body.substring(0, slash);
        int port = body.indexOf(':');
        if (port >= 0) body = body.substring(0, port);
        return body;
    }

    private String truncate(String s, int n) {
        if (s == null) return "";
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() <= n ? t : t.substring(0, n) + "…";
    }

    /** Human-readable report for the scan console. */
    public static String formatReport(ContainerExposureReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== CONTAINER EXPOSURE: ").append(report.target()).append(" ===\n");
        if (report.findings().isEmpty()) {
            sb.append("  No exposed Docker/K8s/Kubelet/etcd endpoints found.\n");
            return sb.toString();
        }
        sb.append("  HIGH: ").append(report.countSeverity(Severity.HIGH))
          .append("   MEDIUM: ").append(report.countSeverity(Severity.MEDIUM))
          .append("   INFO: ").append(report.countSeverity(Severity.INFO)).append("\n\n");
        for (ExposureFinding f : report.findings()) {
            sb.append(String.format("  [%-6s] %-22s %s%n",
                f.severity(), f.product(), f.url()));
            if (f.evidence() != null && !f.evidence().isBlank()) {
                sb.append("            ").append(f.evidence()).append('\n');
            }
        }
        return sb.toString();
    }
}
