package it.r2u.anibus.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Detects containerization and container orchestration platforms.
 *
 * <p>Two complementary strategies:
 * <ol>
 *   <li><b>Port-level API probing</b> — actively queries Docker Engine REST API,
 *       Kubernetes API Server, cAdvisor, Portainer, and OCI container registries.</li>
 *   <li><b>HTTP-header fingerprinting</b> — passively inspects response headers
 *       for Envoy/Istio, Kong, Traefik, Kubernetes metadata headers, Heroku, and
 *       container-like hostnames in {@code X-Served-By}.</li>
 * </ol>
 */
public class ContainerDetector {

    private static final int TIMEOUT = 3000;

    // -------------------------------------------------------------------------
    // Result model
    // -------------------------------------------------------------------------

    public static class ContainerInfo {
        private boolean containerized;
        private String platform;        // e.g. Docker, Kubernetes, Podman …
        private String orchestrator;    // e.g. Docker Swarm, Kubernetes, Nomad …
        private String version;
        private final List<String> indicators  = new ArrayList<>();
        private final List<String> exposedApis = new ArrayList<>();

        public boolean isContainerized()          { return containerized; }
        public void setContainerized(boolean v)   { this.containerized = v; }
        public String getPlatform()               { return platform; }
        public void setPlatform(String v)         { this.platform = v; }
        public String getOrchestrator()           { return orchestrator; }
        public void setOrchestrator(String v)     { this.orchestrator = v; }
        public String getVersion()                { return version; }
        public void setVersion(String v)          { this.version = v; }
        public List<String> getIndicators()       { return indicators; }
        public List<String> getExposedApis()      { return exposedApis; }

        @Override
        public String toString() {
            if (!containerized) return null;

            StringBuilder sb = new StringBuilder();
            sb.append("[CONTAINER] Containerization Detected");
            if (platform != null)    sb.append(": ").append(platform);
            if (version  != null)    sb.append(" v").append(version);
            sb.append("\n");

            if (orchestrator != null) {
                sb.append("  [ORCHESTRATOR] Orchestrator: ").append(orchestrator).append("\n");
            }
            if (!indicators.isEmpty()) {
                sb.append("  [INDICATORS] ").append(String.join(" | ", indicators)).append("\n");
            }
            if (!exposedApis.isEmpty()) {
                sb.append("  [WARN] Exposed APIs: ").append(String.join(", ", exposedApis)).append("\n");
            }
            return sb.toString().trim();
        }
    }

    // -------------------------------------------------------------------------
    // Public entry point
    // -------------------------------------------------------------------------

    /**
     * Run all applicable detection strategies for the given host/port.
     *
     * @param host            target host
     * @param port            target port
     * @param responseHeaders HTTP response headers already collected (may be null)
     * @return ContainerInfo — always non-null; check {@link ContainerInfo#isContainerized()}
     */
    public static ContainerInfo detectContainer(String host, int port,
                                                Map<String, String> responseHeaders) {
        ContainerInfo info = new ContainerInfo();

        // 1. Passive: HTTP header fingerprinting
        if (responseHeaders != null && !responseHeaders.isEmpty()) {
            analyzeHeaders(info, responseHeaders);
        }

        // 2. Active probes on well-known container management ports
        switch (port) {
            case 2375, 2376      -> probeDockerApi(info, host, port);
            case 5000            -> probeContainerRegistry(info, host);
            case 6443            -> probeKubernetesApi(info, host, port, true);
            case 8080            -> probeKubernetesApi(info, host, port, false);
            case 10250           -> probeKubelet(info, host);
            case 4194            -> probeCAdvisor(info, host);
            case 9000, 9443      -> probePortainer(info, host, port);
            case 2377            -> markSwarm(info);                        // Docker Swarm manager
            case 9323            -> markDockerMetrics(info, host);          // Docker Prometheus metrics
            case 2379, 2380      -> markEtcd(info, port);                   // Kubernetes etcd
        }

        return info;
    }

    // -------------------------------------------------------------------------
    // HTTP header fingerprinting
    // -------------------------------------------------------------------------

    private static void analyzeHeaders(ContainerInfo info, Map<String, String> headers) {
        // Normalise to lowercase keys for case-insensitive look-ups
        Map<String, String> h = new LinkedHashMap<>();
        headers.forEach((k, v) -> h.put(k.toLowerCase(), v == null ? "" : v.toLowerCase()));

        // --- Envoy proxy (Kubernetes Istio service mesh) ---
        boolean envoy = h.keySet().stream().anyMatch(k -> k.startsWith("x-envoy-"));
        if (!envoy && h.getOrDefault("via", "").contains("envoy")) envoy = true;
        if (envoy) {
            addIndicator(info, "Envoy Proxy (Istio / K8s service mesh)");
            setIfAbsent(info, null, "Kubernetes (Istio)");
        }

        // --- Kong API Gateway ---
        boolean kong = h.keySet().stream().anyMatch(k -> k.startsWith("x-kong-"));
        if (!kong && h.getOrDefault("via", "").contains("kong")) kong = true;
        if (kong) {
            addIndicator(info, "Kong API Gateway");
            setIfAbsent(info, null, "Docker/Kubernetes (Kong)");
        }

        // --- Traefik ingress ---
        String via = h.getOrDefault("via", "");
        if (via.contains("traefik") || h.containsKey("x-forwarded-server") &&
                h.get("x-forwarded-server").contains("traefik")) {
            addIndicator(info, "Traefik Ingress Controller");
            setIfAbsent(info, null, "Docker/Kubernetes (Traefik)");
        }

        // --- Kubernetes metadata headers exposed by ingress/app ---
        checkHeader(info, h, "x-pod-name",      "K8s pod name exposed",       "Kubernetes");
        checkHeader(info, h, "x-node-name",     "K8s node name exposed",      "Kubernetes");
        checkHeader(info, h, "x-namespace",     "K8s namespace exposed",      "Kubernetes");
        checkHeader(info, h, "x-cluster-name",  "K8s cluster name exposed",   "Kubernetes");
        checkHeader(info, h, "x-kubernetes-*",  "K8s custom header present",  "Kubernetes");

        // --- Heroku (PaaS container runtime) ---
        if (h.containsKey("x-heroku-dynos-in-use") || via.contains("vegur")) {
            addIndicator(info, "Heroku PaaS (container dynos)");
            setIfAbsentPlatform(info, "Heroku");
        }

        // --- OpenResty (often the base image for nginx-based Docker containers) ---
        if (h.getOrDefault("server", "").contains("openresty")) {
            addIndicator(info, "OpenResty server (commonly containerised)");
        }

        // --- Container-ID-like hostname in X-Served-By ---
        String servedBy = h.getOrDefault("x-served-by", "");
        if (looksLikeContainerId(servedBy)) {
            addIndicator(info, "Container hostname in X-Served-By: " + servedBy);
        }

        // --- Nomad / Consul Connect sidecar ---
        if (h.containsKey("x-nomad-task") || h.containsKey("x-consul-token")) {
            addIndicator(info, "HashiCorp Nomad/Consul orchestration");
            setIfAbsent(info, "Nomad", "HashiCorp Nomad");
        }

        if (!info.getIndicators().isEmpty()) {
            info.setContainerized(true);
            setIfAbsentPlatform(info, "Container / Orchestration Platform");
        }
    }

    /** Set orchestrator only if not already set. */
    private static void setIfAbsent(ContainerInfo info, String platform, String orchestrator) {
        if (info.getOrchestrator() == null && orchestrator != null) info.setOrchestrator(orchestrator);
        setIfAbsentPlatform(info, platform);
    }

    private static void setIfAbsentPlatform(ContainerInfo info, String platform) {
        if (info.getPlatform() == null && platform != null) info.setPlatform(platform);
    }

    private static void checkHeader(ContainerInfo info, Map<String, String> h,
                                    String headerName, String label, String orchestrator) {
        boolean found = h.containsKey(headerName) ||
                h.keySet().stream().anyMatch(k -> k.startsWith(headerName.replace("*", "")));
        if (found) {
            addIndicator(info, label);
            setIfAbsent(info, null, orchestrator);
        }
    }

    /** Returns true for Docker short IDs (12 hex chars) or full IDs (64 hex chars). */
    private static boolean looksLikeContainerId(String value) {
        return value != null && (value.matches("[0-9a-f]{12}") || value.matches("[0-9a-f]{64}"));
    }

    // -------------------------------------------------------------------------
    // Active probes
    // -------------------------------------------------------------------------

    /** Probe Docker Engine REST API (/version, /info). */
    private static void probeDockerApi(ContainerInfo info, String host, int port) {
        String resp = httpGet(host, port, "/version", false);
        if (resp == null || !resp.contains("\"ApiVersion\"")) return;

        info.setContainerized(true);
        setIfAbsentPlatform(info, "Docker");

        Pattern vp = Pattern.compile("\"Version\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = vp.matcher(resp);
        if (m.find()) info.setVersion(m.group(1));

        if (port == 2375) {
            info.getExposedApis().add("Docker Engine API (NO AUTH/TLS) on port 2375 — CRITICAL");
            addIndicator(info, "Docker Engine API exposed without authentication");
        } else {
            info.getExposedApis().add("Docker Engine API (TLS) on port 2376");
            addIndicator(info, "Docker Engine API reachable with TLS");
        }

        // Check Swarm mode
        String infoResp = httpGet(host, port, "/info", false);
        if (infoResp != null && infoResp.contains("\"Swarm\"") &&
                (infoResp.contains("\"active\"") || infoResp.contains("\"manager\""))) {
            setIfAbsent(info, null, "Docker Swarm");
            addIndicator(info, "Docker Swarm cluster active");
        }
    }

    /** Probe OCI / Docker container registry (/v2/ discovery endpoint). */
    private static void probeContainerRegistry(ContainerInfo info, String host) {
        String resp = httpGet(host, 5000, "/v2/", false);
        // A registry returns 200 (anonymous) or 401 (auth required) for /v2/
        if (resp != null) {
            info.setContainerized(true);
            setIfAbsentPlatform(info, "Docker");
            info.getExposedApis().add("Docker/OCI Container Registry on port 5000");
            addIndicator(info, "OCI Container Registry detected");
        }
    }

    /** Probe Kubernetes API server (/version endpoint returns JSON with gitVersion). */
    private static void probeKubernetesApi(ContainerInfo info, String host, int port, boolean ssl) {
        String resp = httpGet(host, port, "/version", ssl);
        if (resp == null || !resp.contains("\"gitVersion\"")) return;

        info.setContainerized(true);
        setIfAbsentPlatform(info, "Kubernetes");
        setIfAbsent(info, null, "Kubernetes");

        Pattern vp = Pattern.compile("\"gitVersion\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = vp.matcher(resp);
        if (m.find()) info.setVersion(m.group(1));

        info.getExposedApis().add("Kubernetes API Server on port " + port);
        addIndicator(info, "Kubernetes API Server accessible");
    }

    /** Probe Kubernetes Kubelet healthz endpoint on port 10250. */
    private static void probeKubelet(ContainerInfo info, String host) {
        String resp = httpGet(host, 10250, "/healthz", true);
        if (resp != null && resp.contains("ok")) {
            info.setContainerized(true);
            setIfAbsentPlatform(info, "Kubernetes");
            info.getExposedApis().add("Kubernetes Kubelet on port 10250");
            addIndicator(info, "Kubernetes Kubelet healthz exposed");
        }
    }

    /** Probe cAdvisor container metrics endpoint. */
    private static void probeCAdvisor(ContainerInfo info, String host) {
        String resp = httpGet(host, 4194, "/api/v1.3/containers/", false);
        if (resp != null && (resp.contains("\"subcontainers\"") || resp.contains("docker"))) {
            info.setContainerized(true);
            setIfAbsentPlatform(info, "Docker");
            info.getExposedApis().add("cAdvisor container metrics on port 4194");
            addIndicator(info, "cAdvisor container monitoring exposed");
        }
    }

    /** Probe Portainer Docker management UI. */
    private static void probePortainer(ContainerInfo info, String host, int port) {
        boolean ssl = (port == 9443);
        String resp = httpGet(host, port, "/api/status", ssl);
        if (resp != null && (resp.contains("\"Version\"") || resp.contains("portainer"))) {
            info.setContainerized(true);
            setIfAbsentPlatform(info, "Docker");
            info.getExposedApis().add("Portainer Docker management on port " + port);
            addIndicator(info, "Portainer container management UI accessible");
        }
    }

    private static void markSwarm(ContainerInfo info) {
        info.setContainerized(true);
        setIfAbsentPlatform(info, "Docker");
        setIfAbsent(info, null, "Docker Swarm");
        addIndicator(info, "Docker Swarm manager port 2377 open");
    }

    private static void markDockerMetrics(ContainerInfo info, String host) {
        info.setContainerized(true);
        setIfAbsentPlatform(info, "Docker");
        String resp = httpGet(host, 9323, "/metrics", false);
        if (resp != null && resp.contains("docker_")) {
            info.getExposedApis().add("Docker Prometheus metrics on port 9323");
            addIndicator(info, "Docker metrics endpoint exposed (port 9323)");
        } else {
            addIndicator(info, "Docker metrics port 9323 open");
        }
    }

    private static void markEtcd(ContainerInfo info, int port) {
        info.setContainerized(true);
        setIfAbsentPlatform(info, "Kubernetes");
        setIfAbsent(info, null, "Kubernetes");
        addIndicator(info, "etcd key-value store port " + port + " open (Kubernetes control plane)");
    }

    // -------------------------------------------------------------------------
    // HTTP helper
    // -------------------------------------------------------------------------

    /** Minimal HTTP GET — returns response body (up to 8 KB) or null on any error. */
    private static String httpGet(String host, int port, String path, boolean ssl) {
        try {
            String protocol = ssl ? "https" : "http";
            URI uri = new URI(protocol + "://" + host + ":" + port + path);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("User-Agent", "Anibus/1.0");
            conn.setInstanceFollowRedirects(false);

            if (ssl && conn instanceof HttpsURLConnection httpsConn) {
                TrustManager[] trustAll = {new X509TrustManager() {
                    @Override public X509Certificate[] getAcceptedIssuers() { return null; }
                    @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
                    @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
                }};
                SSLContext sc = SSLContext.getInstance("TLS");
                sc.init(null, trustAll, new java.security.SecureRandom());
                httpsConn.setSSLSocketFactory(sc.getSocketFactory());
                httpsConn.setHostnameVerifier((h, s) -> true);
            }

            int status = conn.getResponseCode();
            InputStream is = (status < 400) ? conn.getInputStream() : conn.getErrorStream();
            if (is == null) return String.valueOf(status);

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                int total = 0;
                while ((line = br.readLine()) != null && total < 8192) {
                    sb.append(line);
                    total += line.length();
                }
                conn.disconnect();
                return sb.toString();
            }
        } catch (IOException | java.security.GeneralSecurityException | java.net.URISyntaxException e) {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private static void addIndicator(ContainerInfo info, String indicator) {
        if (!info.getIndicators().contains(indicator)) {
            info.getIndicators().add(indicator);
        }
    }
}
