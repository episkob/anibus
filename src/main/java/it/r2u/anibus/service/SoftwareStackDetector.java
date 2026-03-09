package it.r2u.anibus.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Detects software stacks, container platforms, and technology fingerprints
 * based on open ports and service banners.
 */
public class SoftwareStackDetector {
    
    /**
     * Analyzes port patterns and banners to detect software stacks.
     * Returns a list of detected technologies.
     */
    public static List<String> detectSoftwareStack(Map<Integer, String> openPortsWithBanners) {
        List<String> detectedSoftware = new ArrayList<>();
        
        // Docker detection
        if (openPortsWithBanners.containsKey(2375) || openPortsWithBanners.containsKey(2376)) {
            detectedSoftware.add("[DOCKER] Docker Engine" +
                (openPortsWithBanners.containsKey(2375) ? " (API UNAUTHENTICATED — CRITICAL)" : " (API TLS)"));
        }
        
        // Docker Swarm
        if (openPortsWithBanners.containsKey(2377)) {
            detectedSoftware.add("[DOCKER] Docker Swarm Manager (port 2377)");
        }
        
        // Docker overlay / VXLAN network (UDP 4789 — informational if TCP open)
        if (openPortsWithBanners.containsKey(4789)) {
            detectedSoftware.add("[DOCKER] Docker Overlay Network / VXLAN (port 4789)");
        }
        
        // Docker metrics (Prometheus exporter)
        if (openPortsWithBanners.containsKey(9323)) {
            detectedSoftware.add("[DOCKER] Docker Prometheus Metrics (port 9323)");
        }
        
        // OCI / Docker Registry
        if (openPortsWithBanners.containsKey(5000) &&
                hasBannerKeyword(openPortsWithBanners.get(5000), "registry", "docker", "v2")) {
            detectedSoftware.add("[DOCKER] Docker/OCI Container Registry (port 5000)");
        }
        
        // cAdvisor container monitoring
        if (openPortsWithBanners.containsKey(4194)) {
            detectedSoftware.add("[CONTAINER] cAdvisor Container Metrics (port 4194)");
        }
        
        // Podman REST API (same default port as Docker API but different banner)
        if (openPortsWithBanners.containsKey(2375) &&
                hasBannerKeyword(openPortsWithBanners.get(2375), "podman", "libpod")) {
            detectedSoftware.add("[CONTAINER] Podman Container Engine");
        }
        
        // Kubernetes detection
        if (openPortsWithBanners.containsKey(6443)) {
            detectedSoftware.add("[K8S] Kubernetes API Server");
        }
        if (openPortsWithBanners.containsKey(10250)) {
            detectedSoftware.add("[K8S] Kubernetes Kubelet");
        }
        if (openPortsWithBanners.containsKey(10248)) {
            detectedSoftware.add("[K8S] Kubernetes Kubelet Healthz (port 10248)");
        }
        if (openPortsWithBanners.containsKey(10249)) {
            detectedSoftware.add("[K8S] Kubernetes kube-proxy Metrics (port 10249)");
        }
        if (openPortsWithBanners.containsKey(10251)) {
            detectedSoftware.add("[K8S] Kubernetes Scheduler (port 10251)");
        }
        if (openPortsWithBanners.containsKey(10252)) {
            detectedSoftware.add("[K8S] Kubernetes Controller Manager (port 10252)");
        }
        if (openPortsWithBanners.containsKey(8080) && 
            hasBannerKeyword(openPortsWithBanners.get(8080), "kubernetes", "k8s")) {
            detectedSoftware.add("[K8S] Kubernetes Dashboard");
        }
        
        // Kubernetes etcd
        if (openPortsWithBanners.containsKey(2379) || openPortsWithBanners.containsKey(2380)) {
            detectedSoftware.add("[K8S] Kubernetes etcd (control plane key-value store)");
        }
        
        // Kubernetes overlay networking
        if (openPortsWithBanners.containsKey(8472)) {
            detectedSoftware.add("[K8S] Flannel VXLAN Overlay Network (port 8472)");
        }
        if (openPortsWithBanners.containsKey(6783) || openPortsWithBanners.containsKey(6784)) {
            detectedSoftware.add("[K8S] Weave Net Overlay Network (port 6783/6784)");
        }
        if (openPortsWithBanners.containsKey(9099)) {
            detectedSoftware.add("[K8S] Calico Networking (port 9099)");
        }
        
        // containerd gRPC
        if (openPortsWithBanners.containsKey(2376) &&
                hasBannerKeyword(openPortsWithBanners.get(2376), "containerd")) {
            detectedSoftware.add("[CONTAINER] containerd Container Runtime");
        }
        
        // Jenkins detection
        if (openPortsWithBanners.containsKey(8080) && 
            hasBannerKeyword(openPortsWithBanners.get(8080), "jenkins")) {
            detectedSoftware.add("[CI] Jenkins CI/CD");
        }
        
        // GitLab detection
        if (hasBannerKeyword(openPortsWithBanners, "gitlab")) {
            detectedSoftware.add("🦊 GitLab");
        }
        
        // Prometheus/Grafana stack detection
        if (openPortsWithBanners.containsKey(9090)) {
            detectedSoftware.add("📊 Prometheus");
        }
        if (openPortsWithBanners.containsKey(3000) && 
            hasBannerKeyword(openPortsWithBanners.get(3000), "grafana")) {
            detectedSoftware.add("📈 Grafana");
        }
        
        // ELK Stack detection
        if (openPortsWithBanners.containsKey(9200) || 
            hasBannerKeyword(openPortsWithBanners, "elasticsearch")) {
            detectedSoftware.add("[SEARCH] Elasticsearch");
        }
        if (openPortsWithBanners.containsKey(5601) || 
            hasBannerKeyword(openPortsWithBanners, "kibana")) {
            detectedSoftware.add("📊 Kibana");
        }
        if (openPortsWithBanners.containsKey(5044) || 
            hasBannerKeyword(openPortsWithBanners, "logstash")) {
            detectedSoftware.add("📝 Logstash");
        }
        
        // RabbitMQ detection
        if (openPortsWithBanners.containsKey(5672) || openPortsWithBanners.containsKey(15672)) {
            detectedSoftware.add("🐰 RabbitMQ");
        }
        
        // Apache Kafka detection
        if (openPortsWithBanners.containsKey(9092)) {
            detectedSoftware.add("📨 Apache Kafka");
        }
        
        // Redis detection
        if (openPortsWithBanners.containsKey(6379)) {
            detectedSoftware.add("[CACHE] Redis Cache");
        }
        
        // MongoDB detection
        if (openPortsWithBanners.containsKey(27017) || 
            hasBannerKeyword(openPortsWithBanners, "mongodb")) {
            detectedSoftware.add("🍃 MongoDB");
        }
        
        // PostgreSQL detection
        if (openPortsWithBanners.containsKey(5432) || 
            hasBannerKeyword(openPortsWithBanners, "postgresql", "postgres")) {
            detectedSoftware.add("🐘 PostgreSQL");
        }
        
        // MySQL/MariaDB detection
        if (openPortsWithBanners.containsKey(3306) || 
            hasBannerKeyword(openPortsWithBanners, "mysql", "mariadb")) {
            detectedSoftware.add("🐬 MySQL/MariaDB");
        }
        
        // Nginx detection
        if (hasBannerKeyword(openPortsWithBanners, "nginx")) {
            detectedSoftware.add("[WEB] Nginx Web Server");
        }
        
        // Apache detection
        if (hasBannerKeyword(openPortsWithBanners, "apache")) {
            detectedSoftware.add("🪶 Apache HTTP Server");
        }
        
        // Node.js detection
        if (hasBannerKeyword(openPortsWithBanners, "node", "express")) {
            detectedSoftware.add("🟢 Node.js Application");
        }
        
        // Tomcat detection
        if (openPortsWithBanners.containsKey(8080) && 
            hasBannerKeyword(openPortsWithBanners.get(8080), "tomcat")) {
            detectedSoftware.add("🐱 Apache Tomcat");
        }
        
        // Consul detection
        if (openPortsWithBanners.containsKey(8500)) {
            detectedSoftware.add("[SECURE] HashiCorp Consul");
        }
        
        // Vault detection
        if (openPortsWithBanners.containsKey(8200)) {
            detectedSoftware.add("[VAULT] HashiCorp Vault");
        }
        
        // Traefik detection
        if (hasBannerKeyword(openPortsWithBanners, "traefik")) {
            detectedSoftware.add("🔀 Traefik Proxy");
        }
        
        // HAProxy detection
        if (hasBannerKeyword(openPortsWithBanners, "haproxy")) {
            detectedSoftware.add("[LB] HAProxy Load Balancer");
        }
        
        // MinIO detection
        if (openPortsWithBanners.containsKey(9000) && 
            hasBannerKeyword(openPortsWithBanners.get(9000), "minio")) {
            detectedSoftware.add("[STORAGE] MinIO Object Storage");
        }
        
        // Portainer detection
        if (openPortsWithBanners.containsKey(9000) && 
            hasBannerKeyword(openPortsWithBanners.get(9000), "portainer")) {
            detectedSoftware.add("[DOCKER] Portainer Docker Management");
        }
        
        return detectedSoftware;
    }
    
    /**
     * Checks if any banner contains the specified keywords (case-insensitive).
     */
    private static boolean hasBannerKeyword(Map<Integer, String> openPortsWithBanners, String... keywords) {
        for (String banner : openPortsWithBanners.values()) {
            if (banner != null && hasBannerKeyword(banner, keywords)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Checks if a banner contains any of the specified keywords (case-insensitive).
     */
    private static boolean hasBannerKeyword(String banner, String... keywords) {
        if (banner == null) return false;
        String lowerBanner = banner.toLowerCase();
        for (String keyword : keywords) {
            if (lowerBanner.contains(keyword.toLowerCase())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Generates a summary of the detected software stack.
     */
    public static String generateStackSummary(List<String> detectedSoftware) {
        if (detectedSoftware.isEmpty()) {
            return "No specific software stack detected";
        }
        
        StringBuilder summary = new StringBuilder("Detected Technologies:\n");
        for (String software : detectedSoftware) {
            summary.append("  • ").append(software).append("\n");
        }
        
        return summary.toString().trim();
    }
}
