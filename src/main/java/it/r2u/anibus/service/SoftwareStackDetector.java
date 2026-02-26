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
            detectedSoftware.add("🐳 Docker Engine (unsecured)" + 
                (openPortsWithBanners.containsKey(2376) ? " [TLS]" : ""));
        }
        
        // Kubernetes detection
        if (openPortsWithBanners.containsKey(6443)) {
            detectedSoftware.add("[K8S] Kubernetes API Server");
        }
        if (openPortsWithBanners.containsKey(10250)) {
            detectedSoftware.add("[K8S] Kubernetes Kubelet");
        }
        if (openPortsWithBanners.containsKey(8080) && 
            hasBannerKeyword(openPortsWithBanners.get(8080), "kubernetes", "k8s")) {
            detectedSoftware.add("[K8S] Kubernetes Dashboard");
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
