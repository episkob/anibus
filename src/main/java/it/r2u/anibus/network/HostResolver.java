package it.r2u.anibus.network;

import javafx.application.Platform;
import javafx.scene.control.Label;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Handles host resolution, SSL/TLS detection, and URL sanitization.
 */
public class HostResolver {
    
    /**
     * Sanitizes a host input by removing http/https prefixes,
     * extracting hostname from URLs, and removing port numbers.
     */
    public String sanitizeHost(String input) {
        if (input == null || input.isEmpty()) return input;
        
        String cleaned = input.trim();
        
        // Remove http:// or https:// prefix
        if (cleaned.toLowerCase().startsWith("https://")) {
            cleaned = cleaned.substring(8);
        } else if (cleaned.toLowerCase().startsWith("http://")) {
            cleaned = cleaned.substring(7);
        }
        
        // Remove path, query params, and fragments (keep only hostname/IP)
        int slashIndex = cleaned.indexOf('/');
        if (slashIndex != -1) {
            cleaned = cleaned.substring(0, slashIndex);
        }
        
        // Remove port number from hostname if present (e.g., example.com:8080)
        int colonIndex = cleaned.indexOf(':');
        if (colonIndex != -1) {
            // Check if it's not an IPv6 address
            if (!cleaned.contains("[") && !cleaned.contains("]")) {
                cleaned = cleaned.substring(0, colonIndex);
            }
        }
        
        return cleaned.trim();
    }
    
    /**
     * Checks if the host supports SSL/TLS on port 443.
     */
    public String checkSSL(String host) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
                socket.connect(new InetSocketAddress(host, 443), 2000);
                socket.startHandshake();
                return " [SSL/TLS ✓]";
            }
        } catch (Exception e) {
            return " [SSL/TLS ✗]";
        }
    }
    
    /**
     * Resolves a hostname to IP address asynchronously and updates the label with SSL status.
     */
    public void resolveHostAsync(String host, Label resolvedHostLabel, Runnable onUpdate) {
        new Thread(() -> {
            try {
                String ip = InetAddress.getByName(host).getHostAddress();
                String sslStatus = checkSSL(host);
                Platform.runLater(() -> {
                    resolvedHostLabel.setText("Resolved: " + ip + sslStatus);
                    if (onUpdate != null) onUpdate.run();
                });
            } catch (UnknownHostException ex) {
                Platform.runLater(() -> {
                    resolvedHostLabel.setText("Unable to resolve host");
                    if (onUpdate != null) onUpdate.run();
                });
            }
        }).start();
    }
    
    /**
     * Extracts IP address from resolved label text (removes "Resolved:" and SSL status).
     */
    public String extractIPFromResolvedText(String resolvedText) {
        if (resolvedText == null || resolvedText.isEmpty()) return "";
        
        String ip = resolvedText.replace("Resolved:", "").trim();
        
        // Remove SSL status if present
        int sslIndex = ip.indexOf("[SSL/TLS");
        if (sslIndex != -1) {
            ip = ip.substring(0, sslIndex).trim();
        }
        
        return ip;
    }
}
