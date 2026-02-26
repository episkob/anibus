package it.r2u.anibus.network;

import javafx.application.Platform;
import javafx.scene.control.Label;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.IDN;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Handles host resolution, SSL/TLS detection, and URL sanitization.
 */
public class HostResolver {
    
    /**
     * Sanitizes a host input by removing http/https prefixes,
     * extracting hostname from URLs, and removing port numbers.
     * Also converts internationalized domain names (IDN) to ASCII (Punycode).
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
        
        // Convert internationalized domain names to ASCII (Punycode)
        // This handles Cyrillic domains like фсб.рф -> xn--b1aew.xn--p1ai
        try {
            // Use ALLOW_UNASSIGNED flag to support all Unicode characters
            cleaned = IDN.toASCII(cleaned, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException e) {
            // If IDN conversion fails, try splitting by dots and converting each part
            try {
                String[] parts = cleaned.split("\\.");
                StringBuilder result = new StringBuilder();
                for (int i = 0; i < parts.length; i++) {
                    if (i > 0) result.append(".");
                    result.append(IDN.toASCII(parts[i], IDN.ALLOW_UNASSIGNED));
                }
                cleaned = result.toString();
            } catch (Exception ex) {
                // If still fails, return as is
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
                    // Check if it's an IDN domain by looking for xn-- prefix
                    if (host.contains("xn--")) {
                        try {
                            String unicodeDomain = IDN.toUnicode(host);
                            String errorMsg = "Unable to resolve: " + unicodeDomain;
                            
                            // Check for common mistakes with Cyrillic domains
                            if (unicodeDomain.endsWith(".ру")) {
                                errorMsg += " (hint: did you mean .рф or .ru?)";
                            } else if (unicodeDomain.endsWith(".ргф") || unicodeDomain.endsWith(".рг")) {
                                errorMsg += " (hint: did you mean .рф?)";
                            }
                            
                            resolvedHostLabel.setText(errorMsg);
                        } catch (Exception e) {
                            resolvedHostLabel.setText("Unable to resolve: " + host);
                        }
                    } else {
                        resolvedHostLabel.setText("Unable to resolve: " + host);
                    }
                    if (onUpdate != null) onUpdate.run();
                });
            } catch (Exception ex) {
                Platform.runLater(() -> {
                    resolvedHostLabel.setText("Error: " + ex.getMessage());
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
