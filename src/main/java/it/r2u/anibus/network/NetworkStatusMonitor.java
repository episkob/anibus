package it.r2u.anibus.network;

import javafx.application.Platform;
import javafx.scene.control.Tooltip;
import javafx.scene.shape.Circle;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Monitors network connectivity status and updates UI indicator.
 */
public class NetworkStatusMonitor {
    
    public enum NetworkStatus {
        CONNECTED, LOCAL_ONLY, DISCONNECTED
    }
    
    private final Circle networkDot;
    private final Tooltip networkTooltip;
    private ScheduledExecutorService executor;
    
    public NetworkStatusMonitor(Circle networkDot, Tooltip networkTooltip) {
        this.networkDot = networkDot;
        this.networkTooltip = networkTooltip;
    }
    
    /**
     * Starts monitoring network status every 5 seconds.
     */
    public void start() {
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "NetworkMonitor");
            t.setDaemon(true);
            return t;
        });
        
        executor.scheduleAtFixedRate(this::checkAndUpdate, 0, 5, TimeUnit.SECONDS);
    }
    
    /**
     * Stops the network monitor.
     */
    public void stop() {
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }
    
    /**
     * Checks network status and updates the UI.
     */
    private void checkAndUpdate() {
        NetworkStatus status = checkNetworkStatus();
        Platform.runLater(() -> applyNetworkDot(status));
    }
    
    /**
     * Checks current network connectivity status.
     */
    private NetworkStatus checkNetworkStatus() {
        try {
            // Check internet connectivity
            HttpURLConnection conn = (HttpURLConnection) URI.create("https://www.google.com").toURL().openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            conn.connect();
            int code = conn.getResponseCode();
            conn.disconnect();
            if (code == 200) return NetworkStatus.CONNECTED;
        } catch (Exception ignored) {
            // Internet not available, check local network
        }
        
        try {
            // Check local connectivity
            InetAddress addr = InetAddress.getByName("192.168.1.1");
            if (addr.isReachable(1000)) {
                return NetworkStatus.LOCAL_ONLY;
            }
        } catch (Exception ignored) {
        }
        
        return NetworkStatus.DISCONNECTED;
    }
    
    /**
     * Updates the network indicator dot based on status.
     */
    private void applyNetworkDot(NetworkStatus status) {
        if (networkDot == null) return;
        
        // Remove all status classes first
        networkDot.getStyleClass().removeAll("network-dot-green", "network-dot-yellow", "network-dot-red");
        
        switch (status) {
            case CONNECTED -> {
                networkDot.getStyleClass().add("network-dot-green");
                if (networkTooltip != null) {
                    networkTooltip.setText("Internet connected");
                }
            }
            case LOCAL_ONLY -> {
                networkDot.getStyleClass().add("network-dot-yellow");
                if (networkTooltip != null) {
                    networkTooltip.setText("Local network only");
                }
            }
            case DISCONNECTED -> {
                networkDot.getStyleClass().add("network-dot-red");
                if (networkTooltip != null) {
                    networkTooltip.setText("No network connection");
                }
            }
        }
    }
}
