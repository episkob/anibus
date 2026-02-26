package it.r2u.anibus.coordinator;

import it.r2u.anibus.model.PortScanResult;

/**
 * Context object encapsulating all scan parameters and callbacks.
 * Follows Builder pattern for easy construction.
 * Reduces coupling between controller and scan strategies.
 */
public class ScanContext {
    
    private final String host;
    private final int startPort;
    private final int endPort;
    private final int threadCount;
    private final ScanCallbacks callbacks;
    
    private ScanContext(Builder builder) {
        this.host = builder.host;
        this.startPort = builder.startPort;
        this.endPort = builder.endPort;
        this.threadCount = builder.threadCount;
        this.callbacks = builder.callbacks;
    }
    
    public String getHost() { return host; }
    public int getStartPort() { return startPort; }
    public int getEndPort() { return endPort; }
    public int getThreadCount() { return threadCount; }
    public ScanCallbacks getCallbacks() { return callbacks; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String host;
        private int startPort;
        private int endPort;
        private int threadCount = 10;
        private ScanCallbacks callbacks;
        
        public Builder host(String host) {
            this.host = host;
            return this;
        }
        
        public Builder startPort(int startPort) {
            this.startPort = startPort;
            return this;
        }
        
        public Builder endPort(int endPort) {
            this.endPort = endPort;
            return this;
        }
        
        public Builder threadCount(int threadCount) {
            this.threadCount = threadCount;
            return this;
        }
        
        public Builder callbacks(ScanCallbacks callbacks) {
            this.callbacks = callbacks;
            return this;
        }
        
        public ScanContext build() {
            if (host == null || host.isEmpty()) {
                throw new IllegalStateException("Host is required");
            }
            if (callbacks == null) {
                throw new IllegalStateException("Callbacks are required");
            }
            return new ScanContext(this);
        }
    }
    
    /**
     * Callback interface for scan events.
     * Follows Observer pattern.
     */
    public interface ScanCallbacks {
        void onHostResolved(String ip);
        void onScanStarted(String ip, String hostname, int totalPorts);
        void onResult(PortScanResult result);
        void onStatus(String message);
        void onCompleted();
        void onCancelled();
        void onFailed(String error);
        
        // Optional callback for subnet detection in service detection mode
        default void onSubnetDetected(String subnet, String gateway) {}
    }
}
