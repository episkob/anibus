package it.r2u.anibus.coordinator;

import javafx.beans.property.DoubleProperty;

/**
 * Strategy interface for different scan types.
 * Follows Strategy Pattern and Open/Closed Principle.
 */
public interface ScanStrategy {
    
    /**
     * Execute the scan with given parameters.
     * 
     * @param context Scan execution context with all necessary parameters
     */
    void executeScan(ScanContext context);
    
    /**
     * Cancel ongoing scan if possible.
     */
    void cancel();
    
    /**
     * Check if scan is currently running.
     */
    boolean isRunning();
    
    /**
     * Get progress property for binding to UI.
     */
    DoubleProperty progressProperty();
    
    /**
     * Get human-readable name of this strategy.
     */
    String getStrategyName();
    
    /**
     * Get status prefix for this strategy (e.g., "[FAST]", "[SD]".
     */
    String getStatusPrefix();
    
    /**
     * Shutdown and cleanup resources.
     */
    void shutdown();
}
