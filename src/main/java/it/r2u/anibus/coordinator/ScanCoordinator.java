package it.r2u.anibus.coordinator;

import javafx.beans.property.DoubleProperty;
import java.util.HashMap;
import java.util.Map;

/**
 * Facade for managing scan operations.
 * Coordinates between different scan strategies and provides
 * unified interface for controller.
 * 
 * Follows Facade and Strategy patterns.
 */
public class ScanCoordinator {
    
    private final Map<String, ScanStrategy> strategies = new HashMap<>();
    private ScanStrategy currentStrategy;
    private String currentStrategyName;
    
    /**
     * Register a scan strategy with given name.
     * 
     * @param name Strategy name (must match UI combo box values)
     * @param strategy Strategy implementation
     */
    public void registerStrategy(String name, ScanStrategy strategy) {
        strategies.put(name, strategy);
    }
    
    /**
     * Set active strategy by name.
     * 
     * @param name Strategy name
     * @throws IllegalArgumentException if strategy not found
     */
    public void setActiveStrategy(String name) {
        ScanStrategy strategy = strategies.get(name);
        if (strategy == null) {
            throw new IllegalArgumentException("Unknown strategy: " + name);
        }
        currentStrategy = strategy;
        currentStrategyName = name;
    }
    
    /**
     * Execute scan with current strategy.
     * 
     * @param context Scan parameters and callbacks
     * @throws IllegalStateException if no strategy is active
     */
    public void executeScan(ScanContext context) {
        if (currentStrategy == null) {
            throw new IllegalStateException("No strategy selected");
        }
        currentStrategy.executeScan(context);
    }
    
    /**
     * Cancel ongoing scan.
     */
    public void cancelScan() {
        if (currentStrategy != null) {
            currentStrategy.cancel();
        }
    }
    
    /**
     * Check if scan is running.
     */
    public boolean isScanning() {
        return currentStrategy != null && currentStrategy.isRunning();
    }
    
    /**
     * Get progress property for UI binding.
     */
    public DoubleProperty progressProperty() {
        if (currentStrategy == null) {
            throw new IllegalStateException("No strategy selected");
        }
        return currentStrategy.progressProperty();
    }
    
    /**
     * Get status prefix for current strategy.
     */
    public String getCurrentStatusPrefix() {
        return currentStrategy != null ? currentStrategy.getStatusPrefix() : "";
    }
    
    /**
     * Get current strategy name.
     */
    public String getCurrentStrategyName() {
        return currentStrategyName;
    }
    
    /**
     * Get description for strategy.
     */
    public String getStrategyDescription(String name) {
        return switch (name) {
            case "Standard Scanning" -> 
                "Standard Scanning mode: Basic TCP port scanning with service detection";
            case "Service Detection" -> 
                "Service Detection mode: Enhanced service fingerprinting with real-time detection";
            default -> "Unknown scan mode";
        };
    }
    
    /**
     * Shutdown all strategies and cleanup resources.
     */
    public void shutdown() {
        for (ScanStrategy strategy : strategies.values()) {
            strategy.shutdown();
        }
        strategies.clear();
        currentStrategy = null;
    }
}
