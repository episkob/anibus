package it.r2u.anibus.coordinator;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.EnhancedServiceDetector;
import it.r2u.anibus.service.ServiceDetectionTask;
import javafx.application.Platform;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;

/**
 * Enhanced service detection strategy with deep fingerprinting.
 * Includes OS detection, vulnerability scanning, geolocation, etc.
 */
public class ServiceDetectionStrategy implements ScanStrategy {
    
    private final EnhancedServiceDetector detector;
    private ServiceDetectionTask activeTask;
    private final DoubleProperty progress = new SimpleDoubleProperty(0);
    
    public ServiceDetectionStrategy(EnhancedServiceDetector detector) {
        this.detector = detector;
    }
    
    @Override
    public void executeScan(ScanContext context) {
        activeTask = new ServiceDetectionTask(
            context.getHost(),
            context.getStartPort(),
            context.getEndPort(),
            context.getThreadCount(),
            detector,
            new ServiceDetectionTask.Callbacks() {
                @Override
                public void onHostResolved(String ip) {
                    Platform.runLater(() -> context.getCallbacks().onHostResolved(ip));
                }
                
                @Override
                public void onScanStarted(String ip, String hostname, int totalPorts) {
                    context.getCallbacks().onScanStarted(ip, hostname, totalPorts);
                }
                
                @Override
                public void onResult(PortScanResult result) {
                    Platform.runLater(() -> context.getCallbacks().onResult(result));
                }
                
                @Override
                public void onStatus(String msg) {
                    context.getCallbacks().onStatus(msg);
                }
                
                @Override
                public void onSubnetDetected(String subnet, String gateway) {
                    context.getCallbacks().onSubnetDetected(subnet, gateway);
                }
                
                @Override
                public void onCompleted() {
                    context.getCallbacks().onCompleted();
                }
                
                @Override
                public void onCancelled() {
                    context.getCallbacks().onCancelled();
                }
                
                @Override
                public void onFailed(String error) {
                    context.getCallbacks().onFailed(error);
                }
            }
        );
        
        progress.bind(activeTask.progressProperty());
        new Thread(activeTask).start();
    }
    
    @Override
    public void cancel() {
        if (activeTask != null && activeTask.isRunning()) {
            activeTask.cancel();
        }
    }
    
    @Override
    public boolean isRunning() {
        return activeTask != null && activeTask.isRunning();
    }
    
    @Override
    public DoubleProperty progressProperty() {
        return progress;
    }
    
    @Override
    public String getStrategyName() {
        return "Service Detection";
    }
    
    @Override
    public String getStatusPrefix() {
        return "[SD]";
    }
    
    @Override
    public void shutdown() {
        if (activeTask != null) {
            activeTask.shutdown();
        }
    }
}
