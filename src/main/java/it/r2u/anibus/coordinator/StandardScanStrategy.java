package it.r2u.anibus.coordinator;

import it.r2u.anibus.model.PortScanResult;
import it.r2u.anibus.service.PortScannerService;
import it.r2u.anibus.service.ScanTask;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.SimpleDoubleProperty;

/**
 * Standard TCP port scanning strategy.
 * Lightweight and fast, without enhanced service detection.
 */
public class StandardScanStrategy implements ScanStrategy {
    
    private final PortScannerService scanner;
    private ScanTask activeScanTask;
    private final DoubleProperty progress = new SimpleDoubleProperty(0);
    
    public StandardScanStrategy(PortScannerService scanner) {
        this.scanner = scanner;
    }
    
    @Override
    public void executeScan(ScanContext context) {
        activeScanTask = new ScanTask(
            context.getHost(),
            context.getStartPort(),
            context.getEndPort(),
            context.getThreadCount(),
            scanner,
            new ScanTask.Callbacks() {
                @Override
                public void onHostResolved(String ip) {
                    context.getCallbacks().onHostResolved(ip);
                }
                
                @Override
                public void onScanStarted(String ip, String hostname, int totalPorts) {
                    context.getCallbacks().onScanStarted(ip, hostname, totalPorts);
                }
                
                @Override
                public void onResult(PortScanResult result) {
                    context.getCallbacks().onResult(result);
                }
                
                @Override
                public void onStatus(String msg) {
                    context.getCallbacks().onStatus(msg);
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
        
        progress.bind(activeScanTask.progressProperty());
        new Thread(activeScanTask).start();
    }
    
    @Override
    public void cancel() {
        if (activeScanTask != null && activeScanTask.isRunning()) {
            activeScanTask.cancel();
        }
    }
    
    @Override
    public boolean isRunning() {
        return activeScanTask != null && activeScanTask.isRunning();
    }
    
    @Override
    public DoubleProperty progressProperty() {
        return progress;
    }
    
    @Override
    public String getStrategyName() {
        return "Standard Scanning";
    }
    
    @Override
    public String getStatusPrefix() {
        return "[FAST]";
    }
    
    @Override
    public void shutdown() {
        if (activeScanTask != null) {
            activeScanTask.shutdown();
        }
    }
}
