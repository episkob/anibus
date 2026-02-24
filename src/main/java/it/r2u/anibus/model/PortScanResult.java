package it.r2u.anibus.model;

import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleLongProperty;
import javafx.beans.property.SimpleStringProperty;

public class PortScanResult {

    private final SimpleIntegerProperty port;
    private final SimpleStringProperty service;
    private final SimpleStringProperty banner;
    private final SimpleStringProperty protocol;
    private final SimpleLongProperty latency;
    private final SimpleStringProperty version;
    private final SimpleStringProperty state;
    private final SimpleStringProperty scanMode;

    public PortScanResult(int port, String service, String banner, String protocol,
                          long latency, String version, String state) {
        this(port, service, banner, protocol, latency, version, state, "Standard");
    }

    public PortScanResult(int port, String service, String banner, String protocol,
                          long latency, String version, String state, String scanMode) {
        this.port     = new SimpleIntegerProperty(port);
        this.service  = new SimpleStringProperty(service);
        this.banner   = new SimpleStringProperty(banner);
        this.protocol = new SimpleStringProperty(protocol);
        this.latency  = new SimpleLongProperty(latency);
        this.version  = new SimpleStringProperty(version);
        this.state    = new SimpleStringProperty(state);
        this.scanMode = new SimpleStringProperty(scanMode != null ? scanMode : "Standard");
    }

    public int getPort()                          { return port.get(); }
    public SimpleIntegerProperty portProperty()   { return port; }

    public String getService()                    { return service.get(); }
    public SimpleStringProperty serviceProperty() { return service; }

    public String getBanner()                     { return banner.get(); }
    public SimpleStringProperty bannerProperty()  { return banner; }

    public String getProtocol()                    { return protocol.get(); }
    public SimpleStringProperty protocolProperty() { return protocol; }

    public long getLatency()                      { return latency.get(); }
    public SimpleLongProperty latencyProperty()   { return latency; }

    public String getVersion()                    { return version.get(); }
    public SimpleStringProperty versionProperty() { return version; }

    public String getState()                      { return state.get(); }
    public SimpleStringProperty stateProperty()   { return state; }

    public String getScanMode()                   { return scanMode.get(); }
    public SimpleStringProperty scanModeProperty() { return scanMode; }
}
