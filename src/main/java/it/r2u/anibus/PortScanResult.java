package it.r2u.anibus;

import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleLongProperty;
import javafx.beans.property.SimpleStringProperty;

public class PortScanResult {

    private final SimpleIntegerProperty port;
    private final SimpleStringProperty service;
    private final SimpleStringProperty banner;
    private final SimpleStringProperty protocol;
    private final SimpleLongProperty latency;       // ms round-trip
    private final SimpleStringProperty version;     // software version extracted from banner
    private final SimpleStringProperty state;       // "Open", "Open|Filtered"

    public PortScanResult(int port, String service, String banner, String protocol,
                          long latency, String version, String state) {
        this.port     = new SimpleIntegerProperty(port);
        this.service  = new SimpleStringProperty(service);
        this.banner   = new SimpleStringProperty(banner);
        this.protocol = new SimpleStringProperty(protocol);
        this.latency  = new SimpleLongProperty(latency);
        this.version  = new SimpleStringProperty(version);
        this.state    = new SimpleStringProperty(state);
    }

    // -- port --
    public int getPort()                          { return port.get(); }
    public SimpleIntegerProperty portProperty()   { return port; }

    // -- service --
    public String getService()                    { return service.get(); }
    public SimpleStringProperty serviceProperty() { return service; }

    // -- banner --
    public String getBanner()                     { return banner.get(); }
    public SimpleStringProperty bannerProperty()  { return banner; }

    // -- protocol --
    public String getProtocol()                   { return protocol.get(); }
    public SimpleStringProperty protocolProperty(){ return protocol; }

    // -- latency --
    public long getLatency()                      { return latency.get(); }
    public SimpleLongProperty latencyProperty()   { return latency; }

    // -- version --
    public String getVersion()                    { return version.get(); }
    public SimpleStringProperty versionProperty() { return version; }

    // -- state --
    public String getState()                      { return state.get(); }
    public SimpleStringProperty stateProperty()   { return state; }
}
