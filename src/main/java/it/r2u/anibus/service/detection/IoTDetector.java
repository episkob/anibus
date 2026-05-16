package it.r2u.anibus.service.detection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import it.r2u.anibus.service.iot.AdbProbeService;
import it.r2u.anibus.service.iot.RtspProbeService;

/**
 * IoT and IP Camera Detection Service
 * Detects IP cameras, RTSP streams, ONVIF services, and various IoT devices
 */
public class IoTDetector {
    
    private static final int TIMEOUT = 3000;
    private static final int MAX_RESPONSE_SIZE = 10 * 1024; // 10KB
    private static final RtspProbeService RTSP_PROBE = new RtspProbeService(TIMEOUT);
    private static final AdbProbeService ADB_PROBE = new AdbProbeService(TIMEOUT);
    
    public static class IoTDevice {
        private String deviceType;
        private String manufacturer;
        private String model;
        private String firmware;
        private boolean hasDefaultCredentials;
        private boolean hasWebInterface;
        private String webInterfaceUrl;
        private boolean hasRTSPStream;
        private String rtspUrl;
        private boolean hasONVIF;
        private final List<String> vulnerabilities;
        private String additionalInfo;
        
        public IoTDevice() {
            this.vulnerabilities = new ArrayList<>();
        }
        
        // Getters and setters
        public String getDeviceType() { return deviceType; }
        public void setDeviceType(String deviceType) { this.deviceType = deviceType; }
        public String getManufacturer() { return manufacturer; }
        public void setManufacturer(String manufacturer) { this.manufacturer = manufacturer; }
        public String getModel() { return model; }
        public void setModel(String model) { this.model = model; }
        public String getFirmware() { return firmware; }
        public void setFirmware(String firmware) { this.firmware = firmware; }
        public boolean hasDefaultCredentials() { return hasDefaultCredentials; }
        public void setHasDefaultCredentials(boolean hasDefaultCredentials) { this.hasDefaultCredentials = hasDefaultCredentials; }
        public boolean hasWebInterface() { return hasWebInterface; }
        public void setHasWebInterface(boolean hasWebInterface) { this.hasWebInterface = hasWebInterface; }
        public String getWebInterfaceUrl() { return webInterfaceUrl; }
        public void setWebInterfaceUrl(String webInterfaceUrl) { this.webInterfaceUrl = webInterfaceUrl; }
        public boolean hasRTSPStream() { return hasRTSPStream; }
        public void setHasRTSPStream(boolean hasRTSPStream) { this.hasRTSPStream = hasRTSPStream; }
        public String getRtspUrl() { return rtspUrl; }
        public void setRtspUrl(String rtspUrl) { this.rtspUrl = rtspUrl; }
        public boolean hasONVIF() { return hasONVIF; }
        public void setHasONVIF(boolean hasONVIF) { this.hasONVIF = hasONVIF; }
        public List<String> getVulnerabilities() { return vulnerabilities; }
        public String getAdditionalInfo() { return additionalInfo; }
        public void setAdditionalInfo(String additionalInfo) { this.additionalInfo = additionalInfo; }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("[IOT] IoT Device Detected:\n");
            
            if (manufacturer != null) {
                sb.append("  Manufacturer: ").append(manufacturer);
                if (model != null) {
                    sb.append(" ").append(model);
                }
                sb.append("\n");
            }
            
            if (deviceType != null) {
                sb.append("  Type: ").append(deviceType).append("\n");
            }
            
            if (firmware != null) {
                sb.append("  Firmware: ").append(firmware).append("\n");
            }
            
            if (hasWebInterface && webInterfaceUrl != null) {
                sb.append("  [WEB] Web Interface: ").append(webInterfaceUrl).append("\n");
            }
            
            if (hasRTSPStream && rtspUrl != null) {
                sb.append("  [RTSP] RTSP Stream: ").append(rtspUrl).append("\n");
            }
            
            if (hasONVIF) {
                sb.append("  [ONVIF] Supported\n");
            }
            
            if (hasDefaultCredentials) {
                sb.append("  [WARN] WARNING: Likely using default credentials!\n");
            }
            
            if (!vulnerabilities.isEmpty()) {
                sb.append("  [ALERT] Known Issues:\n");
                for (String vuln : vulnerabilities) {
                    sb.append("    - ").append(vuln).append("\n");
                }
            }
            
            if (additionalInfo != null) {
                sb.append("  [INFO] ").append(additionalInfo).append("\n");
            }
            
            return sb.toString().trim();
        }
    }
    
    /**
     * Detect IoT device based on port and banner
     */
    public static IoTDevice detectIoTDevice(String host, int port, String banner) {
        IoTDevice device = null;
        
        // Port-specific detection
        switch (port) {
            case 554 -> device = detectRTSPCamera(host, port);
            case 80, 8080, 8081, 8000 -> device = detectWebCamera(host, port);
            case 37777 -> device = detectDahuaCamera(host);
            case 34567 -> device = detectXiongmaiCamera(host);
            case 9527 -> device = detectGossipCamera();
            case 5000, 5001 -> device = detectSynologyNAS(host, port);
            case 8443, 443 -> device = detectWebCamera(host, port);
            case 23, 2323 -> device = detectTelnetIoT(port, banner);
            case 1883, 8883 -> device = detectMQTTDevice(port);
            case 5555 -> device = detectAdb(host, port);
            default -> { }
        }
        
        // Banner-based detection even if port is not typical
        if (device == null && banner != null && !banner.isEmpty()) {
            device = detectFromBanner(banner);
        }
        
        return device;
    }
    
    /**
     * Detect RTSP camera (port 554)
     */
    private static IoTDevice detectRTSPCamera(String host, int port) {
        IoTDevice device = new IoTDevice();
        device.setDeviceType("IP Camera (RTSP)");
        device.setHasRTSPStream(true);

        RtspProbeService.RtspProbeResult probe = RTSP_PROBE.probe(host, port);
        device.setRtspUrl(probe.suggestedRtspUrl());
        if (probe.manufacturerGuess() != null) {
            device.setManufacturer(probe.manufacturerGuess());
        }

        String rawLower = probe.rawResponse() == null ? "" : probe.rawResponse().toLowerCase();
        if (rawLower.contains("onvif")) {
            device.setHasONVIF(true);
        }

        if ("Foscam".equals(device.getManufacturer())) {
            device.setHasDefaultCredentials(true);
        }
        if ("Hikvision".equals(device.getManufacturer())) {
            device.getVulnerabilities().add("Multiple CVEs - firmware hardcoded credentials");
        } else if ("Dahua".equals(device.getManufacturer())) {
            device.getVulnerabilities().add("CVE-2021-33044 - Authentication bypass");
        }

        return device;
    }

    /**
     * Detect exposed Android Debug Bridge (ADB), typically on port 5555.
     */
    private static IoTDevice detectAdb(String host, int port) {
        AdbProbeService.AdbProbeResult res = ADB_PROBE.probe(host, port);
        if (!res.ok()) {
            return null;
        }
        IoTDevice device = new IoTDevice();
        device.setDeviceType("Android Debug Bridge (ADB)");
        device.setAdditionalInfo("ADB service responded on port " + port + (res.version() != null ? (" (version=" + res.version() + ")") : ""));
        device.getVulnerabilities().add("ADB over TCP exposed — remote debugging interface accessible");
        device.setHasDefaultCredentials(true);
        return device;
    }
    
    /**
     * Detect IP camera via web interface
     */
    private static IoTDevice detectWebCamera(String host, int port) {
        IoTDevice device = null;
        
        try {
            String protocol = (port == 443 || port == 8443) ? "https" : "http";
            String url = protocol + "://" + host + ":" + port;
            
            URI uri = new URI(url);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            conn.setInstanceFollowRedirects(true);
            
            // For HTTPS, keep default JVM certificate and hostname verification.
            if (conn instanceof javax.net.ssl.HttpsURLConnection) {
                // Default verification is intentionally preserved.
            }
            
            int responseCode = conn.getResponseCode();
            
            // Read response
            StringBuilder content = new StringBuilder();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(
                responseCode < 400 ? conn.getInputStream() : conn.getErrorStream()))) {
                String line;
                int totalSize = 0;
                
                while ((line = in.readLine()) != null && totalSize < MAX_RESPONSE_SIZE) {
                    content.append(line).append("\n");
                    totalSize += line.length();
                }
            }
            
            String pageContent = content.toString().toLowerCase();
            String headers = getHeadersString(conn).toLowerCase();
            
            // Detect specific camera brands
            
            // Hikvision
            if (pageContent.contains("hikvision") || headers.contains("hikvision") || 
                pageContent.contains("/doc/page/login.asp") || pageContent.contains("ivms-")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setManufacturer("Hikvision");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                device.setHasRTSPStream(true);
                device.setRtspUrl("rtsp://" + host + ":554/Streaming/Channels/101");
                device.setHasONVIF(true);
                device.getVulnerabilities().add("CVE-2021-36260 - Command injection");
                device.getVulnerabilities().add("Default credentials: admin/12345");
                device.setHasDefaultCredentials(true);
            }
            
            // Dahua
            else if (pageContent.contains("dahua") || headers.contains("dahua") ||
                     pageContent.contains("dh_") || pageContent.contains("/rpc/")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setManufacturer("Dahua");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                device.setHasRTSPStream(true);
                device.setRtspUrl("rtsp://" + host + ":554/cam/realmonitor?channel=1&subtype=0");
                device.setHasONVIF(true);
                device.getVulnerabilities().add("CVE-2021-33044 - Auth bypass");
                device.getVulnerabilities().add("Default credentials: admin/admin");
                device.setHasDefaultCredentials(true);
            }
            
            // Axis
            else if (pageContent.contains("axis") || headers.contains("axis communications")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setManufacturer("Axis Communications");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                device.setHasRTSPStream(true);
                device.setRtspUrl("rtsp://" + host + ":554/axis-media/media.amp");
                device.setHasONVIF(true);
            }
            
            // Foscam
            else if (pageContent.contains("foscam") || headers.contains("foscam")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setManufacturer("Foscam");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                device.setHasRTSPStream(true);
                device.setRtspUrl("rtsp://" + host + ":554/videoMain");
                device.getVulnerabilities().add("Multiple backdoors and default credentials");
                device.setHasDefaultCredentials(true);
            }
            
            // TP-Link (Tapo cameras)
            else if (pageContent.contains("tp-link") || pageContent.contains("tapo") || 
                     headers.contains("tp-link")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setManufacturer("TP-Link");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                device.setHasRTSPStream(true);
                device.setRtspUrl("rtsp://" + host + ":554/stream1");
            }
            
            // Vivotek
            else if (pageContent.contains("vivotek") || headers.contains("vivotek")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setManufacturer("Vivotek");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                device.setHasRTSPStream(true);
                device.setRtspUrl("rtsp://" + host + ":554/live.sdp");
                device.setHasONVIF(true);
            }
            
            // D-Link cameras
            else if (pageContent.contains("d-link") || headers.contains("d-link") ||
                     pageContent.contains("dcs-")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setManufacturer("D-Link");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                device.getVulnerabilities().add("Multiple RCE vulnerabilities");
                device.setHasDefaultCredentials(true);
            }
            
            // Xiaomi/Xiaofang cameras
            else if (pageContent.contains("xiaomi") || pageContent.contains("mijia") ||
                     pageContent.contains("xiaofang")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setManufacturer("Xiaomi");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                device.setHasRTSPStream(true);
            }
            
            // Generic camera detection
            else if (pageContent.contains("webcamxp") || pageContent.contains("ip camera") ||
                     pageContent.contains("network camera") || pageContent.contains("video stream")) {
                device = new IoTDevice();
                device.setDeviceType("IP Camera");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
            }
            
            // Router detection
            else if (pageContent.contains("router login") || pageContent.contains("router config") ||
                     headers.contains("router")) {
                device = new IoTDevice();
                device.setDeviceType("Router");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
                detectRouterBrand(device, pageContent, headers);
            }
            
            // Smart home hub detection
            else if (pageContent.contains("smart home") || pageContent.contains("home assistant") ||
                     pageContent.contains("homeassistant")) {
                device = new IoTDevice();
                device.setDeviceType("Smart Home Hub");
                device.setHasWebInterface(true);
                device.setWebInterfaceUrl(url);
            }
            
            conn.disconnect();
            
        } catch (java.io.IOException | java.net.URISyntaxException e) {
            // Silently fail
        }
        
        return device;
    }
    
    /**
     * Detect Dahua camera on custom port 37777
     */
    private static IoTDevice detectDahuaCamera(String host) {
        IoTDevice device = new IoTDevice();
        device.setDeviceType("IP Camera");
        device.setManufacturer("Dahua");
        device.setHasWebInterface(true);
        device.setWebInterfaceUrl("http://" + host + ":80");
        device.setHasRTSPStream(true);
        device.setRtspUrl("rtsp://" + host + ":554/cam/realmonitor?channel=1&subtype=0");
        device.getVulnerabilities().add("CVE-2021-33044 - Authentication bypass");
        device.getVulnerabilities().add("Port 37777 - Dahua DVR protocol");
        device.setHasDefaultCredentials(true);
        return device;
    }
    
    /**
     * Detect Xiongmai/XMEye camera on port 34567
     */
    private static IoTDevice detectXiongmaiCamera(String host) {
        IoTDevice device = new IoTDevice();
        device.setDeviceType("IP Camera/DVR");
        device.setManufacturer("Xiongmai (XMEye)");
        device.setHasWebInterface(true);
        device.setWebInterfaceUrl("http://" + host + ":80");
        device.getVulnerabilities().add("CVE-2018-9995 - Backdoor account");
        device.getVulnerabilities().add("Multiple firmware backdoors");
        device.setHasDefaultCredentials(true);
        device.setAdditionalInfo("Port 34567 - XMEye DVR protocol");
        return device;
    }
    
    /**
     * Detect Gossip camera on port 9527
     */
    private static IoTDevice detectGossipCamera() {
        IoTDevice device = new IoTDevice();
        device.setDeviceType("IP Camera");
        device.setManufacturer("Generic (Gossip Protocol)");
        device.setAdditionalInfo("Port 9527 - Gossip camera protocol");
        return device;
    }
    
    /**
     * Detect Synology NAS
     */
    private static IoTDevice detectSynologyNAS(String host, int port) {
        IoTDevice device = new IoTDevice();
        device.setDeviceType("NAS (Network Attached Storage)");
        device.setManufacturer("Synology");
        device.setHasWebInterface(true);
        device.setWebInterfaceUrl("http://" + host + ":" + port);
        return device;
    }
    
    /**
     * Detect IoT devices via Telnet
     */
    private static IoTDevice detectTelnetIoT(int port, String banner) {
        if (banner == null || banner.isEmpty()) {
            return null;
        }
        
        String lower = banner.toLowerCase();
        IoTDevice device = null;
        
        if (lower.contains("camera") || lower.contains("ipc") || lower.contains("dvr") ||
            lower.contains("nvr")) {
            device = new IoTDevice();
            device.setDeviceType("IP Camera/DVR");
            device.setAdditionalInfo("Telnet access on port " + port);
            device.getVulnerabilities().add("Telnet enabled - insecure protocol");
            
            if (port == 2323) {
                device.getVulnerabilities().add("Non-standard telnet port (possible backdoor)");
            }
        } else if (lower.contains("busybox") || lower.contains("buildroot")) {
            device = new IoTDevice();
            device.setDeviceType("Embedded Linux Device");
            device.setAdditionalInfo("BusyBox/Buildroot system on port " + port);
            device.getVulnerabilities().add("Telnet enabled - likely IoT device");
        }
        
        return device;
    }
    
    /**
     * Detect MQTT broker (IoT communication protocol)
     */
    private static IoTDevice detectMQTTDevice(int port) {
        IoTDevice device = new IoTDevice();
        device.setDeviceType("MQTT Broker (IoT Hub)");
        device.setAdditionalInfo("MQTT message broker on port " + port);
        
        if (port == 1883) {
            device.getVulnerabilities().add("Unencrypted MQTT - should use port 8883 (TLS)");
        }
        
        return device;
    }
    
    /**
     * Detect from banner when port is not typical
     */
    private static IoTDevice detectFromBanner(String banner) {
        String lower = banner.toLowerCase();
        
        if (lower.contains("hikvision")) {
            IoTDevice device = new IoTDevice();
            device.setDeviceType("IP Camera");
            device.setManufacturer("Hikvision");
            device.setHasONVIF(true);
            return device;
        } else if (lower.contains("dahua")) {
            IoTDevice device = new IoTDevice();
            device.setDeviceType("IP Camera");
            device.setManufacturer("Dahua");
            device.setHasONVIF(true);
            return device;
        } else if (lower.contains("axis")) {
            IoTDevice device = new IoTDevice();
            device.setDeviceType("IP Camera");
            device.setManufacturer("Axis Communications");
            device.setHasONVIF(true);
            return device;
        }
        
        return null;
    }
    
    /**
     * Detect router brand from web interface
     */
    private static void detectRouterBrand(IoTDevice device, String content, String headers) {
        if (content.contains("tp-link") || headers.contains("tp-link")) {
            device.setManufacturer("TP-Link");
        } else if (content.contains("asus") || headers.contains("asus")) {
            device.setManufacturer("ASUS");
        } else if (content.contains("netgear") || headers.contains("netgear")) {
            device.setManufacturer("Netgear");
        } else if (content.contains("d-link") || headers.contains("d-link")) {
            device.setManufacturer("D-Link");
        } else if (content.contains("linksys") || headers.contains("linksys")) {
            device.setManufacturer("Linksys");
        } else if (content.contains("mikrotik") || headers.contains("mikrotik")) {
            device.setManufacturer("MikroTik");
        } else if (content.contains("ubiquiti") || headers.contains("ubiquiti")) {
            device.setManufacturer("Ubiquiti");
        }
    }
    
    /**
     * Get headers as string for analysis
     */
    private static String getHeadersString(HttpURLConnection conn) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; ; i++) {
            String headerName = conn.getHeaderFieldKey(i);
            String headerValue = conn.getHeaderField(i);
            if (headerName == null && headerValue == null) {
                break;
            }
            if (headerName != null) {
                sb.append(headerName).append(": ").append(headerValue).append("\n");
            }
        }
        return sb.toString();
    }
    
    /**
     * Check if device is likely a camera
     */
    public static boolean isLikelyCamera(int port) {
        return port == 554 || // RTSP
               port == 8000 || port == 8001 || // Common camera ports
               port == 37777 || // Dahua
               port == 34567 || // Xiongmai
               port == 9527;    // Gossip
    }
    
    /**
     * Quick check if banner indicates IoT device
     */
    public static boolean isIoTBanner(String banner) {
        if (banner == null || banner.isEmpty()) {
            return false;
        }
        
        String lower = banner.toLowerCase();
        return lower.contains("camera") || lower.contains("ipc") ||
               lower.contains("dvr") || lower.contains("nvr") ||
               lower.contains("hikvision") || lower.contains("dahua") ||
               lower.contains("axis") || lower.contains("foscam") ||
               lower.contains("vivotek") || lower.contains("mqtt") ||
               lower.contains("onvif") || lower.contains("rtsp") ||
               lower.contains("android debug bridge") || lower.contains("adb");
    }
}
