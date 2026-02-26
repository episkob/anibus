package it.r2u.anibus.service;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * IoT and IP Camera Detection Service
 * Detects IP cameras, RTSP streams, ONVIF services, and various IoT devices
 */
public class IoTDetector {
    
    private static final int TIMEOUT = 3000;
    private static final int MAX_RESPONSE_SIZE = 10 * 1024; // 10KB
    
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
        private List<String> vulnerabilities;
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
                sb.append("  🔌 ONVIF Supported\n");
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
        if (port == 554) {
            device = detectRTSPCamera(host, port, banner);
        } else if (port == 80 || port == 8080 || port == 8081 || port == 8000) {
            device = detectWebCamera(host, port, banner);
        } else if (port == 37777) {
            device = detectDahuaCamera(host, port, banner);
        } else if (port == 34567) {
            device = detectXiongmaiCamera(host, port, banner);
        } else if (port == 9527) {
            device = detectGossipCamera(host, port, banner);
        } else if (port == 5000 || port == 5001) {
            device = detectSynologyNAS(host, port, banner);
        } else if (port == 8443 || port == 443) {
            device = detectWebCamera(host, port, banner);
        } else if (port == 23 || port == 2323) {
            device = detectTelnetIoT(host, port, banner);
        } else if (port == 1883 || port == 8883) {
            device = detectMQTTDevice(host, port, banner);
        }
        
        // Banner-based detection even if port is not typical
        if (device == null && banner != null && !banner.isEmpty()) {
            device = detectFromBanner(host, port, banner);
        }
        
        return device;
    }
    
    /**
     * Detect RTSP camera (port 554)
     */
    private static IoTDevice detectRTSPCamera(String host, int port, String banner) {
        IoTDevice device = new IoTDevice();
        device.setDeviceType("IP Camera (RTSP)");
        device.setHasRTSPStream(true);
        
        // Try RTSP handshake
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(TIMEOUT);
            socket.connect(new java.net.InetSocketAddress(host, port), TIMEOUT);
            
            // Send RTSP OPTIONS request
            String request = "OPTIONS rtsp://" + host + ":" + port + "/ RTSP/1.0\r\n" +
                           "CSeq: 1\r\n" +
                           "User-Agent: Anibus/1.0\r\n\r\n";
            
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.flush();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            
            StringBuilder response = new StringBuilder();
            String line;
            int lineCount = 0;
            while ((line = reader.readLine()) != null && lineCount < 20) {
                response.append(line).append("\n");
                lineCount++;
                if (line.isEmpty()) break;
            }
            
            String rtspResponse = response.toString().toLowerCase();
            
            // Detect manufacturer from RTSP response
            if (rtspResponse.contains("hikvision") || rtspResponse.contains("ds-")) {
                device.setManufacturer("Hikvision");
                device.setRtspUrl("rtsp://" + host + ":554/Streaming/Channels/101");
                device.getVulnerabilities().add("Multiple CVEs - firmware hardcoded credentials");
            } else if (rtspResponse.contains("dahua")) {
                device.setManufacturer("Dahua");
                device.setRtspUrl("rtsp://" + host + ":554/cam/realmonitor?channel=1&subtype=0");
                device.getVulnerabilities().add("CVE-2021-33044 - Authentication bypass");
            } else if (rtspResponse.contains("axis")) {
                device.setManufacturer("Axis Communications");
                device.setRtspUrl("rtsp://" + host + ":554/axis-media/media.amp");
            } else if (rtspResponse.contains("vivotek")) {
                device.setManufacturer("Vivotek");
                device.setRtspUrl("rtsp://" + host + ":554/live.sdp");
            } else if (rtspResponse.contains("foscam")) {
                device.setManufacturer("Foscam");
                device.setRtspUrl("rtsp://" + host + ":554/videoMain");
                device.setHasDefaultCredentials(true);
            } else if (rtspResponse.contains("tp-link") || rtspResponse.contains("tapo")) {
                device.setManufacturer("TP-Link");
                device.setRtspUrl("rtsp://" + host + ":554/stream1");
            } else {
                device.setRtspUrl("rtsp://" + host + ":554/");
            }
            
            // Check ONVIF support
            if (rtspResponse.contains("onvif")) {
                device.setHasONVIF(true);
            }
            
        } catch (IOException e) {
            // Still return partial info
            device.setRtspUrl("rtsp://" + host + ":554/");
        }
        
        return device;
    }
    
    /**
     * Detect IP camera via web interface
     */
    private static IoTDevice detectWebCamera(String host, int port, String banner) {
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
            
            // For HTTPS, trust all certificates
            if (conn instanceof javax.net.ssl.HttpsURLConnection) {
                javax.net.ssl.HttpsURLConnection httpsConn = (javax.net.ssl.HttpsURLConnection) conn;
                javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    }
                };
                javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
                sc.init(null, trustAll, new java.security.SecureRandom());
                httpsConn.setSSLSocketFactory(sc.getSocketFactory());
                httpsConn.setHostnameVerifier((hostname, session) -> true);
            }
            
            int responseCode = conn.getResponseCode();
            
            // Read response
            BufferedReader in = new BufferedReader(new InputStreamReader(
                responseCode < 400 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder content = new StringBuilder();
            String line;
            int totalSize = 0;
            
            while ((line = in.readLine()) != null && totalSize < MAX_RESPONSE_SIZE) {
                content.append(line).append("\n");
                totalSize += line.length();
            }
            in.close();
            
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
            
        } catch (Exception e) {
            // Silently fail
        }
        
        return device;
    }
    
    /**
     * Detect Dahua camera on custom port 37777
     */
    private static IoTDevice detectDahuaCamera(String host, int port, String banner) {
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
    private static IoTDevice detectXiongmaiCamera(String host, int port, String banner) {
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
    private static IoTDevice detectGossipCamera(String host, int port, String banner) {
        IoTDevice device = new IoTDevice();
        device.setDeviceType("IP Camera");
        device.setManufacturer("Generic (Gossip Protocol)");
        device.setAdditionalInfo("Port 9527 - Gossip camera protocol");
        return device;
    }
    
    /**
     * Detect Synology NAS
     */
    private static IoTDevice detectSynologyNAS(String host, int port, String banner) {
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
    private static IoTDevice detectTelnetIoT(String host, int port, String banner) {
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
    private static IoTDevice detectMQTTDevice(String host, int port, String banner) {
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
    private static IoTDevice detectFromBanner(String host, int port, String banner) {
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
               lower.contains("onvif") || lower.contains("rtsp");
    }
}
