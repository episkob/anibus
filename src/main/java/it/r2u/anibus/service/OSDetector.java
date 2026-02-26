package it.r2u.anibus.service;

import java.io.IOException;
import java.net.InetAddress;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OS Detection Service
 * Detects operating system based on TTL, TCP characteristics, and banner analysis
 */
public class OSDetector {
    
    public static class OSInfo {
        private String osName;
        private String kernelVersion;
        private int confidence; // 0-100%
        private String detectionMethod;
        
        public OSInfo(String osName, String kernelVersion, int confidence, String detectionMethod) {
            this.osName = osName;
            this.kernelVersion = kernelVersion;
            this.confidence = confidence;
            this.detectionMethod = detectionMethod;
        }
        
        public String getOsName() { return osName; }
        public String getKernelVersion() { return kernelVersion; }
        public int getConfidence() { return confidence; }
        public String getDetectionMethod() { return detectionMethod; }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("[OS] OS: ").append(osName);
            if (kernelVersion != null && !kernelVersion.isEmpty()) {
                sb.append(" | Kernel: ").append(kernelVersion);
            }
            sb.append(" | Confidence: ").append(confidence).append("%");
            return sb.toString();
        }
    }
    
    /**
     * Detect OS from TTL value
     * Different operating systems use different default TTL values
     */
    public static OSInfo detectFromTTL(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            
            // Ping to get TTL (approximate via reachability test)
            boolean reachable = address.isReachable(2000);
            
            if (!reachable) {
                return null;
            }
            
            // Try to execute system ping to get actual TTL
            String os = System.getProperty("os.name").toLowerCase();
            ProcessBuilder pb;
            
            if (os.contains("win")) {
                pb = new ProcessBuilder("ping", "-n", "1", host);
            } else {
                pb = new ProcessBuilder("ping", "-c", "1", host);
            }
            
            Process process = pb.start();
            String output = new String(process.getInputStream().readAllBytes());
            process.waitFor();
            
            // Parse TTL from ping output
            Pattern ttlPattern = Pattern.compile("(?:ttl|TTL)\\s*[=:]?\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
            Matcher matcher = ttlPattern.matcher(output);
            
            if (matcher.find()) {
                int ttl = Integer.parseInt(matcher.group(1));
                return analyzeOSFromTTL(ttl, "TTL Analysis");
            }
            
        } catch (IOException | InterruptedException e) {
            // Silently fail
        }
        
        return null;
    }
    
    /**
     * Analyze OS based on TTL value
     */
    private static OSInfo analyzeOSFromTTL(int ttl, String method) {
        // TTL fingerprinting based on known defaults
        // Note: TTL decreases by 1 for each hop, so we look at ranges
        
        if (ttl >= 60 && ttl <= 64) {
            return new OSInfo("Linux/Unix", null, 75, method);
        } else if (ttl >= 120 && ttl <= 128) {
            return new OSInfo("Windows", null, 75, method);
        } else if (ttl >= 250 && ttl <= 255) {
            return new OSInfo("Cisco IOS/Network Device", null, 70, method);
        } else if (ttl >= 30 && ttl <= 32) {
            return new OSInfo("Windows 95/98", null, 60, method);
        } else if (ttl >= 200 && ttl <= 210) {
            return new OSInfo("AIX/BSD", null, 65, method);
        }
        
        return new OSInfo("Unknown", null, 30, method);
    }
    
    /**
     * Detect OS from banner strings
     */
    public static OSInfo detectFromBanner(String banner) {
        if (banner == null || banner.isEmpty()) {
            return null;
        }
        
        String lowerBanner = banner.toLowerCase();
        
        // Linux distributions
        if (lowerBanner.contains("linux")) {
            String kernelVersion = extractKernelVersion(banner);
            
            if (lowerBanner.contains("ubuntu")) {
                return new OSInfo("Ubuntu Linux", kernelVersion, 95, "Banner Analysis");
            } else if (lowerBanner.contains("debian")) {
                return new OSInfo("Debian Linux", kernelVersion, 95, "Banner Analysis");
            } else if (lowerBanner.contains("centos")) {
                return new OSInfo("CentOS Linux", kernelVersion, 95, "Banner Analysis");
            } else if (lowerBanner.contains("redhat") || lowerBanner.contains("rhel")) {
                return new OSInfo("Red Hat Enterprise Linux", kernelVersion, 95, "Banner Analysis");
            } else if (lowerBanner.contains("fedora")) {
                return new OSInfo("Fedora Linux", kernelVersion, 95, "Banner Analysis");
            } else if (lowerBanner.contains("alpine")) {
                return new OSInfo("Alpine Linux", kernelVersion, 95, "Banner Analysis");
            } else if (lowerBanner.contains("arch")) {
                return new OSInfo("Arch Linux", kernelVersion, 95, "Banner Analysis");
            } else {
                return new OSInfo("Linux", kernelVersion, 90, "Banner Analysis");
            }
        }
        
        // Windows versions
        if (lowerBanner.contains("windows") || lowerBanner.contains("microsoft") || lowerBanner.contains("win32") || lowerBanner.contains("win64")) {
            if (lowerBanner.contains("windows server 2022")) {
                return new OSInfo("Windows Server 2022", null, 95, "Banner Analysis");
            } else if (lowerBanner.contains("windows server 2019")) {
                return new OSInfo("Windows Server 2019", null, 95, "Banner Analysis");
            } else if (lowerBanner.contains("windows server 2016")) {
                return new OSInfo("Windows Server 2016", null, 95, "Banner Analysis");
            } else if (lowerBanner.contains("windows server 2012")) {
                return new OSInfo("Windows Server 2012", null, 95, "Banner Analysis");
            } else if (lowerBanner.contains("windows 11")) {
                return new OSInfo("Windows 11", null, 95, "Banner Analysis");
            } else if (lowerBanner.contains("windows 10")) {
                return new OSInfo("Windows 10", null, 95, "Banner Analysis");
            } else if (lowerBanner.contains("windows")) {
                return new OSInfo("Windows", null, 85, "Banner Analysis");
            }
        }
        
        // BSD variants
        if (lowerBanner.contains("freebsd")) {
            String version = extractVersion(banner, "freebsd");
            return new OSInfo("FreeBSD", version, 95, "Banner Analysis");
        } else if (lowerBanner.contains("openbsd")) {
            String version = extractVersion(banner, "openbsd");
            return new OSInfo("OpenBSD", version, 95, "Banner Analysis");
        } else if (lowerBanner.contains("netbsd")) {
            String version = extractVersion(banner, "netbsd");
            return new OSInfo("NetBSD", version, 95, "Banner Analysis");
        }
        
        // macOS
        if (lowerBanner.contains("darwin") || lowerBanner.contains("macos") || lowerBanner.contains("mac os")) {
            String version = extractVersion(banner, "darwin");
            return new OSInfo("macOS", version, 90, "Banner Analysis");
        }
        
        // Unix variants
        if (lowerBanner.contains("solaris")) {
            return new OSInfo("Solaris", null, 95, "Banner Analysis");
        } else if (lowerBanner.contains("aix")) {
            return new OSInfo("IBM AIX", null, 95, "Banner Analysis");
        } else if (lowerBanner.contains("hp-ux")) {
            return new OSInfo("HP-UX", null, 95, "Banner Analysis");
        }
        
        // Network devices
        if (lowerBanner.contains("cisco")) {
            return new OSInfo("Cisco IOS", null, 90, "Banner Analysis");
        } else if (lowerBanner.contains("junos")) {
            return new OSInfo("Juniper JunOS", null, 90, "Banner Analysis");
        } else if (lowerBanner.contains("mikrotik")) {
            return new OSInfo("MikroTik RouterOS", null, 90, "Banner Analysis");
        }
        
        // Unix-like hints
        if (lowerBanner.contains("unix")) {
            return new OSInfo("Unix-like", null, 70, "Banner Analysis");
        }
        
        return null;
    }
    
    /**
     * Extract kernel version from banner
     */
    private static String extractKernelVersion(String banner) {
        // Pattern for kernel version like 5.15.0-91-generic or 4.19.0
        Pattern pattern = Pattern.compile("(\\d+\\.\\d+\\.\\d+(?:-\\d+)?(?:-\\w+)?)");
        Matcher matcher = pattern.matcher(banner);
        
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        return null;
    }
    
    /**
     * Extract version for specific OS
     */
    private static String extractVersion(String banner, String osName) {
        Pattern pattern = Pattern.compile(osName + "[\\s/]*(\\d+\\.\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(banner);
        
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        return null;
    }
    
    /**
     * Combine multiple detection methods for best result
     */
    public static OSInfo detectOS(String host, String banner) {
        OSInfo bannerOS = detectFromBanner(banner);
        
        // If banner detection is confident, use it
        if (bannerOS != null && bannerOS.getConfidence() >= 90) {
            return bannerOS;
        }
        
        OSInfo ttlOS = detectFromTTL(host);
        
        // If we have both, prefer banner but mention TTL
        if (bannerOS != null && ttlOS != null) {
            // If they agree, increase confidence
            if (bannerOS.getOsName().toLowerCase().contains(ttlOS.getOsName().toLowerCase()) ||
                ttlOS.getOsName().toLowerCase().contains(bannerOS.getOsName().toLowerCase())) {
                return new OSInfo(bannerOS.getOsName(), bannerOS.getKernelVersion(), 
                                 Math.min(95, bannerOS.getConfidence() + 10), 
                                 "Banner + TTL");
            }
            return bannerOS; // Prefer banner if they don't agree
        }
        
        // Return whichever is available
        return bannerOS != null ? bannerOS : ttlOS;
    }
}
