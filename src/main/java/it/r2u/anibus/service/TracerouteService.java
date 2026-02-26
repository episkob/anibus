package it.r2u.anibus.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Traceroute Service
 * Provides network path visualization showing intermediate hops
 */
public class TracerouteService {
    
    private static final int MAX_HOPS = 30;
    private static final int TIMEOUT_MS = 5000;
    
    public static class Hop {
        private int hopNumber;
        private String ipAddress;
        private String hostname;
        private long rtt1; // Round-trip time 1 (ms)
        private long rtt2; // Round-trip time 2 (ms)
        private long rtt3; // Round-trip time 3 (ms)
        private boolean timeout;
        
        public Hop(int hopNumber) {
            this.hopNumber = hopNumber;
            this.rtt1 = -1;
            this.rtt2 = -1;
            this.rtt3 = -1;
        }
        
        public int getHopNumber() { return hopNumber; }
        public String getIpAddress() { return ipAddress; }
        public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
        public String getHostname() { return hostname; }
        public void setHostname(String hostname) { this.hostname = hostname; }
        public long getRtt1() { return rtt1; }
        public void setRtt1(long rtt1) { this.rtt1 = rtt1; }
        public long getRtt2() { return rtt2; }
        public void setRtt2(long rtt2) { this.rtt2 = rtt2; }
        public long getRtt3() { return rtt3; }
        public void setRtt3(long rtt3) { this.rtt3 = rtt3; }
        public boolean isTimeout() { return timeout; }
        public void setTimeout(boolean timeout) { this.timeout = timeout; }
        
        public long getAverageRTT() {
            int count = 0;
            long total = 0;
            
            if (rtt1 >= 0) { total += rtt1; count++; }
            if (rtt2 >= 0) { total += rtt2; count++; }
            if (rtt3 >= 0) { total += rtt3; count++; }
            
            return count > 0 ? total / count : -1;
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%2d  ", hopNumber));
            
            if (timeout) {
                sb.append("* * * (timeout)");
            } else {
                if (hostname != null && !hostname.equals(ipAddress)) {
                    sb.append(hostname).append(" ");
                }
                
                if (ipAddress != null) {
                    sb.append("(").append(ipAddress).append(")");
                }
                
                sb.append("  ");
                
                if (rtt1 >= 0) sb.append(rtt1).append(" ms  ");
                else sb.append("*  ");
                
                if (rtt2 >= 0) sb.append(rtt2).append(" ms  ");
                else sb.append("*  ");
                
                if (rtt3 >= 0) sb.append(rtt3).append(" ms");
                else sb.append("*");
            }
            
            return sb.toString();
        }
    }
    
    public static class TraceRoute {
        private String targetHost;
        private String targetIP;
        private List<Hop> hops;
        private int totalHops;
        private boolean reachedTarget;
        
        public TraceRoute(String targetHost) {
            this.targetHost = targetHost;
            this.hops = new ArrayList<>();
        }
        
        public String getTargetHost() { return targetHost; }
        public String getTargetIP() { return targetIP; }
        public void setTargetIP(String targetIP) { this.targetIP = targetIP; }
        public List<Hop> getHops() { return hops; }
        public int getTotalHops() { return totalHops; }
        public void setTotalHops(int totalHops) { this.totalHops = totalHops; }
        public boolean isReachedTarget() { return reachedTarget; }
        public void setReachedTarget(boolean reachedTarget) { this.reachedTarget = reachedTarget; }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("[TRACEROUTE] Traceroute to ").append(targetHost);
            
            if (targetIP != null) {
                sb.append(" (").append(targetIP).append(")");
            }
            
            sb.append(", ").append(MAX_HOPS).append(" hops max:\n\n");
            
            for (Hop hop : hops) {
                sb.append(hop.toString()).append("\n");
            }
            
            if (reachedTarget) {
                sb.append("\n✅ Successfully reached target in ").append(totalHops).append(" hops");
            } else {
                sb.append("\n[WARN] Did not reach target within ").append(MAX_HOPS).append(" hops");
            }
            
            return sb.toString();
        }
    }
    
    /**
     * Perform traceroute to target host
     */
    public static TraceRoute traceroute(String host) {
        TraceRoute result = new TraceRoute(host);
        
        try {
            // Resolve target IP
            InetAddress target = InetAddress.getByName(host);
            result.setTargetIP(target.getHostAddress());
            
            // Determine OS and execute appropriate traceroute command
            String os = System.getProperty("os.name").toLowerCase();
            ProcessBuilder pb;
            
            if (os.contains("win")) {
                // Windows: tracert
                pb = new ProcessBuilder("tracert", "-d", "-h", String.valueOf(MAX_HOPS), host);
            } else {
                // Linux/Unix: traceroute
                pb = new ProcessBuilder("traceroute", "-m", String.valueOf(MAX_HOPS), "-w", "3", host);
            }
            
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            String line;
            int hopCount = 0;
            boolean isWindows = os.contains("win");
            
            while ((line = reader.readLine()) != null) {
                Hop hop = parseTracerouteLine(line, isWindows);
                
                if (hop != null) {
                    result.getHops().add(hop);
                    hopCount++;
                    
                    // Check if we reached the target
                    if (hop.getIpAddress() != null && hop.getIpAddress().equals(result.getTargetIP())) {
                        result.setReachedTarget(true);
                        result.setTotalHops(hopCount);
                        break;
                    }
                }
            }
            
            reader.close();
            process.waitFor();
            
            if (!result.isReachedTarget()) {
                result.setTotalHops(hopCount);
            }
            
        } catch (Exception e) {
            // Return partial results or empty
        }
        
        return result;
    }
    
    /**
     * Parse a single line from traceroute output
     */
    private static Hop parseTracerouteLine(String line, boolean isWindows) {
        if (line == null || line.trim().isEmpty()) {
            return null;
        }
        
        line = line.trim();
        
        // Skip header lines
        if (line.startsWith("Tracing route") || line.startsWith("traceroute to") ||
            line.contains("over a maximum") || line.contains("hops max")) {
            return null;
        }
        
        Hop hop = null;
        
        if (isWindows) {
            // Windows tracert format: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            Pattern pattern = Pattern.compile("^\\s*(\\d+)\\s+(.+)");
            Matcher matcher = pattern.matcher(line);
            
            if (matcher.find()) {
                int hopNum = Integer.parseInt(matcher.group(1));
                hop = new Hop(hopNum);
                
                String rest = matcher.group(2);
                
                // Check for timeout
                if (rest.contains("Request timed out") || rest.contains("* * *")) {
                    hop.setTimeout(true);
                    return hop;
                }
                
                // Extract RTT values
                Pattern rttPattern = Pattern.compile("(\\d+)\\s*ms");
                Matcher rttMatcher = rttPattern.matcher(rest);
                
                if (rttMatcher.find()) hop.setRtt1(Long.parseLong(rttMatcher.group(1)));
                if (rttMatcher.find()) hop.setRtt2(Long.parseLong(rttMatcher.group(1)));
                if (rttMatcher.find()) hop.setRtt3(Long.parseLong(rttMatcher.group(1)));
                
                // Extract IP address
                Pattern ipPattern = Pattern.compile("(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
                Matcher ipMatcher = ipPattern.matcher(rest);
                
                if (ipMatcher.find()) {
                    hop.setIpAddress(ipMatcher.group(1));
                }
                
                // Extract hostname (if present)
                Pattern hostnamePattern = Pattern.compile("([a-zA-Z0-9][-a-zA-Z0-9.]+[a-zA-Z0-9])\\s+\\[");
                Matcher hostnameMatcher = hostnamePattern.matcher(rest);
                
                if (hostnameMatcher.find()) {
                    hop.setHostname(hostnameMatcher.group(1));
                }
            }
            
        } else {
            // Linux traceroute format: " 1  192.168.1.1 (192.168.1.1)  0.234 ms  0.156 ms  0.189 ms"
            Pattern pattern = Pattern.compile("^\\s*(\\d+)\\s+(.+)");
            Matcher matcher = pattern.matcher(line);
            
            if (matcher.find()) {
                int hopNum = Integer.parseInt(matcher.group(1));
                hop = new Hop(hopNum);
                
                String rest = matcher.group(2);
                
                // Check for timeout
                if (rest.contains("* * *")) {
                    hop.setTimeout(true);
                    return hop;
                }
                
                // Extract IP address
                Pattern ipPattern = Pattern.compile("\\((\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\)");
                Matcher ipMatcher = ipPattern.matcher(rest);
                
                if (ipMatcher.find()) {
                    hop.setIpAddress(ipMatcher.group(1));
                }
                
                // Extract hostname
                Pattern hostnamePattern = Pattern.compile("^([a-zA-Z0-9][-a-zA-Z0-9.]+[a-zA-Z0-9])\\s+");
                Matcher hostnameMatcher = hostnamePattern.matcher(rest);
                
                if (hostnameMatcher.find()) {
                    hop.setHostname(hostnameMatcher.group(1));
                }
                
                // Extract RTT values
                Pattern rttPattern = Pattern.compile("([\\d.]+)\\s*ms");
                Matcher rttMatcher = rttPattern.matcher(rest);
                
                if (rttMatcher.find()) hop.setRtt1((long) Double.parseDouble(rttMatcher.group(1)));
                if (rttMatcher.find()) hop.setRtt2((long) Double.parseDouble(rttMatcher.group(1)));
                if (rttMatcher.find()) hop.setRtt3((long) Double.parseDouble(rttMatcher.group(1)));
            }
        }
        
        return hop;
    }
    
    /**
     * Perform quick ICMP ping to estimate RTT
     */
    public static Long quickPing(String host) {
        try {
            long start = System.currentTimeMillis();
            InetAddress address = InetAddress.getByName(host);
            
            if (address.isReachable(TIMEOUT_MS)) {
                return System.currentTimeMillis() - start;
            }
        } catch (Exception e) {
            // Silently fail
        }
        
        return null;
    }
}
