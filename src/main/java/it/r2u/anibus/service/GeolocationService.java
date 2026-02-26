package it.r2u.anibus.service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Geolocation and WHOIS Service
 * Provides geographical and organizational information for IP addresses
 */
public class GeolocationService {
    
    private static final int TIMEOUT = 5000;
    
    public static class GeoInfo {
        private String ip;
        private String country;
        private String city;
        private String isp;
        private String asn;
        private String organization;
        private String region;
        private String timezone;
        private double latitude;
        private double longitude;
        private boolean isPrivate;
        private boolean isCloudProvider;
        private String cloudProvider;
        
        public GeoInfo(String ip) {
            this.ip = ip;
        }
        
        // Getters and setters
        public String getIp() { return ip; }
        public String getCountry() { return country; }
        public void setCountry(String country) { this.country = country; }
        public String getCity() { return city; }
        public void setCity(String city) { this.city = city; }
        public String getIsp() { return isp; }
        public void setIsp(String isp) { this.isp = isp; }
        public String getAsn() { return asn; }
        public void setAsn(String asn) { this.asn = asn; }
        public String getOrganization() { return organization; }
        public void setOrganization(String organization) { this.organization = organization; }
        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }
        public String getTimezone() { return timezone; }
        public void setTimezone(String timezone) { this.timezone = timezone; }
        public double getLatitude() { return latitude; }
        public void setLatitude(double latitude) { this.latitude = latitude; }
        public double getLongitude() { return longitude; }
        public void setLongitude(double longitude) { this.longitude = longitude; }
        public boolean isPrivate() { return isPrivate; }
        public void setPrivate(boolean isPrivate) { this.isPrivate = isPrivate; }
        public boolean isCloudProvider() { return isCloudProvider; }
        public void setCloudProvider(boolean isCloudProvider) { this.isCloudProvider = isCloudProvider; }
        public String getCloudProvider() { return cloudProvider; }
        public void setCloudProvider(String cloudProvider) { this.cloudProvider = cloudProvider; }
        
        @Override
        public String toString() {
            if (isPrivate) {
                return "[GEO] " + ip + " - Private/Local Network";
            }
            
            StringBuilder sb = new StringBuilder();
            sb.append("[GEO] ").append(ip);
            
            if (country != null) {
                sb.append(" | ").append(country);
                if (city != null) {
                    sb.append(", ").append(city);
                }
            }
            
            if (isCloudProvider && cloudProvider != null) {
                sb.append(" | [CLOUD] ").append(cloudProvider);
            } else if (isp != null) {
                sb.append(" | ISP: ").append(isp);
            }
            
            if (asn != null) {
                sb.append(" | ASN: ").append(asn);
            }
            
            if (organization != null && !organization.equals(isp)) {
                sb.append(" | Org: ").append(organization);
            }
            
            return sb.toString();
        }
        
        public String toDetailedString() {
            if (isPrivate) {
                return toString();
            }
            
            StringBuilder sb = new StringBuilder();
            sb.append("[GEO] Geolocation Information:\n");
            sb.append("  IP: ").append(ip).append("\n");
            
            if (country != null) {
                sb.append("  Country: ").append(country).append("\n");
            }
            if (region != null) {
                sb.append("  Region: ").append(region).append("\n");
            }
            if (city != null) {
                sb.append("  City: ").append(city).append("\n");
            }
            if (timezone != null) {
                sb.append("  Timezone: ").append(timezone).append("\n");
            }
            if (latitude != 0 || longitude != 0) {
                sb.append("  Coordinates: ").append(latitude).append(", ").append(longitude).append("\n");
            }
            
            if (isCloudProvider && cloudProvider != null) {
                sb.append("  [CLOUD] Cloud Provider: ").append(cloudProvider).append("\n");
            }
            
            if (isp != null) {
                sb.append("  ISP: ").append(isp).append("\n");
            }
            if (asn != null) {
                sb.append("  ASN: ").append(asn).append("\n");
            }
            if (organization != null) {
                sb.append("  Organization: ").append(organization).append("\n");
            }
            
            return sb.toString().trim();
        }
    }
    
    /**
     * Check if IP is private/internal
     */
    private static boolean isPrivateIP(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.isSiteLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress();
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get geolocation information for an IP address
     */
    public static GeoInfo getGeoInfo(String ip) {
        GeoInfo geoInfo = new GeoInfo(ip);
        
        // Check if private IP
        if (isPrivateIP(ip)) {
            geoInfo.setPrivate(true);
            return geoInfo;
        }
        
        try {
            // Use ip-api.com (free, no API key required, 45 requests/minute)
            String urlString = "http://ip-api.com/json/" + ip + "?fields=status,message,country,regionName,city,isp,org,as,timezone,lat,lon";
            URI uri = new URI(urlString);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT);
            conn.setReadTimeout(TIMEOUT);
            conn.setRequestProperty("User-Agent", "Anibus-Scanner/1.0");
            
            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }
                in.close();
                
                parseIPApiResponse(response.toString(), geoInfo);
            }
            
            conn.disconnect();
            
        } catch (Exception e) {
            // Silently fail, return partial info
        }
        
        // Detect cloud providers
        detectCloudProvider(geoInfo);
        
        return geoInfo;
    }
    
    /**
     * Parse JSON response from ip-api.com
     */
    private static void parseIPApiResponse(String json, GeoInfo geoInfo) {
        // Simple JSON parsing without external libraries
        geoInfo.setCountry(extractJsonValue(json, "country"));
        geoInfo.setRegion(extractJsonValue(json, "regionName"));
        geoInfo.setCity(extractJsonValue(json, "city"));
        geoInfo.setIsp(extractJsonValue(json, "isp"));
        geoInfo.setOrganization(extractJsonValue(json, "org"));
        geoInfo.setAsn(extractJsonValue(json, "as"));
        geoInfo.setTimezone(extractJsonValue(json, "timezone"));
        
        String lat = extractJsonValue(json, "lat");
        String lon = extractJsonValue(json, "lon");
        
        try {
            if (lat != null) geoInfo.setLatitude(Double.parseDouble(lat));
            if (lon != null) geoInfo.setLongitude(Double.parseDouble(lon));
        } catch (NumberFormatException e) {
            // Ignore
        }
    }
    
    /**
     * Extract value from simple JSON
     */
    private static String extractJsonValue(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        // Try for numeric values
        pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*([\\d.\\-]+)");
        matcher = pattern.matcher(json);
        
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        return null;
    }
    
    /**
     * Detect major cloud providers based on ASN, ISP, or organization
     */
    private static void detectCloudProvider(GeoInfo geoInfo) {
        String checkString = (geoInfo.getIsp() + " " + geoInfo.getOrganization() + " " + geoInfo.getAsn()).toLowerCase();
        
        if (checkString.contains("amazon") || checkString.contains("aws") || checkString.contains("ec2")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Amazon Web Services (AWS)");
        } else if (checkString.contains("microsoft") || checkString.contains("azure")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Microsoft Azure");
        } else if (checkString.contains("google") || checkString.contains("gcp") || checkString.contains("cloud platform")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Google Cloud Platform (GCP)");
        } else if (checkString.contains("digitalocean")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("DigitalOcean");
        } else if (checkString.contains("linode") || checkString.contains("akamai")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Linode (Akamai)");
        } else if (checkString.contains("vultr")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Vultr");
        } else if (checkString.contains("ovh")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("OVH");
        } else if (checkString.contains("hetzner")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Hetzner");
        } else if (checkString.contains("cloudflare")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Cloudflare");
        } else if (checkString.contains("alibaba") || checkString.contains("aliyun")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Alibaba Cloud");
        } else if (checkString.contains("tencent")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Tencent Cloud");
        } else if (checkString.contains("oracle") && checkString.contains("cloud")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("Oracle Cloud");
        } else if (checkString.contains("ibm") && checkString.contains("cloud")) {
            geoInfo.setCloudProvider(true);
            geoInfo.setCloudProvider("IBM Cloud");
        }
    }
    
    /**
     * Quick check for cloud provider without full geo lookup
     */
    public static String quickCloudCheck(String ip) {
        if (isPrivateIP(ip)) {
            return "Private Network";
        }
        
        GeoInfo info = getGeoInfo(ip);
        if (info.isCloudProvider()) {
            return info.getCloudProvider();
        }
        
        return null;
    }
}
