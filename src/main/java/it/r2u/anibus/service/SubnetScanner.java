package it.r2u.anibus.service;

import java.net.*;
import java.util.Enumeration;

/**
 * Detects subnet and network information for the target host.
 */
public class SubnetScanner {

    /**
     * Detects the subnet (CIDR notation) for the given IP address.
     */
    public String detectSubnet(String targetIp) {
        try {
            InetAddress target = InetAddress.getByName(targetIp);
            
            // Find the network interface that can reach this address
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isUp() && !iface.isLoopback()) {
                    for (InterfaceAddress ifaceAddr : iface.getInterfaceAddresses()) {
                        InetAddress addr = ifaceAddr.getAddress();
                        if (addr instanceof Inet4Address && sameSubnet(addr, target, ifaceAddr.getNetworkPrefixLength())) {
                            return calculateSubnet(addr, ifaceAddr.getNetworkPrefixLength());
                        }
                    }
                }
            }
            
            // Fallback: estimate based on IP class
            return estimateSubnet(targetIp);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Attempts to detect the default gateway.
     */
    public String detectGateway(String targetIp) {
        try {
            InetAddress target = InetAddress.getByName(targetIp);
            
            // Find the network interface that can reach this address
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isUp() && !iface.isLoopback()) {
                    for (InterfaceAddress ifaceAddr : iface.getInterfaceAddresses()) {
                        InetAddress addr = ifaceAddr.getAddress();
                        if (addr instanceof Inet4Address && sameSubnet(addr, target, ifaceAddr.getNetworkPrefixLength())) {
                            // Gateway is typically .1 or .254 in the subnet
                            return estimateGateway(addr, ifaceAddr.getNetworkPrefixLength());
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    private boolean sameSubnet(InetAddress addr1, InetAddress addr2, short prefixLength) {
        byte[] ip1 = addr1.getAddress();
        byte[] ip2 = addr2.getAddress();
        
        if (ip1.length != ip2.length) return false;
        
        int bytes = prefixLength / 8;
        int bits = prefixLength % 8;
        
        // Check full bytes
        for (int i = 0; i < bytes; i++) {
            if (ip1[i] != ip2[i]) return false;
        }
        
        // Check remaining bits
        if (bits > 0 && bytes < ip1.length) {
            int mask = 0xFF << (8 - bits);
            if ((ip1[bytes] & mask) != (ip2[bytes] & mask)) return false;
        }
        
        return true;
    }

    private String calculateSubnet(InetAddress addr, short prefixLength) {
        byte[] ip = addr.getAddress();
        
        // Calculate network address
        int bytes = prefixLength / 8;
        int bits = prefixLength % 8;
        
        byte[] network = ip.clone();
        if (bits > 0 && bytes < ip.length) {
            int mask = 0xFF << (8 - bits);
            network[bytes] = (byte) (network[bytes] & mask);
            for (int i = bytes + 1; i < network.length; i++) {
                network[i] = 0;
            }
        } else {
            for (int i = bytes; i < network.length; i++) {
                network[i] = 0;
            }
        }
        
        try {
            InetAddress networkAddr = InetAddress.getByAddress(network);
            return networkAddr.getHostAddress() + "/" + prefixLength;
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private String estimateSubnet(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return null;
        
        int firstOctet = Integer.parseInt(parts[0]);
        
        // Class A: 1-126
        if (firstOctet >= 1 && firstOctet <= 126) {
            return parts[0] + ".0.0.0/8";
        }
        // Class B: 128-191
        else if (firstOctet >= 128 && firstOctet <= 191) {
            return parts[0] + "." + parts[1] + ".0.0/16";
        }
        // Class C: 192-223
        else if (firstOctet >= 192 && firstOctet <= 223) {
            return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
        }
        
        return null;
    }

    private String estimateGateway(InetAddress addr, short prefixLength) {
        byte[] ip = addr.getAddress();
        byte[] gateway = ip.clone();
        
        // Set last octet to 1 (common gateway)
        gateway[gateway.length - 1] = 1;
        
        try {
            InetAddress gatewayAddr = InetAddress.getByAddress(gateway);
            return gatewayAddr.getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
