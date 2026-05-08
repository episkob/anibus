package it.r2u.anibus.service.core;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import it.r2u.anibus.model.PortScanResult;

/**
 * UDP port scanner with protocol-specific probes.
 * Covers DNS (53), NTP (123), SNMP (161/162), mDNS (5353),
 * TFTP (69), DHCP (67/68), Syslog (514), NetBIOS (137), QUIC (443).
 *
 * Note: UDP is connectionless — "open" is inferred from a valid response.
 * No response may mean open|filtered; ICMP port-unreachable means closed.
 */
public class UdpScannerService {

    private static final int DEFAULT_TIMEOUT_MS = 1500;

    // Minimal probes per well-known UDP port
    private static final Map<Integer, byte[]> PROBES = Map.ofEntries(
            Map.entry(53,   dnsProbe()),
            Map.entry(123,  ntpProbe()),
            Map.entry(161,  snmpProbe()),
            Map.entry(162,  snmpProbe()),
            Map.entry(5353, mdnsProbe()),
            Map.entry(69,   tftpProbe()),
            Map.entry(514,  syslogProbe()),
            Map.entry(137,  netbiosProbe()),
            Map.entry(1900, ssdpProbe())
    );

    private static final Map<Integer, String> PORT_NAMES = Map.ofEntries(
            Map.entry(53,   "DNS"),
            Map.entry(67,   "DHCP"),
            Map.entry(68,   "DHCP Client"),
            Map.entry(69,   "TFTP"),
            Map.entry(123,  "NTP"),
            Map.entry(137,  "NetBIOS-NS"),
            Map.entry(161,  "SNMP"),
            Map.entry(162,  "SNMP Trap"),
            Map.entry(514,  "Syslog"),
            Map.entry(1900, "SSDP/UPnP"),
            Map.entry(5353, "mDNS")
    );

    /** Common UDP ports to probe when the user requests a UDP scan. */
    public static final int[] DEFAULT_UDP_PORTS = {
            53, 67, 68, 69, 123, 137, 161, 162, 514, 1900, 5353
    };

    private final int timeoutMs;

    public UdpScannerService() {
        this(DEFAULT_TIMEOUT_MS);
    }

    public UdpScannerService(int timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    /**
     * Probe a range of well-known UDP ports on the given host.
     *
     * @param host target hostname or IP
     * @param ports array of ports to probe; if null uses DEFAULT_UDP_PORTS
     * @param progressCallback called with (0..1) after each port; may be null
     * @return list of PortScanResult with protocol "UDP" and state "open|filtered" or "open"
     */
    public List<PortScanResult> scan(String host, int[] ports, java.util.function.DoubleConsumer progressCallback) {
        int[] targets = (ports != null) ? ports : DEFAULT_UDP_PORTS;
        List<PortScanResult> results = new ArrayList<>();

        for (int i = 0; i < targets.length; i++) {
            int port = targets[i];
            PortScanResult r = probePort(host, port);
            if (r != null) results.add(r);

            if (progressCallback != null) {
                progressCallback.accept((double)(i + 1) / targets.length);
            }
        }
        return results;
    }

    private PortScanResult probePort(String host, int port) {
        byte[] probe = PROBES.getOrDefault(port, genericProbe());
        String serviceName = PORT_NAMES.getOrDefault(port, "unknown");

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            InetAddress addr = InetAddress.getByName(host);

            long start = System.nanoTime();
            DatagramPacket send = new DatagramPacket(probe, probe.length, addr, port);
            socket.send(send);

            byte[] buf = new byte[512];
            DatagramPacket recv = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(recv);
                long latencyMs = (System.nanoTime() - start) / 1_000_000;
                String banner = parseBanner(port, buf, recv.getLength());
                return new PortScanResult(port, serviceName, banner, "UDP",
                        latencyMs, "", "open", "UDP");
            } catch (SocketTimeoutException e) {
                // No response = open|filtered for UDP
                return new PortScanResult(port, serviceName, "", "UDP",
                        -1, "", "open|filtered", "UDP");
            }
        } catch (Exception ignored) {
            return null;
        }
    }

    // ── Banner parsers ────────────────────────────────────────────────────

    private String parseBanner(int port, byte[] data, int len) {
        if (len == 0) return "";
        return switch (port) {
            case 53   -> parseDnsResponse(data, len);
            case 123  -> parseNtpResponse(data, len);
            case 161  -> "SNMP response (" + len + " bytes)";
            case 5353 -> "mDNS response (" + len + " bytes)";
            default   -> "Response: " + len + " bytes";
        };
    }

    private String parseDnsResponse(byte[] data, int len) {
        if (len < 4) return "DNS response";
        int flags = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        int rcode = flags & 0x0F;
        String rcodeStr = switch (rcode) {
            case 0 -> "NOERROR";
            case 1 -> "FORMERR";
            case 2 -> "SERVFAIL";
            case 3 -> "NXDOMAIN";
            case 5 -> "REFUSED";
            default -> "rcode=" + rcode;
        };
        return "DNS server, " + rcodeStr;
    }

    private String parseNtpResponse(byte[] data, int len) {
        if (len < 4) return "NTP response";
        int stratum = data[1] & 0xFF;
        int version = (data[0] >> 3) & 0x07;
        return "NTPv" + version + ", stratum=" + stratum;
    }

    // ── Probe builders ────────────────────────────────────────────────────

    /** Minimal DNS query for "version.bind" TXT IN */
    private static byte[] dnsProbe() {
        return new byte[]{
                0x00, 0x01, // Transaction ID
                0x01, 0x00, // Flags: standard query, recursion desired
                0x00, 0x01, // Questions: 1
                0x00, 0x00, // Answer RRs: 0
                0x00, 0x00, // Authority RRs: 0
                0x00, 0x00, // Additional RRs: 0
                // QNAME: version.bind
                0x07, 'v','e','r','s','i','o','n',
                0x04, 'b','i','n','d',
                0x00,       // end of QNAME
                0x00, 0x10, // QTYPE: TXT
                0x00, 0x03  // QCLASS: CH
        };
    }

    /** NTP client request (version 3, mode 3) */
    private static byte[] ntpProbe() {
        byte[] buf = new byte[48];
        buf[0] = 0x1B; // LI=0, VN=3, Mode=3
        return buf;
    }

    /** SNMPv1 GetRequest for sysDescr OID */
    private static byte[] snmpProbe() {
        return new byte[]{
                0x30, 0x26,             // SEQUENCE
                0x02, 0x01, 0x00,       // INTEGER version=0 (SNMPv1)
                0x04, 0x06, 'p','u','b','l','i','c', // OCTET STRING community="public"
                (byte)0xa0, 0x19,       // GetRequest PDU
                0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // RequestID
                0x02, 0x01, 0x00,       // error-status
                0x02, 0x01, 0x00,       // error-index
                0x30, 0x0b,             // VarBindList
                0x30, 0x09,             // VarBind
                0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1
                0x05, 0x00              // NULL
        };
    }

    /** mDNS query for _services._dns-sd._udp.local PTR */
    private static byte[] mdnsProbe() {
        return new byte[]{
                0x00, 0x00, // ID = 0 (mDNS)
                0x00, 0x00, // Flags: standard query
                0x00, 0x01, // Questions: 1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x09, '_','s','e','r','v','i','c','e','s',
                0x07, '_','d','n','s','-','s','d',
                0x04, '_','u','d','p',
                0x05, 'l','o','c','a','l',
                0x00,
                0x00, 0x0c, // PTR
                0x00, 0x01  // IN
        };
    }

    /** Minimal TFTP Read Request for "test" in octet mode */
    private static byte[] tftpProbe() {
        return new byte[]{
                0x00, 0x01,                         // Opcode: RRQ
                't','e','s','t', 0x00,               // filename
                'o','c','t','e','t', 0x00            // mode
        };
    }

    /** Minimal BSD syslog UDP message */
    private static byte[] syslogProbe() {
        byte[] msg = "<14>1 - - - - - - Anibus probe".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return msg;
    }

    /** NetBIOS Name Service node status request */
    private static byte[] netbiosProbe() {
        return new byte[]{
                0x00, 0x01, // Transaction ID
                0x00, 0x00, // Flags: query
                0x00, 0x01, // Questions: 1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20,       // Name length (32)
                'C','K','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
                'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A',
                0x00,
                0x00, 0x21, // NBSTAT
                0x00, 0x01  // IN
        };
    }

    /** SSDP M-SEARCH for UPnP discovery */
    private static byte[] ssdpProbe() {
        // \r before each newline → CRLF (required by HTTP/SSDP protocol)
        String msg = """
                M-SEARCH * HTTP/1.1\r
                HOST: 239.255.255.250:1900\r
                MAN: "ssdp:discover"\r
                MX: 1\r
                ST: ssdp:all\r
                \r
                """;
        return msg.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static byte[] genericProbe() {
        return new byte[]{0x00};
    }
}
