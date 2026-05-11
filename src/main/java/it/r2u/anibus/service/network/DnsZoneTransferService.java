package it.r2u.anibus.service.network;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DNS Zone Transfer Service
 *
 * Attempts an AXFR (full zone transfer) request against common name server
 * candidates for the target domain using raw TCP/53 DNS packets.
 * A successful transfer reveals all DNS records — a critical misconfiguration.
 */
public class DnsZoneTransferService {

    public record DnsRecord(String name, String type, String value) {}

    public record ZoneTransferResult(
        String domain,
        String nameServer,
        boolean transferSucceeded,
        List<DnsRecord> records,
        String errorMessage
    ) {}

    private static final int DNS_PORT   = 53;
    private static final int TIMEOUT_MS = 6000;

    public ZoneTransferResult attemptAxfr(String domain) {
        // Try common NS hostnames first, then the domain itself
        List<String> candidates = List.of(
            "ns1." + domain, "ns2." + domain, "ns." + domain, domain
        );
        for (String ns : candidates) {
            ZoneTransferResult r = axfrFromServer(domain, ns);
            if (r.transferSucceeded()) return r;
        }
        return new ZoneTransferResult(domain, "-", false, List.of(),
            "AXFR refused or filtered on all tried name servers");
    }

    private ZoneTransferResult axfrFromServer(String domain, String nsServer) {
        try {
            InetAddress nsAddr = InetAddress.getByName(nsServer);
            byte[] query = buildAxfrQuery(domain);

            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(nsAddr, DNS_PORT), TIMEOUT_MS);
                socket.setSoTimeout(TIMEOUT_MS);

                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.writeShort(query.length); // TCP DNS prepends 2-byte length
                out.write(query);
                out.flush();

                DataInputStream in = new DataInputStream(socket.getInputStream());
                List<DnsRecord> records = new ArrayList<>();

                while (true) {
                    int msgLen;
                    try {
                        msgLen = in.readUnsignedShort();
                    } catch (EOFException e) {
                        break;
                    }
                    if (msgLen <= 0) break;
                    byte[] msg = new byte[msgLen];
                    in.readFully(msg);
                    records.addAll(parseDnsMessage(msg));
                    // SOA marks the start and end of the zone
                    long soaCount = records.stream().filter(r -> "SOA".equals(r.type())).count();
                    if (soaCount >= 2) break;
                }

                if (!records.isEmpty()) {
                    return new ZoneTransferResult(domain, nsServer, true, records, null);
                }
                return new ZoneTransferResult(domain, nsServer, false, List.of(),
                    "No records in response");
            }
        } catch (IOException | IllegalArgumentException e) {
            return new ZoneTransferResult(domain, nsServer, false, List.of(), e.getMessage());
        }
    }

    private byte[] buildAxfrQuery(String domain) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeShort(0x1234); // Transaction ID
        dos.writeShort(0x0000); // Flags: standard query, recursion desired=0
        dos.writeShort(1);      // QDCOUNT
        dos.writeShort(0);      // ANCOUNT
        dos.writeShort(0);      // NSCOUNT
        dos.writeShort(0);      // ARCOUNT
        // Encode QNAME as length-prefixed labels
        for (String label : domain.split("\\.")) {
            byte[] lb = label.getBytes(StandardCharsets.US_ASCII);
            dos.writeByte(lb.length);
            dos.write(lb);
        }
        dos.writeByte(0);    // Root label
        dos.writeShort(252); // QTYPE = AXFR
        dos.writeShort(1);   // QCLASS = IN
        return baos.toByteArray();
    }

    private List<DnsRecord> parseDnsMessage(byte[] msg) {
        List<DnsRecord> records = new ArrayList<>();
        if (msg.length < 12) return records;

        ByteBuffer buf = ByteBuffer.wrap(msg);
        buf.getShort(); // Transaction ID
        buf.getShort(); // Flags
        int qdcount = Short.toUnsignedInt(buf.getShort());
        int ancount = Short.toUnsignedInt(buf.getShort());
        int nscount = Short.toUnsignedInt(buf.getShort());
        int arcount = Short.toUnsignedInt(buf.getShort());

        for (int i = 0; i < qdcount; i++) {
            readName(buf);
            if (buf.remaining() >= 4) { buf.getShort(); buf.getShort(); }
        }

        int totalRR = ancount + nscount + arcount;
        for (int i = 0; i < totalRR; i++) {
            if (buf.remaining() < 10) break;
            String name = readName(buf);
            if (buf.remaining() < 10) break;
            int type    = Short.toUnsignedInt(buf.getShort());
            buf.getShort(); // class
            buf.getInt();   // TTL
            int rdlength = Short.toUnsignedInt(buf.getShort());
            if (buf.remaining() < rdlength) break;

            String typeName = switch (type) {
                case 1  -> "A";
                case 2  -> "NS";
                case 5  -> "CNAME";
                case 6  -> "SOA";
                case 12 -> "PTR";
                case 15 -> "MX";
                case 16 -> "TXT";
                case 28 -> "AAAA";
                case 33 -> "SRV";
                default -> "TYPE" + type;
            };
            String value = parseRdata(buf, type, rdlength);
            if (name != null && !name.isEmpty()) {
                records.add(new DnsRecord(name, typeName, value));
            }
        }
        return records;
    }

    private String parseRdata(ByteBuffer buf, int type, int rdlength) {
        int startPos = buf.position();
        try {
            return switch (type) {
                case 1 -> { // A
                    if (rdlength == 4) yield String.format("%d.%d.%d.%d",
                        Byte.toUnsignedInt(buf.get()), Byte.toUnsignedInt(buf.get()),
                        Byte.toUnsignedInt(buf.get()), Byte.toUnsignedInt(buf.get()));
                    buf.position(startPos + rdlength);
                    yield "?";
                }
                case 2, 5, 12 -> readName(buf); // NS, CNAME, PTR
                case 15 -> { buf.getShort(); yield readName(buf); } // MX: skip preference
                case 28 -> { // AAAA
                    if (rdlength == 16) {
                        StringBuilder ip6 = new StringBuilder();
                        for (int i = 0; i < 8; i++) {
                            if (i > 0) ip6.append(":");
                            ip6.append(String.format("%x", Short.toUnsignedInt(buf.getShort())));
                        }
                        yield ip6.toString();
                    }
                    buf.position(startPos + rdlength);
                    yield "?";
                }
                default -> {
                    buf.position(startPos + rdlength);
                    yield "(binary, " + rdlength + " bytes)";
                }
            };
        } catch (Exception e) {
            buf.position(Math.min(startPos + rdlength, buf.limit()));
            return "?";
        }
    }

    private String readName(ByteBuffer buf) {
        StringBuilder name = new StringBuilder();
        int savedPos = -1;
        int safety = 20;
        while (buf.hasRemaining() && safety-- > 0) {
            int len = Byte.toUnsignedInt(buf.get());
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) { // DNS pointer compression
                if (!buf.hasRemaining()) break;
                int offset = ((len & 0x3F) << 8) | Byte.toUnsignedInt(buf.get());
                if (savedPos < 0) savedPos = buf.position();
                buf.position(offset);
                continue;
            }
            if (name.length() > 0) name.append(".");
            if (buf.remaining() < len) break;
            byte[] label = new byte[len];
            buf.get(label);
            name.append(new String(label, StandardCharsets.US_ASCII));
        }
        if (savedPos >= 0) buf.position(savedPos);
        return name.toString();
    }

    public static String formatReport(ZoneTransferResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append("       DNS ZONE TRANSFER (AXFR) — ").append(result.domain()).append("\n");
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (!result.transferSucceeded()) {
            sb.append("  ✓ AXFR refused — zone transfer is protected.\n");
            if (result.errorMessage() != null) {
                sb.append("  Info: ").append(result.errorMessage()).append("\n");
            }
            return sb.toString();
        }

        sb.append(String.format("  ⚠ AXFR SUCCEEDED on %s!\n", result.nameServer()));
        sb.append(String.format("  Retrieved %d record(s):\n\n", result.records().size()));

        Map<String, List<DnsRecord>> byType = new LinkedHashMap<>();
        for (DnsRecord rec : result.records()) {
            byType.computeIfAbsent(rec.type(), k -> new ArrayList<>()).add(rec);
        }
        for (Map.Entry<String, List<DnsRecord>> entry : byType.entrySet()) {
            sb.append(String.format("  [%s]\n", entry.getKey()));
            for (DnsRecord rec : entry.getValue()) {
                sb.append(String.format("    %-45s %s\n", rec.name(), rec.value()));
            }
            sb.append("\n");
        }
        return sb.toString();
    }
}
