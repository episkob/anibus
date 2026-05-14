package it.r2u.anibus.service.detection;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deep protocol-specific probing for authentic service identification.
 * <p>
 * Each probe opens a fresh TCP (or UDP) connection and performs the actual protocol
 * handshake — not just a banner read. This extracts data that cannot be trivially
 * spoofed without implementing the full protocol: SSH key-exchange algorithm lists,
 * Redis INFO output, MongoDB wire-protocol greeting, SMTP extension set, FTP FEAT
 * list + anonymous login check, DNS version.bind, VNC protocol version, Memcached
 * stats, LDAP rootDSE, SMB dialect negotiation, and RDP security negotiation.
 */
public final class DeepServiceProber {

    private static final Logger LOG = Logger.getLogger(DeepServiceProber.class.getName());
    private static final int TIMEOUT_MS = 3000;

    private DeepServiceProber() { }

    // -------------------------------------------------------------------------
    // Public result type
    // -------------------------------------------------------------------------

    /**
     * Result of a single deep probe session.
     *
     * @param protocol detected protocol name (e.g. "SSH 2.0", "Redis", "SMB")
     * @param version  detected version string, or {@code null} if not found
     * @param details  pre-formatted multi-line text (attributes, capabilities, warnings)
     */
    public record ProbeResult(String protocol, String version, String details) {
        /** Returns pre-formatted detail text for inclusion in the scan banner. */
        public String format() { return details != null ? details : ""; }
    }

    // -------------------------------------------------------------------------
    // Dispatch
    // -------------------------------------------------------------------------

    /**
     * Selects and runs the appropriate deep probe for the given port / banner.
     * Returns {@code null} if no specific probe is available or if the probe fails.
     */
    public static ProbeResult probe(String host, int port, String existingBanner) {
        if (isSsh(port, existingBanner))      return probeSsh(host, port);
        if (isRedis(port, existingBanner))     return probeRedis(host, port);
        if (isMongo(port))                     return probeMongo(host, port);
        if (isSmtp(port, existingBanner))      return probeSmtp(host, port);
        if (isFtp(port, existingBanner))       return probeFtp(host, port);
        if (isDns(port))                       return probeDns(host, port);
        if (isVnc(port, existingBanner))       return probeVnc(host, port);
        if (isMemcached(port))                 return probeMemcached(host, port);
        if (isLdap(port))                      return probeLdap(host, port);
        if (isSmb(port))                       return probeSmb(host, port);
        if (isRdp(port))                       return probeRdp(host, port);
        return null;
    }

    // -------------------------------------------------------------------------
    // SSH — parse SSH_MSG_KEXINIT to extract algorithm lists
    // -------------------------------------------------------------------------

    private static ProbeResult probeSsh(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            // 1. Read server identification line byte-by-byte to avoid
            //    BufferedReader consuming bytes that belong to the binary KEXINIT.
            String ident = readLineRaw(in);

            // 2. Send our client identification.
            out.write("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
                    .getBytes(StandardCharsets.UTF_8));
            out.flush();

            // 3. Read the first SSH binary packet: SSH_MSG_KEXINIT (type 20).
            //    Packet format: uint32 packet_length | byte padding_length | payload | padding
            byte[] lenBuf = new byte[4];
            readFully(in, lenBuf);
            int pktLen = ByteBuffer.wrap(lenBuf).getInt(); // big-endian
            if (pktLen < 2 || pktLen > 65_536) {
                return simpleResult("SSH", ident);
            }
            byte[] payload = new byte[pktLen];
            readFully(in, payload);

            // payload[0] = padding_length, payload[1] = message type
            if ((payload[1] & 0xFF) != 20) {
                return simpleResult("SSH", ident); // not KEXINIT
            }

            // 4. Parse KEXINIT body.
            //    After padding_length(1) + msg_type(1) + 16-byte cookie → offset 18
            int offset = 18;
            String[] algNames = {
                "kex_algorithms", "server_host_key_algorithms",
                "encryption_c2s", "encryption_s2c",
                "mac_c2s", "mac_s2c",
                "compression_c2s", "compression_s2c"
            };
            Map<String, String> attrs = new LinkedHashMap<>();
            List<String> warnings  = new ArrayList<>();

            if (ident != null) attrs.put("Banner", ident);

            for (String name : algNames) {
                if (offset + 4 > payload.length) break;
                int strLen = ByteBuffer.wrap(payload, offset, 4).getInt();
                offset += 4;
                if (strLen < 0 || offset + strLen > payload.length) break;
                String algList = new String(payload, offset, strLen, StandardCharsets.UTF_8);
                offset += strLen;
                attrs.put(name, algList);

                // Security checks per algorithm category
                if ("kex_algorithms".equals(name)) {
                    if (algList.contains("diffie-hellman-group1-sha1")) {
                        warnings.add("[CRITICAL] Weak KEX: diffie-hellman-group1-sha1"
                                + " (Logjam / CVE-2002-20001)");
                    }
                    if (algList.contains("diffie-hellman-group14-sha1")) {
                        warnings.add("[HIGH] Weak KEX: diffie-hellman-group14-sha1"
                                + " (SHA-1 considered deprecated)");
                    }
                }
                if (name.startsWith("encryption_") && algList.contains("arcfour")) {
                    warnings.add("[CRITICAL] Weak cipher offered: RC4 (arcfour)");
                }
                if (name.startsWith("encryption_") && algList.contains("3des-cbc")) {
                    warnings.add("[HIGH] Weak cipher offered: 3DES-CBC");
                }
                if (name.startsWith("mac_") && algList.contains("-96")) {
                    warnings.add("[HIGH] Weak MAC: truncated HMAC-96 variant offered");
                }
            }

            // 5. Anti-spoof: cross-validate banner version vs. offered algorithms
            if (ident != null) {
                validateSshVersionVsAlgorithms(ident,
                        attrs.getOrDefault("kex_algorithms", ""),
                        attrs.getOrDefault("server_host_key_algorithms", ""),
                        warnings);
            }

            String version = extractSshVersion(ident);
            return new ProbeResult("SSH 2.0", version, buildDetails(attrs, List.of(), warnings));

        } catch (IOException e) {
            LOG.fine(() -> "SSH probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    private static void validateSshVersionVsAlgorithms(
            String banner, String kex, String hostKeys, List<String> warnings) {

        // OpenSSH algorithm timeline:
        //  6.5 (2014-01) — Ed25519, curve25519-sha256, chacha20-poly1305
        //  7.2 (2016-02) — rsa-sha2-256 / rsa-sha2-512
        //  9.0 (2022-04) — sntrup761x25519 (post-quantum)

        Matcher m = Pattern.compile("OpenSSH[_-](\\d+)\\.(\\d+)").matcher(banner);
        if (!m.find()) return;

        int major = Integer.parseInt(m.group(1));
        int minor = Integer.parseInt(m.group(2));
        String claimed = major + "." + minor;

        boolean before65 = major < 6 || (major == 6 && minor < 5);
        boolean before72 = major < 7 || (major == 7 && minor < 2);
        boolean before90 = major < 9;

        if (before65) {
            if (hostKeys.contains("ssh-ed25519")) {
                warnings.add("[ANTI-SPOOF] Banner claims OpenSSH " + claimed
                        + " but Ed25519 host key requires >= 6.5");
            }
            if (kex.contains("curve25519")) {
                warnings.add("[ANTI-SPOOF] Banner claims OpenSSH " + claimed
                        + " but curve25519 KEX requires >= 6.5");
            }
            if (kex.contains("chacha20-poly1305")) {
                warnings.add("[ANTI-SPOOF] Banner claims OpenSSH " + claimed
                        + " but chacha20-poly1305 requires >= 6.5");
            }
        }
        if (before72 && kex.contains("rsa-sha2-256")) {
            warnings.add("[ANTI-SPOOF] Banner claims OpenSSH " + claimed
                    + " but rsa-sha2-256 requires >= 7.2");
        }
        if (before90 && kex.contains("sntrup761")) {
            warnings.add("[ANTI-SPOOF] Banner claims OpenSSH " + claimed
                    + " but post-quantum sntrup761 requires >= 9.0"
                    + " — real version is likely >= 9.0");
        }
    }

    private static String extractSshVersion(String banner) {
        if (banner == null) return null;
        Matcher m = Pattern.compile("OpenSSH[_-](\\S+)").matcher(banner);
        return m.find() ? "OpenSSH " + m.group(1) : null;
    }

    // -------------------------------------------------------------------------
    // Redis — PING + INFO server + DEBUG capability check
    // -------------------------------------------------------------------------

    private static ProbeResult probeRedis(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            // RESP PING
            out.write("*1\r\n$4\r\nPING\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            String pong = readLineRaw(in);
            if (pong == null || !pong.startsWith("+")) return null;

            // RESP INFO server
            out.write("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        warnings = new ArrayList<>();
            String version = null;

            String header = readLineRaw(in);
            if (header != null && header.startsWith("$")) {
                int len = Integer.parseInt(header.substring(1).trim());
                byte[] data = new byte[len];
                readFully(in, data);
                String info = new String(data, StandardCharsets.UTF_8);
                for (String line : info.split("\r\n")) {
                    if (line.startsWith("#") || line.isBlank()) continue;
                    String[] parts = line.split(":", 2);
                    if (parts.length != 2) continue;
                    String k = parts[0].trim();
                    String v = parts[1].trim();
                    switch (k) {
                        case "redis_version"   -> { version = "Redis " + v; attrs.put("Version", v); }
                        case "os"              -> attrs.put("OS", v);
                        case "redis_mode"      -> attrs.put("Mode", v);
                        case "role"            -> attrs.put("Role", v);
                        case "config_file"     -> attrs.put("Config",
                                                    v.isEmpty() ? "(no config file — defaults)" : v);
                        case "maxmemory"       -> {
                            if ("0".equals(v)) warnings.add("[HIGH] maxmemory=0 — unlimited (OOM risk)");
                        }
                        default -> { /* ignore unneeded fields */ }
                    }
                }
            }

            // RESP PING succeeded without any AUTH → unauthenticated access
            warnings.add("[CRITICAL] Redis accessible without authentication"
                    + " — full data read/write possible");

            // Check whether DEBUG command is available (enables RCE via RELOAD/SLEEP/JMAP)
            out.write("*1\r\n$5\r\nDEBUG\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            String dbgResp = readLineRaw(in);
            if (dbgResp != null && !dbgResp.startsWith("-ERR unknown command")
                    && !dbgResp.startsWith("-ERR wrong")) {
                warnings.add("[CRITICAL] DEBUG command enabled — RCE via DEBUG RELOAD/SLEEP/JMAP");
            }

            return new ProbeResult("Redis", version, buildDetails(attrs, List.of(), warnings));
        } catch (IOException e) {
            LOG.fine(() -> "Redis probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // MongoDB — wire-protocol isMaster / hello
    // -------------------------------------------------------------------------

    private static ProbeResult probeMongo(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            out.write(buildMongoIsMasterQuery());
            out.flush();

            // Read full response packet: first 4 bytes = total message length
            byte[] lenBuf = new byte[4];
            readFully(in, lenBuf);
            int totalLen = ByteBuffer.wrap(lenBuf).order(ByteOrder.LITTLE_ENDIAN).getInt();
            if (totalLen < 16 || totalLen > 65_536) return null;

            byte[] rest = new byte[totalLen - 4];
            readFully(in, rest);

            // OP_REPLY body starts after:
            //   requestID(4) + responseTo(4) + opCode(4) = 12 bytes of header after length
            //   responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) = 20 bytes
            // BSON document starts at offset 12 + 20 = 32 (in `rest` array at index 32)
            if (rest.length < 32) return null;
            byte[] bson = Arrays.copyOfRange(rest, 32, rest.length);

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        warnings = new ArrayList<>();

            extractBsonString(bson, "version", attrs);
            extractBsonString(bson, "setName", attrs);
            extractBsonString(bson, "me", attrs);

            warnings.add("[CRITICAL] MongoDB accessible without authentication"
                    + " — check bindIp is not 0.0.0.0");

            String version = attrs.containsKey("version") ? "MongoDB " + attrs.get("version") : null;
            return new ProbeResult("MongoDB", version, buildDetails(attrs, List.of(), warnings));

        } catch (IOException e) {
            LOG.fine(() -> "MongoDB probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    private static byte[] buildMongoIsMasterQuery() {
        // BSON document: {isMaster: 1}
        byte[] key      = "isMaster\0".getBytes(StandardCharsets.UTF_8);
        int    bsonLen  = 4 + 1 + key.length + 4 + 1; // length + type + key + int32 + terminator
        ByteBuffer bson = ByteBuffer.allocate(bsonLen).order(ByteOrder.LITTLE_ENDIAN);
        bson.putInt(bsonLen);
        bson.put((byte) 0x10); // int32 type
        bson.put(key);
        bson.putInt(1);
        bson.put((byte) 0x00); // document terminator
        byte[] bsonDoc = bson.array();

        // OP_QUERY message
        byte[] colName = "admin.$cmd\0".getBytes(StandardCharsets.UTF_8);
        int    msgLen  = 16 + 4 + colName.length + 4 + 4 + bsonDoc.length;
        ByteBuffer msg = ByteBuffer.allocate(msgLen).order(ByteOrder.LITTLE_ENDIAN);
        msg.putInt(msgLen); // total length
        msg.putInt(1);      // requestId
        msg.putInt(0);      // responseTo
        msg.putInt(2004);   // opCode: OP_QUERY
        msg.putInt(0);      // flags
        msg.put(colName);
        msg.putInt(0);      // numberToSkip
        msg.putInt(1);      // numberToReturn
        msg.put(bsonDoc);
        return msg.array();
    }

    /**
     * Locates a BSON string field by type byte (0x02) + key name and extracts its value.
     * Works on the raw BSON bytes of a document.
     */
    private static void extractBsonString(byte[] bson, String key, Map<String, String> attrs) {
        byte[] keyBytes = (key + "\0").getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < bson.length - keyBytes.length - 5; i++) {
            if (bson[i] != 0x02) continue; // not a string type
            boolean match = true;
            for (int j = 0; j < keyBytes.length; j++) {
                if (i + 1 + j >= bson.length || bson[i + 1 + j] != keyBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (!match) continue;
            int lenOffset = i + 1 + keyBytes.length;
            if (lenOffset + 4 > bson.length) return;
            int strLen = ByteBuffer.wrap(bson, lenOffset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int strStart = lenOffset + 4;
            if (strLen <= 0 || strStart >= bson.length) return;
            int actualLen = Math.min(strLen - 1, bson.length - strStart);
            if (actualLen <= 0) return;
            String val = new String(bson, strStart, actualLen, StandardCharsets.UTF_8).trim();
            if (!val.isBlank()) attrs.put(key, val);
            return;
        }
    }

    // -------------------------------------------------------------------------
    // SMTP — EHLO extension list + open-relay check
    // -------------------------------------------------------------------------

    private static ProbeResult probeSmtp(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            String greeting = readSmtpMultiline(in);

            out.write("EHLO probe.anibus.local\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            String ehloResp = readSmtpMultiline(in);

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        caps     = new ArrayList<>();
            List<String>        warnings = new ArrayList<>();

            if (greeting != null && !greeting.isBlank()) {
                attrs.put("Greeting", greeting.lines().findFirst().orElse("").trim());
            }

            if (ehloResp != null) {
                for (String line : ehloResp.split("\n")) {
                    line = line.trim();
                    if (line.length() < 4) continue;
                    String ext = line.substring(4).trim();
                    if (!ext.isEmpty() && !ext.equalsIgnoreCase("OK")) {
                        caps.add(ext);
                        String extLower = ext.toLowerCase();
                        if (extLower.startsWith("vrfy")) {
                            warnings.add("[HIGH] VRFY enabled — user enumeration risk");
                        }
                        if (extLower.startsWith("expn")) {
                            warnings.add("[HIGH] EXPN enabled — mailing list enumeration");
                        }
                    }
                }
            }

            // Open relay check: attempt MAIL FROM + RCPT TO without authentication
            out.write("MAIL FROM:<probe@anibus.local>\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            String mailResp = readLineRaw(in);
            if (mailResp != null && mailResp.startsWith("250")) {
                out.write("RCPT TO:<check@gmail.com>\r\n".getBytes(StandardCharsets.UTF_8));
                out.flush();
                String rcptResp = readLineRaw(in);
                if (rcptResp != null && rcptResp.startsWith("250")) {
                    warnings.add("[CRITICAL] Open SMTP relay — external delivery accepted"
                            + " without authentication");
                }
                out.write("RSET\r\n".getBytes(StandardCharsets.UTF_8));
                out.flush();
                readLineRaw(in); // consume RSET response
            }

            out.write("QUIT\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            // Extract server software from greeting
            String version = null;
            if (greeting != null) {
                Matcher m = Pattern.compile(
                        "(Postfix|Exim|Sendmail|MailEnable|hMailServer|Microsoft ESMTP|Dovecot)"
                        + "[\\s/]*(\\S*)",
                        Pattern.CASE_INSENSITIVE).matcher(greeting);
                if (m.find()) {
                    version = m.group(1) + (m.group(2).isEmpty() ? "" : " " + m.group(2));
                }
            }

            return new ProbeResult("SMTP", version, buildDetails(attrs, caps, warnings));
        } catch (IOException e) {
            LOG.fine(() -> "SMTP probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // FTP — FEAT list + anonymous login check
    // -------------------------------------------------------------------------

    private static ProbeResult probeFtp(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            String banner = readLineRaw(in);

            out.write("FEAT\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        caps     = new ArrayList<>();
            List<String>        warnings = new ArrayList<>();

            if (banner != null) attrs.put("Banner", banner);

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("211 ") || line.startsWith("500 ") || line.startsWith("502 ")) {
                    break;
                }
                if (line.startsWith("211-") || line.startsWith(" ")) {
                    String feat = line.replaceFirst("^211-?\\s*", "").trim();
                    if (!feat.isEmpty() && !feat.equalsIgnoreCase("Features:")) {
                        caps.add(feat);
                    }
                }
            }

            // Anonymous login attempt
            out.write("USER anonymous\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            String userResp = readLineRaw(in);
            if (userResp != null && (userResp.startsWith("230") || userResp.startsWith("331"))) {
                if (userResp.startsWith("331")) {
                    out.write("PASS anonymous@anibus.local\r\n".getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    String passResp = readLineRaw(in);
                    if (passResp != null && passResp.startsWith("230")) {
                        warnings.add("[CRITICAL] Anonymous FTP login allowed"
                                + " — full unauthenticated file access");
                    }
                } else {
                    warnings.add("[CRITICAL] Anonymous FTP login allowed without password");
                }
            }

            out.write("QUIT\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            // Extract server software
            String version = null;
            if (banner != null) {
                Matcher m = Pattern.compile(
                        "(vsftpd|ProFTPD|FileZilla|Pure-FTPd|Microsoft FTP|wu-ftpd)[\\s/]*(\\S*)",
                        Pattern.CASE_INSENSITIVE).matcher(banner);
                if (m.find()) {
                    version = m.group(1) + (m.group(2).isEmpty() ? "" : " " + m.group(2));
                }
            }

            return new ProbeResult("FTP", version, buildDetails(attrs, caps, warnings));
        } catch (IOException e) {
            LOG.fine(() -> "FTP probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // DNS — version.bind TXT CHAOS query (UDP)
    // -------------------------------------------------------------------------

    private static ProbeResult probeDns(String host, int port) {
        try (DatagramSocket ds = new DatagramSocket()) {
            ds.setSoTimeout(2000);
            byte[]      query  = buildDnsVersionQuery();
            InetAddress addr   = InetAddress.getByName(host);
            ds.send(new DatagramPacket(query, query.length, addr, port));

            byte[]         respBuf = new byte[512];
            DatagramPacket respPkt = new DatagramPacket(respBuf, respBuf.length);
            ds.receive(respPkt);

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        warnings = new ArrayList<>();

            String version = parseDnsTxtAnswer(respBuf, respPkt.getLength());
            if (version != null) {
                attrs.put("version.bind", version);
                warnings.add("[INFO] DNS server version disclosure: " + version
                        + " — consider: version \"none\";");
            } else {
                attrs.put("version.bind", "(hidden — version disclosure disabled)");
            }

            return new ProbeResult("DNS", version, buildDetails(attrs, List.of(), warnings));
        } catch (IOException e) {
            LOG.fine(() -> "DNS probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    private static byte[] buildDnsVersionQuery() {
        // version.bind.  TXT  CH
        byte[] qname = {7,'v','e','r','s','i','o','n', 4,'b','i','n','d', 0};
        ByteBuffer buf = ByteBuffer.allocate(12 + qname.length + 4);
        buf.putShort((short) 0x1234); // transaction ID
        buf.putShort((short) 0x0100); // flags: standard query + recursion desired
        buf.putShort((short) 1);      // QDCOUNT
        buf.putShort((short) 0);      // ANCOUNT
        buf.putShort((short) 0);      // NSCOUNT
        buf.putShort((short) 0);      // ARCOUNT
        buf.put(qname);
        buf.putShort((short) 16);     // QTYPE: TXT
        buf.putShort((short) 3);      // QCLASS: CHAOS (CH)
        return buf.array();
    }

    private static String parseDnsTxtAnswer(byte[] resp, int len) {
        if (len < 12) return null;
        int ancount = ((resp[6] & 0xFF) << 8) | (resp[7] & 0xFF);
        if (ancount == 0) return null;

        // Skip header (12 bytes) + QNAME + QTYPE(2) + QCLASS(2)
        int offset = 12;
        while (offset < len && resp[offset] != 0) offset++; // skip QNAME labels
        offset += 5; // null terminator + QTYPE(2) + QCLASS(2)

        if (offset + 10 >= len) return null;

        // Skip NAME in answer (pointer or label)
        if ((resp[offset] & 0xC0) == 0xC0) {
            offset += 2;
        } else {
            while (offset < len && resp[offset] != 0) offset++;
            offset++;
        }
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
        if (offset + 10 > len) return null;
        int rdLen = ((resp[offset + 8] & 0xFF) << 8) | (resp[offset + 9] & 0xFF);
        offset += 10;

        // TXT rdata: 1-byte text-string length + text — validate rdata bounds first
        if (rdLen < 1 || offset + rdLen > len) return null;
        int txtLen = resp[offset] & 0xFF;
        offset++;
        if (offset + txtLen > len) return null;
        return new String(resp, offset, txtLen, StandardCharsets.UTF_8);
    }

    // -------------------------------------------------------------------------
    // VNC — read RFB protocol version
    // -------------------------------------------------------------------------

    private static ProbeResult probeVnc(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in = s.getInputStream();

            // VNC server sends "RFB 003.008\n" (12 bytes) first
            byte[] buf = new byte[12];
            readFully(in, buf);
            String proto = new String(buf, StandardCharsets.UTF_8).trim();

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        warnings = new ArrayList<>();
            attrs.put("Protocol", proto);

            String version = null;
            Matcher m = Pattern.compile("RFB (\\d+)\\.(\\d+)").matcher(proto);
            if (m.find()) {
                version = "VNC RFB " + m.group(1) + "." + m.group(2);
                int minor = Integer.parseInt(m.group(2));
                if (minor < 7) {
                    warnings.add("[HIGH] RFB version < 007 — no authentication support");
                }
            }
            warnings.add("[HIGH] VNC exposed — may allow unauthenticated remote desktop access");

            return new ProbeResult("VNC", version, buildDetails(attrs, List.of(), warnings));
        } catch (IOException e) {
            LOG.fine(() -> "VNC probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Memcached — stats command
    // -------------------------------------------------------------------------

    private static ProbeResult probeMemcached(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            out.write("stats\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        warnings = new ArrayList<>();
            String version = null;

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null && !line.equals("END")) {
                if (!line.startsWith("STAT ")) continue;
                String[] parts = line.split("\\s+", 3);
                if (parts.length != 3) continue;
                switch (parts[1]) {
                    case "version"       -> { version = "Memcached " + parts[2];
                                              attrs.put("Version", parts[2]); }
                    case "pid"           -> attrs.put("PID", parts[2]);
                    case "uptime"        -> attrs.put("Uptime (s)", parts[2]);
                    case "curr_items"    -> attrs.put("Items", parts[2]);
                    case "bytes"         -> attrs.put("Memory used (bytes)", parts[2]);
                    case "limit_maxbytes"-> attrs.put("Max memory (bytes)", parts[2]);
                    default              -> { /* ignore */ }
                }
            }

            warnings.add("[CRITICAL] Memcached accessible without authentication"
                    + " — data theft and DRDoS amplification risk");

            return new ProbeResult("Memcached", version, buildDetails(attrs, List.of(), warnings));
        } catch (IOException e) {
            LOG.fine(() -> "Memcached probe for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // LDAP — anonymous bind + rootDSE search
    // -------------------------------------------------------------------------

    private static ProbeResult probeLdap(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            // Anonymous LDAP bind request (BER/ASN.1)
            byte[] bindReq = {
                0x30, 0x0c,               // LDAPMessage SEQUENCE, length 12
                0x02, 0x01, 0x01,         // messageID INTEGER 1
                0x60, 0x07,               // BindRequest [APPLICATION 0], length 7
                0x02, 0x01, 0x03,         // version INTEGER 3
                0x04, 0x00,               // name OCTET STRING ""
                (byte) 0x80, 0x00         // simple [0] ""
            };
            out.write(bindReq);
            out.flush();

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        warnings = new ArrayList<>();

            byte[] bindResp = new byte[256];
            int read = in.read(bindResp);
            if (read > 0) {
                // Look for resultCode ENUMERATED 0 (success) = 0x0a 0x01 0x00
                for (int i = 0; i < read - 3; i++) {
                    if ((bindResp[i] & 0xFF) == 0x0a
                            && (bindResp[i + 1] & 0xFF) == 0x01
                            && (bindResp[i + 2] & 0xFF) == 0x00) {
                        warnings.add("[HIGH] Anonymous LDAP bind allowed"
                                + " — directory enumeration possible");
                        break;
                    }
                }
            }

            // rootDSE search (base scope, filter: objectClass=*)
            out.write(buildLdapRootDseSearch());
            out.flush();

            byte[] searchResp = new byte[4096];
            int sRead = in.read(searchResp);
            if (sRead > 0) {
                String raw = new String(searchResp, 0, sRead, StandardCharsets.ISO_8859_1);
                extractLdapAttr(raw, "vendorName",           attrs);
                extractLdapAttr(raw, "vendorVersion",        attrs);
                extractLdapAttr(raw, "namingContexts",       attrs);
                extractLdapAttr(raw, "dnsHostName",          attrs);
            }

            String version = attrs.get("vendorVersion");
            return new ProbeResult("LDAP", version, buildDetails(attrs, List.of(), warnings));
        } catch (IOException e) {
            LOG.fine(() -> "LDAP probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    private static byte[] buildLdapRootDseSearch() {
        // SearchRequest: baseObject="", scope=base(0), derefAliases=never(0),
        //   sizeLimit=0, timeLimit=0, typesOnly=false, filter=present(objectClass),
        //   attributes=all
        return new byte[]{
            0x30, 0x25,                   // LDAPMessage SEQUENCE
            0x02, 0x01, 0x02,             // messageID INTEGER 2
            0x63, 0x20,                   // SearchRequest [APPLICATION 3], length 32
            0x04, 0x00,                   // baseObject OCTET STRING ""
            0x0a, 0x01, 0x00,             // scope ENUMERATED base(0)
            0x0a, 0x01, 0x00,             // derefAliases ENUMERATED never(0)
            0x02, 0x01, 0x00,             // sizeLimit INTEGER 0
            0x02, 0x01, 0x00,             // timeLimit INTEGER 0
            0x01, 0x01, 0x00,             // typesOnly BOOLEAN false
            (byte) 0x87, 0x0b,            // filter present [7], length 11
            'o','b','j','e','c','t','C','l','a','s','s', // "objectClass"
            0x30, 0x00                    // attributes SEQUENCE {} (all)
        };
    }

    private static void extractLdapAttr(String raw, String attrName, Map<String, String> attrs) {
        int idx = raw.indexOf(attrName);
        if (idx < 0) return;
        int start = idx + attrName.length();
        // Skip non-printable BER bytes to reach the value
        while (start < raw.length() && !Character.isLetterOrDigit(raw.charAt(start))) start++;
        int end = start;
        while (end < raw.length() && raw.charAt(end) >= 0x20 && raw.charAt(end) < 0x7F) end++;
        if (end > start) attrs.put(attrName, raw.substring(start, end));
    }

    // -------------------------------------------------------------------------
    // SMB — negotiate protocol, detect SMBv1 (EternalBlue risk)
    // -------------------------------------------------------------------------

    private static ProbeResult probeSmb(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            out.write(buildSmbNegotiateRequest());
            out.flush();

            byte[] resp = new byte[512];
            int read = in.read(resp);

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        warnings = new ArrayList<>();
            String version = null;

            if (read > 8) {
                // NetBIOS header is 4 bytes; SMB magic starts at offset 4
                if (read > 7
                        && resp[4] == (byte) 0xFF
                        && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B') {
                    attrs.put("Protocol", "SMBv1");
                    warnings.add("[CRITICAL] SMBv1 is enabled — EternalBlue (CVE-2017-0143/0144/0145"
                            + "/0146/0147/0148) / WannaCry risk — disable immediately");

                } else if (read > 7
                        && resp[4] == (byte) 0xFE
                        && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B') {
                    // SMBv2 Negotiate Response — DialectRevision at offset 68+2=70
                    // (64-byte SMB2 header + 2-byte StructureSize, then dialect at +2)
                    if (read > 71) {
                        int dialect = ((resp[71] & 0xFF) << 8) | (resp[70] & 0xFF);
                        attrs.put("Protocol", "SMBv2/3");
                        version = switch (dialect) {
                            case 0x0202 -> "SMB 2.0.2";
                            case 0x0210 -> "SMB 2.1";
                            case 0x0300 -> "SMB 3.0";
                            case 0x0302 -> "SMB 3.0.2";
                            case 0x0311 -> "SMB 3.1.1";
                            default     -> String.format("SMB dialect 0x%04X", dialect);
                        };
                        attrs.put("Dialect", version);
                    } else {
                        attrs.put("Protocol", "SMBv2/3");
                    }
                }
            }

            return new ProbeResult("SMB", version, buildDetails(attrs, List.of(), warnings));
        } catch (IOException e) {
            LOG.fine(() -> "SMB probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    private static byte[] buildSmbNegotiateRequest() {
        // NetBIOS session message (4 bytes) + SMBv1 Negotiate Protocol Request
        byte[] dialect = {0x02, 'N','T',' ','L','M',' ','0','.','1','2', 0x00};
        // WordCount=0, ByteCount=len(dialect), dialect list
        int msgBodyLen = 32 + 1 + 2 + dialect.length; // SMB header(32) + WordCount(1) + ByteCount(2) + dialects
        ByteBuffer buf = ByteBuffer.allocate(4 + msgBodyLen);

        // NetBIOS session message header: type=0x00, length (3 bytes big-endian)
        buf.put((byte) 0x00);
        buf.put((byte) ((msgBodyLen >> 16) & 0xFF));
        buf.put((byte) ((msgBodyLen >> 8)  & 0xFF));
        buf.put((byte)  (msgBodyLen        & 0xFF));

        // SMB1 header (32 bytes)
        buf.put(new byte[]{(byte)0xFF,'S','M','B'}); // magic
        buf.put((byte) 0x72);                         // command: Negotiate
        buf.putInt(0);                                 // status
        buf.put((byte) 0x18);                          // flags
        buf.putShort((short) 0x0128);                  // flags2 (unicode + extended security)
        buf.putShort((short) 0);                       // PIDHigh
        buf.putLong(0L);                               // security features (8 bytes)
        buf.putShort((short) 0);                       // reserved
        buf.putShort((short) 0xFFFF);                  // TID
        buf.putShort((short) 0xFFFE);                  // PID
        buf.putShort((short) 0);                       // UID
        buf.putShort((short) 0);                       // MID

        // Parameters + data
        buf.put((byte) 0);                             // WordCount = 0
        buf.putShort((short) dialect.length);          // ByteCount (little-endian — ByteBuffer default is big-endian here)
        buf.put(dialect);

        // Fix ByteCount endianness: ByteBuffer is big-endian by default;
        // SMB integers are little-endian. The simplest fix: rewrite the two ByteCount bytes.
        byte[] arr = buf.array();
        int byteCountOffset = 4 + 32 + 1; // NetBIOS(4) + SMBheader(32) + WordCount(1)
        short bc = (short) dialect.length;
        arr[byteCountOffset]     = (byte)  (bc & 0xFF);
        arr[byteCountOffset + 1] = (byte) ((bc >> 8) & 0xFF);
        return arr;
    }

    // -------------------------------------------------------------------------
    // RDP — X.224 connection request + RDP negotiation
    // -------------------------------------------------------------------------

    private static ProbeResult probeRdp(String host, int port) {
        try (Socket s = connect(host, port)) {
            InputStream in  = s.getInputStream();
            OutputStream out = s.getOutputStream();

            // TPKT + X.224 Connection Request + RDP Negotiation Request
            byte[] rdpCR = {
                0x03, 0x00, 0x00, 0x13,   // TPKT: version 3, length 19
                0x0e,                      // X.224 length indicator (14)
                (byte) 0xe0,               // X.224 PDU type: CR TPDU
                0x00, 0x00,                // DST-REF
                0x00, 0x00,                // SRC-REF
                0x00,                      // class/options
                0x01,                      // RDP_NEG_REQ type
                0x00,                      // flags
                0x08, 0x00,                // length: 8
                0x03, 0x00, 0x00, 0x00     // requested protocols: SSL | CredSSP
            };
            out.write(rdpCR);
            out.flush();

            byte[] resp = new byte[64];
            int read = in.read(resp);

            Map<String, String> attrs   = new LinkedHashMap<>();
            List<String>        warnings = new ArrayList<>();

            if (read >= 11 && resp[0] == 0x03) {
                attrs.put("Transport", "TPKT/X.224");

                if (read >= 19 && (resp[11] & 0xFF) == 0x02) { // RDP_NEG_RSP
                    int proto = (resp[15] & 0xFF) | ((resp[16] & 0xFF) << 8);
                    if ((proto & 0x02) != 0) {
                        attrs.put("Security", "CredSSP/NLA (recommended)");
                    } else if ((proto & 0x01) != 0) {
                        attrs.put("Security", "TLS only");
                    } else if ((proto & 0x08) != 0) {
                        attrs.put("Security", "RDSTLS");
                    } else {
                        attrs.put("Security", "RDP Standard Security (no TLS — DEPRECATED)");
                        warnings.add("[CRITICAL] RDP using legacy security without TLS"
                                + " — credential interception risk");
                    }
                } else if (read >= 12 && (resp[11] & 0xFF) == 0x03) { // RDP_NEG_FAILURE
                    attrs.put("Negotiation", "server refused — NLA required");
                }

                warnings.add("[HIGH] RDP exposed — brute-force and BlueKeep"
                        + " (CVE-2019-0708) exposure");
            }

            return new ProbeResult("RDP", null, buildDetails(attrs, List.of(), warnings));
        } catch (IOException e) {
            LOG.fine(() -> "RDP probe failed for " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Protocol predicates
    // -------------------------------------------------------------------------

    private static boolean isSsh(int port, String banner) {
        return port == 22 || (banner != null && banner.startsWith("SSH-"));
    }

    private static boolean isRedis(int port, String banner) {
        return port == 6379 || (banner != null && banner.startsWith("+PONG"));
    }

    private static boolean isMongo(int port) {
        return port == 27017 || port == 27018 || port == 27019;
    }

    private static boolean isSmtp(int port, String banner) {
        return port == 25 || port == 587 || port == 465
                || (banner != null && banner.startsWith("220 ")
                        && banner.toUpperCase().contains("SMTP"));
    }

    private static boolean isFtp(int port, String banner) {
        return port == 21
                || (banner != null && banner.startsWith("220 ")
                        && banner.toLowerCase().contains("ftp"));
    }

    private static boolean isDns(int port) {
        return port == 53;
    }

    private static boolean isVnc(int port, String banner) {
        return port == 5900 || port == 5901 || port == 5902
                || (banner != null && banner.startsWith("RFB"));
    }

    private static boolean isMemcached(int port) {
        return port == 11211;
    }

    private static boolean isLdap(int port) {
        return port == 389 || port == 636 || port == 3268;
    }

    private static boolean isSmb(int port) {
        return port == 445 || port == 139;
    }

    private static boolean isRdp(int port) {
        return port == 3389;
    }

    // -------------------------------------------------------------------------
    // I/O helpers
    // -------------------------------------------------------------------------

    private static Socket connect(String host, int port) throws IOException {
        Socket s = new Socket();
        s.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
        s.setSoTimeout(TIMEOUT_MS);
        return s;
    }

    private static void readFully(InputStream in, byte[] buf) throws IOException {
        int offset = 0;
        while (offset < buf.length) {
            int n = in.read(buf, offset, buf.length - offset);
            if (n == -1) throw new EOFException("Unexpected end of stream");
            offset += n;
        }
    }

    /** Reads one line from raw InputStream without buffering extra bytes. */
    private static String readLineRaw(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') break;
            if (b != '\r') sb.append((char) b);
        }
        return sb.toString();
    }

    /** Reads a multi-line SMTP response (continues while 3rd char is '-'). */
    private static String readSmtpMultiline(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        String line;
        do {
            line = readLineRaw(in);
            if (line == null || line.isEmpty()) break;
            sb.append(line).append("\n");
        } while (line.length() >= 4 && line.charAt(3) == '-');
        return sb.toString();
    }

    /** Formats attrs/caps/warnings into the details string stored in {@link ProbeResult}. */
    private static String buildDetails(Map<String, String> attrs,
                                       List<String> caps,
                                       List<String> warnings) {
        StringBuilder sb = new StringBuilder();
        attrs.forEach((k, v) -> sb.append("\n  ").append(k).append(": ").append(v));
        if (!caps.isEmpty()) {
            sb.append("\n  Capabilities: ").append(String.join(", ", caps));
        }
        warnings.forEach(w -> sb.append("\n  ").append(w));
        return sb.toString();
    }

    private static ProbeResult simpleResult(String proto, String banner) {
        Map<String, String> attrs = new LinkedHashMap<>();
        if (banner != null && !banner.isBlank()) attrs.put("Banner", banner);
        return new ProbeResult(proto, null, buildDetails(attrs, List.of(), List.of()));
    }
}
