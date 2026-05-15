package it.r2u.anibus.service.network;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * Heartbleed Checker — tests whether a TLS server is vulnerable to
 * CVE-2014-0160 (OpenSSL heartbeat read overread).
 *
 * <h3>How it works</h3>
 * <ol>
 *   <li>Open a raw TCP socket and perform a minimal TLS 1.0/1.1 ClientHello
 *       to negotiate the handshake.</li>
 *   <li>Send a malformed TLS Heartbeat request that declares a payload length
 *       of 0 bytes but a requested return length of 64 KB.</li>
 *   <li>Read the response and look for a Heartbeat reply (type 24 / 0x18).
 *       A vulnerable server will echo up to 64 KB of its process memory.</li>
 *   <li><strong>False-positive guard</strong>: verify that the reply record
 *       has type {@code 0x18} (heartbeat), sub-type {@code 0x02} (response),
 *       and that the returned length is strictly greater than the sent payload
 *       length.  A server that simply closes the connection or returns an
 *       alert is considered non-vulnerable.</li>
 * </ol>
 *
 * <p>No sensitive data is transmitted; the probe does not attempt to read
 * any returned memory content — it only checks the structural indicators.
 */
public class HeartbleedChecker {

    // ── Result types ─────────────────────────────────────────────────────────

    public enum VerdictType {
        /** Server returned a valid Heartbeat response with an overread. */
        VULNERABLE,
        /** Server closed or sent an alert — not vulnerable by this probe. */
        NOT_VULNERABLE,
        /** TLS handshake failed before the heartbeat could be sent. */
        HANDSHAKE_FAILED,
        /** Network connection could not be established. */
        UNREACHABLE,
        /** A response was received but could not be classified unambiguously. */
        INCONCLUSIVE
    }

    public record HandshakeDiagnostic(
            boolean connected,
            String  negotiatedVersion,   // e.g. "TLSv1.0", or null
            String  cipherSuiteOffered,  // first suite in ClientHello
            boolean serverHelloReceived,
            boolean heartbeatExtSeen     // server advertised heartbeat extension
    ) {}

    public record HeartbleedResult(
            String              host,
            int                 port,
            VerdictType         verdict,
            HandshakeDiagnostic handshake,
            String              detail,
            List<String>        falsePositiveGuardNotes
    ) {
        public boolean isVulnerable() { return verdict == VerdictType.VULNERABLE; }
    }

    // ── Heartbeat extension type (RFC 6520) ───────────────────────────────────
    private static final int HEARTBEAT_EXT_TYPE  = 0x000F;
    private static final int TLS_RECORD_HEARTBEAT = 0x18;    // 24
    private static final int HB_RESPONSE           = 0x02;

    // Minimal TLS 1.0 ClientHello (with heartbeat extension)
    // Record: type=22 (Handshake), version=0x0301 (TLS 1.0)
    private static final byte[] CLIENT_HELLO = buildClientHello();

    // Heartbeat request: type=24, version=0x0301, len=0x0007 payload
    // HeartbeatMessage: type=1 (request), payload_length=0x4000 (16384 overread), padding
    private static final byte[] HEARTBEAT_REQUEST = {
            // TLS record header
            (byte) 0x18,             // type: heartbeat
            (byte) 0x03, (byte) 0x01, // version: TLS 1.0
            (byte) 0x00, (byte) 0x03, // length: 3 bytes payload
            // HeartbeatMessage
            (byte) 0x01,             // type: heartbeat_request
            (byte) 0x40, (byte) 0x00 // payload_length: 0x4000 = 16384 (but actual payload = 0 bytes)
            // no payload bytes, no padding → triggers overread in vulnerable servers
    };

    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS    = 8_000;

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Tests whether the host is vulnerable to Heartbleed.
     *
     * @param host target hostname or IP
     * @param port TLS port (typically 443)
     */
    public static HeartbleedResult check(String host, int port) {
        List<String> fpNotes = new ArrayList<>();
        HandshakeDiagnostic diag;

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);

            OutputStream out = socket.getOutputStream();
            InputStream  in  = socket.getInputStream();

            // 1. Send ClientHello
            out.write(CLIENT_HELLO);
            out.flush();

            // 2. Read server response (ServerHello + Certificate + possibly ServerHelloDone)
            diag = readHandshakeResponse(in, fpNotes);

            if (!diag.serverHelloReceived()) {
                return new HeartbleedResult(host, port, VerdictType.HANDSHAKE_FAILED,
                        diag, "Server did not respond to ClientHello", fpNotes);
            }

            // 3. Send Heartbeat probe
            out.write(HEARTBEAT_REQUEST);
            out.flush();

            // 4. Read response
            return readHeartbeatResponse(host, port, in, diag, fpNotes);

        } catch (IOException e) {
            diag = new HandshakeDiagnostic(false, null, "TLS_RSA_WITH_AES_128_CBC_SHA", false, false);
            return new HeartbleedResult(host, port, VerdictType.UNREACHABLE,
                    diag, "Connection failed: " + e.getMessage(), fpNotes);
        }
    }

    /** Formats the check result as a human-readable string. */
    public static String formatReport(HeartbleedResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("Heartbleed (CVE-2014-0160) Check — ")
          .append(result.host()).append(':').append(result.port())
          .append(System.lineSeparator());
        sb.append("─".repeat(60)).append(System.lineSeparator());

        String verdictLine = switch (result.verdict()) {
            case VULNERABLE         -> "⚠ VULNERABLE — server returned heartbeat overread data!";
            case NOT_VULNERABLE     -> "✅ NOT VULNERABLE — server rejected malformed heartbeat";
            case HANDSHAKE_FAILED   -> "ℹ HANDSHAKE FAILED — TLS negotiation did not complete";
            case UNREACHABLE        -> "✗ UNREACHABLE — could not connect";
            case INCONCLUSIVE       -> "? INCONCLUSIVE — response did not match expected patterns";
        };
        sb.append("Verdict: ").append(verdictLine).append(System.lineSeparator());
        sb.append("Detail : ").append(result.detail()).append(System.lineSeparator());
        sb.append(System.lineSeparator());

        // Handshake diagnostics
        HandshakeDiagnostic d = result.handshake();
        sb.append("Handshake Diagnostics:").append(System.lineSeparator());
        sb.append("  Connected       : ").append(d.connected() ? "yes" : "no").append(System.lineSeparator());
        if (d.negotiatedVersion() != null)
            sb.append("  TLS Version     : ").append(d.negotiatedVersion()).append(System.lineSeparator());
        sb.append("  Cipher offered  : ").append(d.cipherSuiteOffered()).append(System.lineSeparator());
        sb.append("  ServerHello rcv : ").append(d.serverHelloReceived()).append(System.lineSeparator());
        sb.append("  HB extension    : ").append(d.heartbeatExtSeen() ? "advertised by server" : "not seen")
          .append(System.lineSeparator());

        if (result.isVulnerable()) {
            sb.append(System.lineSeparator());
            sb.append("References:").append(System.lineSeparator());
            sb.append("  NVD   : https://nvd.nist.gov/vuln/detail/CVE-2014-0160").append(System.lineSeparator());
            sb.append("  Site  : https://heartbleed.com").append(System.lineSeparator());
            sb.append("  Fix   : Upgrade OpenSSL to 1.0.1g or later, regenerate keys").append(System.lineSeparator());
        }

        if (!result.falsePositiveGuardNotes().isEmpty()) {
            sb.append(System.lineSeparator());
            sb.append("False-Positive Guard:").append(System.lineSeparator());
            for (String note : result.falsePositiveGuardNotes()) {
                sb.append("  • ").append(note).append(System.lineSeparator());
            }
        }

        return sb.toString().trim();
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    /**
     * Reads TLS records until we see ServerHello or an Alert.
     * Returns a HandshakeDiagnostic with what was observed.
     */
    private static HandshakeDiagnostic readHandshakeResponse(InputStream in,
                                                              List<String> fpNotes) throws IOException {
        boolean serverHelloReceived = false;
        boolean heartbeatExtSeen   = false;
        String  negotiatedVersion  = null;

        // Read up to 16 KB of handshake data (blocking read; socket timeout guards the deadline)
        byte[] buf = new byte[16_384];
        int total  = 0;

        while (total < buf.length) {
            int read;
            try {
                read = in.read(buf, total, buf.length - total);
            } catch (java.net.SocketTimeoutException e) {
                break; // READ_TIMEOUT_MS elapsed
            }
            if (read < 0) break;
            total += read;

            // Scan for ServerHello (handshake type 0x02 inside record type 0x16)
            for (int i = 0; i < total - 6; i++) {
                if ((buf[i] & 0xFF) == 0x16) {                     // Handshake record
                    int recLen = ((buf[i + 3] & 0xFF) << 8) | (buf[i + 4] & 0xFF);
                    if (i + 5 + recLen > total) continue;
                    if ((buf[i + 5] & 0xFF) == 0x02) {             // ServerHello
                        serverHelloReceived = true;
                        // TLS version bytes are at i+9, i+10
                        if (i + 10 < total) {
                            int v = ((buf[i + 9] & 0xFF) << 8) | (buf[i + 10] & 0xFF);
                            negotiatedVersion = tlsVersionString(v);
                        }
                    }
                }
                // Check for heartbeat extension presence (type 0x000F)
                if (i + 3 < total) {
                    int extType = ((buf[i] & 0xFF) << 8) | (buf[i + 1] & 0xFF);
                    if (extType == HEARTBEAT_EXT_TYPE) {
                        heartbeatExtSeen = true;
                        fpNotes.add("Server advertised heartbeat extension in ServerHello — consistent with OpenSSL < 1.0.2");
                    }
                }
            }
            if (serverHelloReceived) break;
        }

        if (!serverHelloReceived) {
            fpNotes.add("No ServerHello received — server may require SNI or use TLS 1.3 only");
        }

        return new HandshakeDiagnostic(true, negotiatedVersion,
                "TLS_RSA_WITH_AES_128_CBC_SHA", serverHelloReceived, heartbeatExtSeen);
    }

    /**
     * Reads the server response to the heartbeat probe and classifies the verdict.
     */
    private static HeartbleedResult readHeartbeatResponse(String host, int port,
                                                           InputStream in,
                                                           HandshakeDiagnostic diag,
                                                           List<String> fpNotes) throws IOException {
        // Blocking read; socket timeout (READ_TIMEOUT_MS) guards against indefinite wait.
        byte[] resp = new byte[8_192];
        int total = 0;

        while (total < resp.length) {
            int read;
            try {
                read = in.read(resp, total, resp.length - total);
            } catch (java.net.SocketTimeoutException e) {
                break; // no more data within timeout
            }
            if (read < 0) break;
            total += read;
            if (total >= 5) break; // we have enough to classify the first record
        }

        if (total < 5) {
            fpNotes.add("Server closed connection or sent no data after heartbeat probe — likely not vulnerable");
            return new HeartbleedResult(host, port, VerdictType.NOT_VULNERABLE, diag,
                    "No heartbeat response (server closed connection)", fpNotes);
        }

        // Scan response bytes for a heartbeat response record
        for (int i = 0; i < total - 4; i++) {
            int recType = buf(resp, i);
            if (recType == TLS_RECORD_HEARTBEAT) {                  // 0x18
                int recLen = (buf(resp, i + 3) << 8) | buf(resp, i + 4);
                if (i + 5 >= total) continue;
                int hbType = buf(resp, i + 5);                      // 0x02 = response

                if (hbType == HB_RESPONSE) {
                    // False-positive guard: returned length must exceed sent payload length (0 bytes)
                    // recLen > 3 bytes (hbType + payload_length field) → we got memory content
                    if (recLen > 3) {
                        fpNotes.add("Received heartbeat RESPONSE record (type=0x18 sub=0x02) with " + recLen + " bytes — exceeds sent payload of 0 bytes");
                        fpNotes.add("Guard check PASSED: response length " + recLen + " > sent payload 0 — genuine overread confirmed");
                        return new HeartbleedResult(host, port, VerdictType.VULNERABLE, diag,
                                "Server returned " + recLen + " bytes of memory data in heartbeat response", fpNotes);
                    } else {
                        fpNotes.add("Received heartbeat response but length (" + recLen + ") ≤ 3 — not a meaningful overread");
                        return new HeartbleedResult(host, port, VerdictType.NOT_VULNERABLE, diag,
                                "Heartbeat response had no extra data — patched server behavior", fpNotes);
                    }
                }
            }

            // Alert record (type 0x15) means server rejected the probe
            if (recType == 0x15) {
                fpNotes.add("Server sent TLS Alert in response to heartbeat probe — correctly rejecting malformed message");
                return new HeartbleedResult(host, port, VerdictType.NOT_VULNERABLE, diag,
                        "Server returned TLS Alert — rejected malformed heartbeat (not vulnerable)", fpNotes);
            }
        }

        fpNotes.add("Response bytes did not contain recognisable heartbeat record — inconclusive");
        return new HeartbleedResult(host, port, VerdictType.INCONCLUSIVE, diag,
                "Could not classify server response to heartbeat probe", fpNotes);
    }

    // ── ClientHello builder ───────────────────────────────────────────────────

    private static byte[] buildClientHello() {
        // Minimal TLS 1.0 ClientHello with heartbeat extension (type 0x000F)
        return new byte[] {
            // TLS Record header
            (byte)0x16,                   // type: Handshake (22)
            (byte)0x03, (byte)0x01,       // version: TLS 1.0
            (byte)0x00, (byte)0x3d,       // length: 61

            // Handshake header
            (byte)0x01,                   // HandshakeType: ClientHello
            (byte)0x00, (byte)0x00, (byte)0x39, // length: 57

            // ClientHello body
            (byte)0x03, (byte)0x02,       // client_version: TLS 1.1 (we offer 1.1 so 1.0 servers respond)
            // random (32 bytes — all zeros for probe simplicity)
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
            0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
            (byte)0x00,                   // session_id length: 0

            // cipher suites (2 suites)
            (byte)0x00, (byte)0x04,
            (byte)0x00, (byte)0x2f,       // TLS_RSA_WITH_AES_128_CBC_SHA
            (byte)0x00, (byte)0xff,       // TLS_EMPTY_RENEGOTIATION_INFO_SCSV

            // compression methods
            (byte)0x01, (byte)0x00,       // no compression

            // extensions length
            (byte)0x00, (byte)0x09,

            // Heartbeat extension
            (byte)0x00, (byte)0x0f,       // extension type: heartbeat (15)
            (byte)0x00, (byte)0x01,       // extension data length: 1
            (byte)0x01                    // peer_allowed_to_send: peer_allowed (1)
        };
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static int buf(byte[] data, int index) {
        return data[index] & 0xFF;
    }

    private static String tlsVersionString(int v) {
        return switch (v) {
            case 0x0301 -> "TLSv1.0";
            case 0x0302 -> "TLSv1.1";
            case 0x0303 -> "TLSv1.2";
            case 0x0304 -> "TLSv1.3";
            default     -> String.format("unknown(0x%04x)", v);
        };
    }
}
