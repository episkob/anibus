package it.r2u.anibus.service.analysis;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * NTLMv2 message builder (Type-1 / Type-3) plus a Type-2 challenge parser.
 *
 * <p>Implements the subset of MS-NLMP needed for reconnaissance probes
 * against IIS, Sharepoint and Exchange Web Services:
 * <ul>
 *   <li>Type-1 Negotiate with the same flags Firefox/Chromium send</li>
 *   <li>Type-2 challenge parsing — server challenge + target info block</li>
 *   <li>Type-3 NTLMv2 response (HMAC-MD5 keyed by NTOWFv2)</li>
 * </ul>
 *
 * <p>No signing, no sealing, no Message Integrity Code (MIC). LM response
 * is omitted (sent as 24 zero bytes) — modern servers accept this.
 */
final class NtlmMessages {

    private static final byte[] NTLM_SIGNATURE = "NTLMSSP\0".getBytes(StandardCharsets.US_ASCII);
    private static final int TYPE_1 = 1;
    private static final int TYPE_3 = 3;

    // Negotiate flags (subset). Bits as per [MS-NLMP] §2.2.2.5.
    private static final int FLAG_NEGOTIATE_UNICODE     = 0x00000001;
    private static final int FLAG_NEGOTIATE_OEM         = 0x00000002;
    private static final int FLAG_REQUEST_TARGET        = 0x00000004;
    private static final int FLAG_NEGOTIATE_NTLM        = 0x00000200;
    private static final int FLAG_NEGOTIATE_ALWAYS_SIGN = 0x00008000;
    private static final int FLAG_NEGOTIATE_NTLM2_KEY   = 0x00080000;
    private static final int FLAG_NEGOTIATE_128         = 0x20000000;
    private static final int FLAG_NEGOTIATE_56          = 0x80000000;

    private NtlmMessages() {}

    static byte[] type1(String workstation, String domain) {
        int flags = FLAG_NEGOTIATE_UNICODE | FLAG_NEGOTIATE_OEM | FLAG_REQUEST_TARGET
            | FLAG_NEGOTIATE_NTLM | FLAG_NEGOTIATE_ALWAYS_SIGN
            | FLAG_NEGOTIATE_NTLM2_KEY | FLAG_NEGOTIATE_128 | FLAG_NEGOTIATE_56;
        ByteBuffer bb = ByteBuffer.allocate(40).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(NTLM_SIGNATURE);
        bb.putInt(TYPE_1);
        bb.putInt(flags);
        // DomainNameFields (length, maxlen, offset) — empty
        bb.putShort((short) 0); bb.putShort((short) 0); bb.putInt(40);
        // WorkstationFields (length, maxlen, offset) — empty
        bb.putShort((short) 0); bb.putShort((short) 0); bb.putInt(40);
        // Version (8 bytes) — left zero / unused
        bb.putLong(0L);
        // Workstation/domain are sent only when OEM-encoded; we deliberately
        // omit them for compatibility — many servers ignore Type-1 payloads.
        // Parameters are kept for API symmetry with type3().
        return bb.array();
    }

    /** Type-3 NTLMv2 response built from a parsed Type-2 challenge. */
    static byte[] type3(byte[] type2, String username, String password,
            String workstation, String domain) {
        Type2 t2 = parseType2(type2);
        byte[] ntowfv2 = ntowfv2(username, password, domain);

        // Blob: 0x01 0x01 reserved(0) reserved(0) timestamp(8) clientChallenge(8) reserved(4) targetInfo z(4)
        byte[] clientChallenge = randomBytes(8);
        long timestamp = (System.currentTimeMillis() + 11_644_473_600_000L) * 10_000L; // Windows FILETIME 100ns
        ByteBuffer blob = ByteBuffer.allocate(28 + (t2.targetInfo == null ? 0 : t2.targetInfo.length) + 4)
            .order(ByteOrder.LITTLE_ENDIAN);
        blob.put((byte) 0x01).put((byte) 0x01);
        blob.putShort((short) 0).putInt(0); // reserved
        blob.putLong(timestamp);
        blob.put(clientChallenge);
        blob.putInt(0); // reserved
        if (t2.targetInfo != null) blob.put(t2.targetInfo);
        blob.putInt(0); // reserved trailer
        byte[] blobBytes = blob.array();

        byte[] ntProofStr = hmacMd5(ntowfv2, concat(t2.serverChallenge, blobBytes));
        byte[] ntResponse = concat(ntProofStr, blobBytes);
        byte[] lmResponse = new byte[24]; // zero-filled — modern servers tolerate this

        byte[] userBytes = unicode(username);
        byte[] domainBytes = unicode(domain == null ? "" : domain);
        byte[] wsBytes = unicode(workstation == null ? "" : workstation);
        byte[] sessionKey = new byte[0]; // no signing

        int headerLen = 64; // 8 sig + 4 type + 6*(8 field) + 4 flags == 8+4+48+4 = 64
        int offset = headerLen;
        int domainOff = offset; offset += domainBytes.length;
        int userOff = offset; offset += userBytes.length;
        int wsOff = offset; offset += wsBytes.length;
        int lmOff = offset; offset += lmResponse.length;
        int ntOff = offset; offset += ntResponse.length;
        int skOff = offset; offset += sessionKey.length;

        ByteBuffer bb = ByteBuffer.allocate(offset).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(NTLM_SIGNATURE);
        bb.putInt(TYPE_3);
        putField(bb, lmResponse.length, lmOff);
        putField(bb, ntResponse.length, ntOff);
        putField(bb, domainBytes.length, domainOff);
        putField(bb, userBytes.length, userOff);
        putField(bb, wsBytes.length, wsOff);
        putField(bb, sessionKey.length, skOff);
        bb.putInt(t2.flags);
        bb.put(domainBytes);
        bb.put(userBytes);
        bb.put(wsBytes);
        bb.put(lmResponse);
        bb.put(ntResponse);
        bb.put(sessionKey);
        return bb.array();
    }

    private static void putField(ByteBuffer bb, int length, int offset) {
        bb.putShort((short) length);
        bb.putShort((short) length);
        bb.putInt(offset);
    }

    private static final class Type2 {
        byte[] serverChallenge;
        int flags;
        byte[] targetInfo;
    }

    private static Type2 parseType2(byte[] msg) {
        if (msg == null || msg.length < 32) {
            throw new IllegalArgumentException("NTLM Type-2 message too short");
        }
        ByteBuffer bb = ByteBuffer.wrap(msg).order(ByteOrder.LITTLE_ENDIAN);
        byte[] sig = new byte[8];
        bb.get(sig);
        if (!Arrays.equals(sig, NTLM_SIGNATURE)) {
            throw new IllegalArgumentException("NTLM signature mismatch");
        }
        int type = bb.getInt();
        if (type != 2) {
            throw new IllegalArgumentException("Expected NTLM Type-2, got " + type);
        }
        // skip TargetName fields (len, maxlen, offset)
        bb.getShort(); bb.getShort(); bb.getInt();
        int flags = bb.getInt();
        byte[] serverChallenge = new byte[8];
        bb.get(serverChallenge);
        // Skip 8 reserved bytes if present
        byte[] targetInfo = null;
        if (msg.length >= 48) {
            bb.position(bb.position() + 8); // reserved
            int tiLen = bb.getShort() & 0xFFFF;
            bb.getShort(); // maxlen
            int tiOff = bb.getInt();
            if (tiLen > 0 && tiOff >= 0 && tiOff + tiLen <= msg.length) {
                targetInfo = Arrays.copyOfRange(msg, tiOff, tiOff + tiLen);
            }
        }
        Type2 t = new Type2();
        t.serverChallenge = serverChallenge;
        t.flags = flags;
        t.targetInfo = targetInfo;
        return t;
    }

    private static byte[] ntowfv2(String username, String password, String domain) {
        byte[] md4 = md4(unicode(password == null ? "" : password));
        String upperUser = (username == null ? "" : username).toUpperCase(Locale.ROOT);
        byte[] identity = unicode(upperUser + (domain == null ? "" : domain));
        return hmacMd5(md4, identity);
    }

    private static byte[] hmacMd5(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacMD5");
            mac.init(new SecretKeySpec(key, "HmacMD5"));
            return mac.doFinal(data);
        } catch (java.security.NoSuchAlgorithmException | java.security.InvalidKeyException e) {
            throw new IllegalStateException("HMAC-MD5 unavailable", e);
        }
    }

    /**
     * MD4 of the given byte array. Java does not ship an MD4 provider — we
     * implement the algorithm directly (RFC 1320). Only ~40 lines.
     */
    private static byte[] md4(byte[] message) {
        int[] state = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
        long bitLen = (long) message.length * 8L;
        int padLen = (56 - (message.length + 1) % 64 + 64) % 64;
        byte[] padded = new byte[message.length + 1 + padLen + 8];
        System.arraycopy(message, 0, padded, 0, message.length);
        padded[message.length] = (byte) 0x80;
        ByteBuffer.wrap(padded, padded.length - 8, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(bitLen);
        for (int block = 0; block < padded.length; block += 64) {
            int[] x = new int[16];
            ByteBuffer bb = ByteBuffer.wrap(padded, block, 64).order(ByteOrder.LITTLE_ENDIAN);
            for (int i = 0; i < 16; i++) x[i] = bb.getInt();
            int a = state[0], b = state[1], c = state[2], d = state[3];
            // Round 1
            int[] r1 = {3, 7, 11, 19};
            for (int i = 0; i < 16; i++) {
                int t = a + ((b & c) | (~b & d)) + x[i];
                a = Integer.rotateLeft(t, r1[i % 4]);
                int tmp = d; d = c; c = b; b = a; a = tmp;
            }
            // Round 2
            int[] r2 = {3, 5, 9, 13};
            int[] idx2 = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
            for (int i = 0; i < 16; i++) {
                int t = a + ((b & c) | (b & d) | (c & d)) + x[idx2[i]] + 0x5A827999;
                a = Integer.rotateLeft(t, r2[i % 4]);
                int tmp = d; d = c; c = b; b = a; a = tmp;
            }
            // Round 3
            int[] r3 = {3, 9, 11, 15};
            int[] idx3 = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
            for (int i = 0; i < 16; i++) {
                int t = a + (b ^ c ^ d) + x[idx3[i]] + 0x6ED9EBA1;
                a = Integer.rotateLeft(t, r3[i % 4]);
                int tmp = d; d = c; c = b; b = a; a = tmp;
            }
            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        }
        ByteBuffer out = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        for (int v : state) out.putInt(v);
        return out.array();
    }

    private static byte[] unicode(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_16LE);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static final SecureRandom RNG = new SecureRandom();

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    // Test-only helper used by AuthCrawlerTest.
    static byte[] md4ForTesting(byte[] m) {
        return md4(m);
    }

    // Test-only helpers.
    static byte[] type1ForTesting() { return type1("", ""); }

    static boolean signatureOk(byte[] msg) {
        if (msg == null || msg.length < 8) return false;
        return Arrays.equals(Arrays.copyOfRange(msg, 0, 8), NTLM_SIGNATURE);
    }

    // Avoid unused MessageDigest import warning (we use it indirectly via JCE for HMAC).
    @SuppressWarnings("unused")
    private static MessageDigest noop() { return null; }
}
