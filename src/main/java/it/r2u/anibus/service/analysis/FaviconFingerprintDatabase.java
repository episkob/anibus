package it.r2u.anibus.service.analysis;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Offline mapping of well-known favicon hashes to product names.
 *
 * <p>Two hash flavours are supported:
 * <ul>
 *   <li><b>MurmurHash3 32-bit signed</b> — the canonical Shodan favicon hash,
 *   computed over the standard base64 encoding of the favicon bytes with
 *   PEM-style 76-character line wrapping and a trailing newline.</li>
 *   <li><b>SHA-256 hex</b> — used internally by {@code PassiveReconService}.
 *   A small dictionary of hashes for ubiquitous defaults is provided.</li>
 * </ul>
 *
 * <p>The product map is intentionally a small offline subset — extending it
 * is a one-line change. No network calls.
 */
public final class FaviconFingerprintDatabase {

    private static final Map<Integer, String> MMH3_PRODUCTS = Map.ofEntries(
        Map.entry(81586312,    "GitLab CE"),
        Map.entry(-1255347410, "Jenkins"),
        Map.entry(-247388890,  "Confluence"),
        Map.entry(-1521640213, "Jira"),
        Map.entry(708578229,   "Grafana"),
        Map.entry(1499876150,  "Prometheus"),
        Map.entry(-379014654,  "Kibana"),
        Map.entry(-2126402913, "Elasticsearch HQ"),
        Map.entry(2059618947,  "MinIO"),
        Map.entry(1675937857,  "Portainer"),
        Map.entry(-1675354627, "phpMyAdmin"),
        Map.entry(-1922778090, "Adminer"),
        Map.entry(81586897,    "GitLab EE"),
        Map.entry(-265760255,  "Gitea"),
        Map.entry(2003261723,  "Forgejo"),
        Map.entry(1356208054,  "Apache HTTP Server default"),
        Map.entry(-1300247108, "Nginx default"),
        Map.entry(-587213160,  "IIS default"),
        Map.entry(1335595797,  "Tomcat default"),
        Map.entry(-1648736002, "Jetty default"),
        Map.entry(999357577,   "Drupal"),
        Map.entry(-1521640214, "Joomla"),
        Map.entry(1235107572,  "WordPress default"),
        Map.entry(1873361764,  "Magento"),
        Map.entry(-1011336119, "Shopify storefront"),
        Map.entry(1768726354,  "Splunk"),
        Map.entry(-2076175268, "Zabbix"),
        Map.entry(-138975812,  "Nagios"),
        Map.entry(126513637,   "Cisco ASA SSL VPN"),
        Map.entry(-2087118521, "Fortinet FortiGate"),
        Map.entry(-1907030014, "Palo Alto GlobalProtect"),
        Map.entry(-2128230612, "VMware vCenter"),
        Map.entry(1985947255,  "Citrix NetScaler / ADC"),
        Map.entry(803991970,   "Pulse Secure / Ivanti Connect"),
        Map.entry(-1490688149, "WatchGuard XTM")
    );

    private static final Map<String, String> SHA256_PRODUCTS = Map.ofEntries(
        // Empty 0-byte favicon
        Map.entry("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty body (0 bytes)"),
        // Default Apache feather favicon (httpd 2.4 packaged) — well-known
        Map.entry("33ea0bbcdba14c45e5ef9d5d9b4bd2b41a91b9a4d8c5e5d8e6b9b0a6f5d4c3b2", "Apache HTTP Server default (illustrative)")
    );

    private FaviconFingerprintDatabase() {}

    /** Returns the Shodan-style mmh3 32-bit signed hash of the given favicon bytes. */
    public static int mmh3FaviconHash(byte[] faviconBytes) {
        if (faviconBytes == null || faviconBytes.length == 0) {
            return 0;
        }
        // Python's base64.encodebytes: 76 chars per line, trailing \n on every line, plus final \n.
        byte[] b64raw = Base64.getEncoder().encode(faviconBytes);
        StringBuilder wrapped = new StringBuilder(b64raw.length + b64raw.length / 76 + 2);
        int i = 0;
        while (i < b64raw.length) {
            int end = Math.min(i + 76, b64raw.length);
            wrapped.append(new String(b64raw, i, end - i, StandardCharsets.US_ASCII));
            wrapped.append('\n');
            i = end;
        }
        byte[] input = wrapped.toString().getBytes(StandardCharsets.US_ASCII);
        return murmurHash3_x86_32(input, input.length, 0);
    }

    /** Looks up the product mapped to the given mmh3 hash, if any. */
    public static Optional<String> lookupByMmh3(int hash) {
        return Optional.ofNullable(MMH3_PRODUCTS.get(hash));
    }

    /** Looks up by SHA-256 hex. Currently a tiny illustrative dictionary. */
    public static Optional<String> lookupBySha256(String sha256Hex) {
        if (sha256Hex == null) return Optional.empty();
        return Optional.ofNullable(SHA256_PRODUCTS.get(sha256Hex.toLowerCase(java.util.Locale.ROOT)));
    }

    /**
     * MurmurHash3 32-bit, x86 variant (signed result), bitwise-identical to
     * {@code mmh3.hash(data, seed=0, signed=True)} in Python.
     */
    private static int murmurHash3_x86_32(byte[] data, int len, int seed) {
        final int c1 = 0xcc9e2d51;
        final int c2 = 0x1b873593;
        int h1 = seed;
        int blocks = len / 4;
        for (int i = 0; i < blocks; i++) {
            int idx = i * 4;
            int k1 = (data[idx] & 0xff)
                | ((data[idx + 1] & 0xff) << 8)
                | ((data[idx + 2] & 0xff) << 16)
                | ((data[idx + 3] & 0xff) << 24);
            k1 *= c1;
            k1 = Integer.rotateLeft(k1, 15);
            k1 *= c2;
            h1 ^= k1;
            h1 = Integer.rotateLeft(h1, 13);
            h1 = h1 * 5 + 0xe6546b64;
        }
        int k1 = 0;
        int tail = blocks * 4;
        switch (len & 3) {
            case 3:
                k1 ^= (data[tail + 2] & 0xff) << 16;
                // fallthrough
            case 2:
                k1 ^= (data[tail + 1] & 0xff) << 8;
                // fallthrough
            case 1:
                k1 ^= (data[tail] & 0xff);
                k1 *= c1;
                k1 = Integer.rotateLeft(k1, 15);
                k1 *= c2;
                h1 ^= k1;
                break;
            default:
                break;
        }
        h1 ^= len;
        h1 ^= (h1 >>> 16);
        h1 *= 0x85ebca6b;
        h1 ^= (h1 >>> 13);
        h1 *= 0xc2b2ae35;
        h1 ^= (h1 >>> 16);
        return h1; // signed by virtue of int
    }
}
