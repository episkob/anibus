package it.r2u.anibus.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Probes cloud instance metadata endpoints (IMDS — Instance Metadata Service).
 *
 * The link-local address 169.254.169.254 is used by:
 *   AWS / Alibaba Cloud — /latest/meta-data/
 *   GCP                 — /computeMetadata/v1/  (requires Metadata-Flavor: Google)
 *   Azure               — /metadata/instance    (requires Metadata: true)
 *   DigitalOcean        — /metadata/v1/
 *
 * If this endpoint responds, the scanner is running inside a cloud instance,
 * or the hop-limit protection on IMDSv1 was not configured (TTL > 1).
 * In either case, IAM roles, access keys, and network topology may be exposed.
 */
public class CloudMetadataProbe {

    private static final String IMDS_IP  = "169.254.169.254";
    private static final int    TIMEOUT  = 1500;
    private static final int    MAX_BODY = 2048;

    // ─── Public result ─────────────────────────────────────────────────────────

    public static class MetadataResult {
        private final String       provider;
        private final List<String> findings;

        MetadataResult(String provider, List<String> findings) {
            this.provider = provider;
            this.findings = findings;
        }

        public String       getProvider() { return provider; }
        public List<String> getFindings() { return findings; }
        public boolean      isEmpty()     { return findings.isEmpty(); }

        @Override
        public String toString() {
            if (findings.isEmpty()) return "";
            StringBuilder sb = new StringBuilder(
                "[CLOUD] Cloud Metadata Exposed (" + provider + "):");
            findings.forEach(f -> sb.append("\n  • ").append(f));
            return sb.toString();
        }
    }

    // ─── Entry point ───────────────────────────────────────────────────────────

    /**
     * Probes all known cloud IMDS providers.
     * Fast-fails if 169.254.169.254:80 is not reachable.
     *
     * @return list of results (one per detected provider), empty if IMDS unreachable
     */
    public static List<MetadataResult> probe() {
        List<MetadataResult> results = new ArrayList<>();
        if (!isReachable(IMDS_IP, 80)) return results;

        MetadataResult aws = probeAWS();
        if (!aws.isEmpty()) results.add(aws);

        MetadataResult gcp = probeGCP();
        if (!gcp.isEmpty()) results.add(gcp);

        MetadataResult azure = probeAzure();
        if (!azure.isEmpty()) results.add(azure);

        MetadataResult doDroplet = probeDigitalOcean();
        if (!doDroplet.isEmpty()) results.add(doDroplet);

        return results;
    }

    // ─── AWS / Alibaba ─────────────────────────────────────────────────────────

    private static MetadataResult probeAWS() {
        List<String> findings = new ArrayList<>();

        String root = get("/latest/meta-data/", null, null);
        if (root == null || root.startsWith("<!")) return new MetadataResult("AWS/Alibaba", findings);

        findings.add("[CRITICAL] AWS IMDS v1 accessible — no hop-limit protection");

        addField(findings, "Instance ID",        get("/latest/meta-data/instance-id",                        null, null));
        addField(findings, "AMI ID",             get("/latest/meta-data/ami-id",                             null, null));
        addField(findings, "Instance type",      get("/latest/meta-data/instance-type",                      null, null));
        addField(findings, "Local IPv4",         get("/latest/meta-data/local-ipv4",                         null, null));
        addField(findings, "Public IPv4",        get("/latest/meta-data/public-ipv4",                        null, null));
        addField(findings, "Hostname",           get("/latest/meta-data/hostname",                           null, null));
        addField(findings, "Avail. zone",        get("/latest/meta-data/placement/availability-zone",        null, null));
        addField(findings, "Region",             get("/latest/meta-data/placement/region",                   null, null));
        addField(findings, "Security groups",    get("/latest/meta-data/security-groups",                    null, null));

        // IAM role credentials (most critical)
        String iamRoles = get("/latest/meta-data/iam/security-credentials/", null, null);
        if (iamRoles != null && !iamRoles.isBlank()) {
            String roleName = iamRoles.lines().findFirst().orElse("").trim();
            findings.add("[CRITICAL] IAM role exposed: " + roleName);
            String creds = get("/latest/meta-data/iam/security-credentials/" + roleName, null, null);
            if (creds != null && creds.contains("AccessKeyId")) {
                String indented = creds.replace("\n", "\n    ");
                findings.add("[CRITICAL] IAM credentials (AccessKeyId/SecretAccessKey) retrieved:\n    " + indented);
            }
        }

        // User-data (startup scripts often contain secrets)
        String userData = get("/latest/user-data", null, null);
        if (userData != null && !userData.isBlank()) {
            findings.add("[WARN] User-data (startup script) exposed:\n    "
                + userData.substring(0, Math.min(userData.length(), 300)).replace("\n", "\n    "));
        }

        return new MetadataResult("AWS/Alibaba", findings);
    }

    // ─── GCP ───────────────────────────────────────────────────────────────────

    private static MetadataResult probeGCP() {
        List<String> findings = new ArrayList<>();

        String root = get("/computeMetadata/v1/", "Metadata-Flavor", "Google");
        if (root == null || root.isBlank()) return new MetadataResult("GCP", findings);

        findings.add("[CRITICAL] GCP IMDS accessible — metadata endpoint exposed");

        addField(findings, "Project ID",     get("/computeMetadata/v1/project/project-id",           "Metadata-Flavor", "Google"));
        addField(findings, "Numeric project",get("/computeMetadata/v1/project/numeric-project-id",    "Metadata-Flavor", "Google"));
        addField(findings, "Instance name",  get("/computeMetadata/v1/instance/name",                 "Metadata-Flavor", "Google"));
        addField(findings, "Zone",           get("/computeMetadata/v1/instance/zone",                 "Metadata-Flavor", "Google"));
        addField(findings, "Machine type",   get("/computeMetadata/v1/instance/machine-type",         "Metadata-Flavor", "Google"));
        addField(findings, "Network ifaces", get("/computeMetadata/v1/instance/network-interfaces/",  "Metadata-Flavor", "Google"));

        // Service account OAuth2 token
        String saList = get("/computeMetadata/v1/instance/service-accounts/", "Metadata-Flavor", "Google");
        if (saList != null && !saList.isBlank()) {
            String sa = saList.lines().findFirst().orElse("").trim();
            findings.add("[CRITICAL] Service account: " + sa);
            if (!sa.isEmpty()) {
                String token = get("/computeMetadata/v1/instance/service-accounts/" + sa + "/token",
                                   "Metadata-Flavor", "Google");
                if (token != null && token.contains("access_token")) {
                    findings.add("[CRITICAL] Service account OAuth2 token (first 100 chars):\n    "
                        + token.substring(0, Math.min(100, token.length())));
                }
            }
        }

        return new MetadataResult("GCP", findings);
    }

    // ─── Azure ─────────────────────────────────────────────────────────────────

    private static MetadataResult probeAzure() {
        List<String> findings = new ArrayList<>();

        String resp = get("/metadata/instance?api-version=2021-02-01&format=text", "Metadata", "true");
        if (resp == null || resp.isBlank() || resp.startsWith("<!"))
            return new MetadataResult("Azure", findings);

        findings.add("[CRITICAL] Azure IMDS accessible — metadata endpoint exposed");

        addField(findings, "Compute info", get("/metadata/instance/compute?api-version=2021-02-01&format=text",  "Metadata", "true"));
        addField(findings, "Network info", get("/metadata/instance/network?api-version=2021-02-01&format=text",   "Metadata", "true"));

        // Managed Identity access token
        String token = get("/metadata/identity/oauth2/token"
                         + "?api-version=2018-02-01"
                         + "&resource=https://management.azure.com/",
                           "Metadata", "true");
        if (token != null && token.contains("access_token")) {
            findings.add("[CRITICAL] Azure Managed Identity access token (first 100 chars):\n    "
                + token.substring(0, Math.min(100, token.length())));
        }

        return new MetadataResult("Azure", findings);
    }

    // ─── DigitalOcean ──────────────────────────────────────────────────────────

    private static MetadataResult probeDigitalOcean() {
        List<String> findings = new ArrayList<>();

        String root = get("/metadata/v1/", null, null);
        if (root == null || root.isBlank() || !root.contains("hostname"))
            return new MetadataResult("DigitalOcean", findings);

        findings.add("[CRITICAL] DigitalOcean Droplet metadata accessible");

        addField(findings, "Hostname",    get("/metadata/v1/hostname",          null, null));
        addField(findings, "Droplet ID",  get("/metadata/v1/id",                null, null));
        addField(findings, "Region",      get("/metadata/v1/region",            null, null));
        addField(findings, "Interfaces",  get("/metadata/v1/interfaces/",       null, null));
        addField(findings, "User-data",   get("/metadata/v1/user-data",         null, null));

        return new MetadataResult("DigitalOcean", findings);
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────

    private static boolean isReachable(String ip, int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(ip, port), TIMEOUT);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Raw HTTP GET via plain socket (avoids JDK HttpURLConnection caching/routing). */
    private static String get(String path, String extraHeader, String extraValue) {
        try (Socket socket = new Socket()) {
            socket.setSoTimeout(TIMEOUT);
            socket.connect(new InetSocketAddress(IMDS_IP, 80), TIMEOUT);

            OutputStream out = socket.getOutputStream();
            StringBuilder req = new StringBuilder();
            req.append("GET ").append(path).append(" HTTP/1.1\r\n")
               .append("Host: ").append(IMDS_IP).append("\r\n");
            if (extraHeader != null)
                req.append(extraHeader).append(": ").append(extraValue).append("\r\n");
            req.append("Connection: close\r\n\r\n");
            out.write(req.toString().getBytes(StandardCharsets.UTF_8));
            out.flush();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

            // Skip HTTP response headers
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) { /* skip */ }

            // Read body up to MAX_BODY chars
            StringBuilder body = new StringBuilder();
            while ((line = reader.readLine()) != null && body.length() < MAX_BODY) {
                body.append(line).append("\n");
            }
            String result = body.toString().trim();
            return result.isEmpty() ? null : result;
        } catch (IOException e) {
            return null;
        }
    }

    private static void addField(List<String> list, String label, String value) {
        if (value != null && !value.isBlank()) {
            int cap = Math.min(value.trim().length(), 200);
            list.add(label + ": " + value.trim().substring(0, cap));
        }
    }
}
