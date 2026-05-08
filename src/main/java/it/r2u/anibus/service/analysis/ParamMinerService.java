package it.r2u.anibus.service.analysis;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Param Miner — discovers hidden GET/POST parameters on web endpoints.
 *
 * Strategy:
 * 1. Baseline request (no extra params) — record response length, status code
 *    and a set of stable tokens from the body.
 * 2. For each candidate parameter from the wordlist, send a request with a
 *    canary value (e.g. {@code param=anibus_NONCE}).
 * 3. If the response differs significantly (length Δ > threshold, different
 *    status code, or canary value is reflected), mark the param as "interesting".
 *
 * Only standard Java HTTP (HttpURLConnection) is used — no external deps.
 */
public class ParamMinerService {

    private static final int    TIMEOUT_MS   = 6000;
    private static final int    BATCH_SIZE   = 10;    // params per request
    private static final int    DELTA_BYTES  = 50;    // byte diff to flag
    private static final String CANARY       = "anibus_probe_x7k";

    // ── Common hidden parameter wordlist ──────────────────────────────────
    private static final String[] WORDLIST = {
            // Auth / session
            "token","access_token","auth","api_key","apikey","key","secret",
            "password","pass","pwd","username","user","login","session","sid",
            // Debug / admin
            "debug","test","dev","admin","verbose","trace","log","internal",
            "preview","draft","mode","env","environment","sandbox",
            // Redirect / flow
            "redirect","redirect_uri","return","return_url","next","callback",
            "origin","ref","referrer","continue","from","to","url","link","goto",
            // Versioning / format
            "version","v","format","output","type","lang","locale","currency",
            "page","per_page","limit","offset","count","size","start","end",
            // Feature flags
            "feature","flag","enable","disable","beta","experimental",
            // Cache / timing
            "nocache","cache","ttl","refresh","timestamp","ts","_","cb",
            // Data
            "id","uid","uuid","user_id","account","profile","email","phone",
            "search","q","query","filter","sort","order","fields","include",
            "expand","embed","with","select",
            // HTTP override
            "X-HTTP-Method-Override","_method","method","action",
            // Common hidden params
            "source","utm_source","utm_medium","campaign",
            "role","group","permission","scope","grant",
            "force","override","bypass","skip","ignore",
            "file","path","dir","folder","filename","download","export",
            "host","server","backend","endpoint","service","region",
            "tags","label","category","status","state"
    };

    public enum ParamType { GET, POST }

    public record ParamFinding(
            String paramName,
            ParamType paramType,
            String url,
            String evidence,   // e.g. "reflected", "length delta", "status change"
            int    baseStatus,
            int    probeStatus,
            int    baseLenBytes,
            int    probeLenBytes
    ) {
        public boolean isReflected() { return evidence.contains("reflected"); }
    }

    /**
     * Mine a URL for hidden GET and POST parameters.
     *
     * @param targetUrl        full URL to test (e.g. "https://example.com/api/data")
     * @param testPost         also test as POST body
     * @param progressCallback receives [0..1]; may be null
     * @return list of interesting parameters found
     */
    public List<ParamFinding> mine(String targetUrl,
                                   boolean testPost,
                                   Consumer<Double> progressCallback) {
        List<ParamFinding> findings = new ArrayList<>();

        // ── Baseline ─────────────────────────────────────────────────────
        Response baseline = sendGet(targetUrl, "");
        if (baseline == null) return findings;

        int totalSteps = (int) Math.ceil(WORDLIST.length / (double) BATCH_SIZE)
                * (testPost ? 2 : 1);
        int step = 0;

        // ── GET probing in batches ────────────────────────────────────────
        for (int i = 0; i < WORDLIST.length; i += BATCH_SIZE) {
            String[] batch = slice(WORDLIST, i, Math.min(i + BATCH_SIZE, WORDLIST.length));
            String qs = buildQueryString(batch);
            Response probe = sendGet(targetUrl, qs);
            if (probe != null) {
                for (String param : batch) {
                    ParamFinding f = evaluate(param, ParamType.GET, targetUrl,
                            baseline, probe);
                    if (f != null) findings.add(f);
                }
            }
            if (progressCallback != null)
                progressCallback.accept((double) ++step / totalSteps);
        }

        // ── POST probing ──────────────────────────────────────────────────
        if (testPost) {
            for (int i = 0; i < WORDLIST.length; i += BATCH_SIZE) {
                String[] batch = slice(WORDLIST, i, Math.min(i + BATCH_SIZE, WORDLIST.length));
                String body = buildQueryString(batch);
                Response probe = sendPost(targetUrl, body);
                if (probe != null) {
                    for (String param : batch) {
                        ParamFinding f = evaluate(param, ParamType.POST, targetUrl,
                                baseline, probe);
                        if (f != null) findings.add(f);
                    }
                }
                if (progressCallback != null)
                    progressCallback.accept((double) ++step / totalSteps);
            }
        }

        return findings;
    }

    // ── Evaluation ───────────────────────────────────────────────────────

    private ParamFinding evaluate(String param, ParamType type,
                                   String url, Response base, Response probe) {
        if (probe == null) return null;
        List<String> evidences = new ArrayList<>();

        if (probe.status != base.status)
            evidences.add("status change " + base.status + "→" + probe.status);

        int delta = Math.abs(probe.bodyLen - base.bodyLen);
        if (delta > DELTA_BYTES)
            evidences.add("length delta +" + delta + "B");

        if (probe.body.contains(CANARY))
            evidences.add("reflected");

        if (evidences.isEmpty()) return null;

        return new ParamFinding(param, type, url, String.join(", ", evidences),
                base.status, probe.status, base.bodyLen, probe.bodyLen);
    }

    // ── HTTP ──────────────────────────────────────────────────────────────

    private Response sendGet(String url, String extraQuery) {
        try {
            String full = extraQuery.isBlank() ? url
                    : (url.contains("?") ? url + "&" : url + "?") + extraQuery;
            HttpURLConnection c = open(full, "GET");
            return read(c);
        } catch (IOException e) { return null; }
    }

    private Response sendPost(String url, String body) {
        try {
            HttpURLConnection c = open(url, "POST");
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            try (OutputStream os = c.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
            return read(c);
        } catch (IOException e) { return null; }
    }

    private HttpURLConnection open(String url, String method) throws IOException {
        HttpURLConnection c = (HttpURLConnection) URI.create(url).toURL().openConnection();
        c.setRequestMethod(method);
        c.setConnectTimeout(TIMEOUT_MS);
        c.setReadTimeout(TIMEOUT_MS);
        c.setInstanceFollowRedirects(false);
        c.setRequestProperty("User-Agent", "Anibus/1.8.0");
        return c;
    }

    private Response read(HttpURLConnection c) {
        try {
            int status = c.getResponseCode();
            var in = (status >= 400) ? c.getErrorStream() : c.getInputStream();
            String body = in != null
                    ? new String(in.readNBytes(64 * 1024), StandardCharsets.UTF_8)
                    : "";
            return new Response(status, body.length(), body);
        } catch (IOException e) { return null; }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private String buildQueryString(String[] params) {
        StringBuilder sb = new StringBuilder();
        for (String p : params) {
            if (!sb.isEmpty()) sb.append("&");
            sb.append(uriEncode(p)).append("=").append(CANARY);
        }
        return sb.toString();
    }

    private String[] slice(String[] arr, int from, int to) {
        String[] out = new String[to - from];
        System.arraycopy(arr, from, out, 0, out.length);
        return out;
    }

    private String uriEncode(String s) {
        try {
            return java.net.URLEncoder.encode(s, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) { return s; }
    }

    private record Response(int status, int bodyLen, String body) {}

    // ── Report ────────────────────────────────────────────────────────────

    public static String formatReport(List<ParamFinding> findings, String url) {
        if (findings.isEmpty())
            return "Param Miner: no interesting parameters found on " + url;
        StringBuilder sb = new StringBuilder();
        sb.append("=== Param Miner Results: ").append(url).append(" ===\n\n");
        sb.append(String.format("%-30s  %-5s  %-10s  %s%n",
                "Parameter", "Type", "Status", "Evidence"));
        sb.append("─".repeat(80)).append("\n");
        for (ParamFinding f : findings) {
            sb.append(String.format("%-30s  %-5s  %3d→%-5d  %s%n",
                    f.paramName(), f.paramType(),
                    f.baseStatus(), f.probeStatus(), f.evidence()));
        }
        long reflected = findings.stream().filter(ParamFinding::isReflected).count();
        if (reflected > 0)
            sb.append("\n⚠ ").append(reflected).append(" reflected param(s) — potential XSS/SSRF vector\n");
        return sb.toString();
    }
}
