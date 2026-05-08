package it.r2u.anibus.service.network.proxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Asynchronous proxy harvester.
 *
 * <p>Sources polled (no API keys required, JDK-only):
 * <ol>
 *   <li>ProxyScrape v2 — HTTP list</li>
 *   <li>ProxyScrape v2 — SOCKS5 list</li>
 *   <li>GitHub TheSpeedX/PROXY-List — HTTP</li>
 *   <li>GitHub TheSpeedX/PROXY-List — SOCKS5</li>
 * </ol>
 *
 * <p>All harvested proxies are marked countryCode="XX" and latency=-1.
 * Country resolution is deferred to {@link ReactiveValidator} post-validation
 * (only validated nodes are geo-resolved, keeping ip-api.com within rate limits).
 */
public class ProxyHarvester implements ProxyProvider {

    private static final Logger LOG = Logger.getLogger(ProxyHarvester.class.getName());

    private static final int TIMEOUT_MS = 8_000;

    // ip:port pattern
    private static final Pattern IP_PORT = Pattern.compile(
            "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d{2,5})");

    private static final String[] HTTP_SOURCES = {
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http"
                    + "&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
    };

    private static final String[] SOCKS5_SOURCES = {
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5"
                    + "&timeout=10000&country=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
    };

    @Override
    public Set<ProxyNode> harvest() {
        Set<ProxyNode> nodes = new HashSet<>();

        for (String url : HTTP_SOURCES) {
            nodes.addAll(fetchList(url, ProxyType.HTTP));
        }
        for (String url : SOCKS5_SOURCES) {
            nodes.addAll(fetchList(url, ProxyType.SOCKS5));
        }

        LOG.info(String.format("[Harvester] Collected %d raw proxy candidates", nodes.size()));
        return nodes;
    }

    private Set<ProxyNode> fetchList(String url, ProxyType type) {
        Set<ProxyNode> result = new HashSet<>();
        try {
            String body = httpGet(url);
            if (body == null) return result;

            Matcher m = IP_PORT.matcher(body);
            while (m.find()) {
                String host = m.group(1);
                int port;
                try {
                    port = Integer.parseInt(m.group(2));
                } catch (NumberFormatException e) {
                    continue;
                }
                if (port < 1 || port > 65535) continue;
                result.add(new ProxyNode(host, port, type, "XX", -1L));
            }
        } catch (Exception e) {
            LOG.log(java.util.logging.Level.WARNING, "[Harvester] Failed to fetch {0} — {1}",
                    new Object[]{url, e.getMessage()});
        }
        return result;
    }

    private String httpGet(String url) {
        try {
            URI uri = new URI(url);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "Anibus-Scanner/1.8");

            if (conn.getResponseCode() != 200) {
                conn.disconnect();
                return null;
            }

            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            }
            conn.disconnect();
            return sb.toString();
        } catch (IOException | URISyntaxException e) {
            return null;
        }
    }
}
