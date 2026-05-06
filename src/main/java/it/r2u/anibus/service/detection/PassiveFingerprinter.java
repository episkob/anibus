package it.r2u.anibus.service.detection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive service/OS fingerprinting based on protocol-level behavioral analysis.
 *
 * Unlike plain banner grabbing (which only reads the Server header), this class
 * examines *how* a server behaves:
 *
 *   HTTP ports
 *   ──────────
 *   • Response header ordering   — Apache, nginx, IIS, Tomcat, Node/Express each
 *                                  emit headers in a characteristic sequence.
 *   • ETag format                — Apache uses  "inode-size-mtime" (3 hex segments),
 *                                  nginx uses    "timestamp-size"  (2 hex segments),
 *                                  IIS uses      colon-delimited or uppercase hex.
 *   • Keep-Alive parameters      — Apache emits "timeout=5, max=100"; nginx omits it.
 *   • X-AspNet-Version presence  — unambiguous Windows/IIS indicator.
 *   • X-Powered-By value         — Express, PHP, ASP.NET each leave distinct marks.
 *   • Server header obfuscation  — detected when behavioral signals contradict or
 *                                  are absent in the Server header.
 *
 *   SSH port (22)
 *   ─────────────
 *   • OpenSSH distro suffix      — "Ubuntu-3ubuntu0.1", "Debian-4+deb10u1", etc.
 *   • OpenSSH version era        — maps to probable OS release cycle.
 *   • Dropbear                   — embedded/IoT Linux.
 *   • Cisco SSH string           — IOS/NX-OS.
 *
 *   Other protocols
 *   ───────────────
 *   • vsFTPd / ProFTPD Debian build  — Linux.
 *   • Microsoft FTP Service          — Windows/IIS.
 *   • Postfix ESMTP                  — Linux.
 *   • MySQL/MariaDB build tag        — e.g. "5.7.38-0ubuntu0.18.04.1" leaks distro.
 */
public class PassiveFingerprinter {

    private static final int TIMEOUT = 3000;

    // ─── Public result type ────────────────────────────────────────────────────

    public static class FingerprintResult {
        private final String os;
        private final String server;
        private final int confidence;
        private final List<String> signals;

        public FingerprintResult(String os, String server, int confidence, List<String> signals) {
            this.os         = os;
            this.server     = server;
            this.confidence = confidence;
            this.signals    = signals;
        }

        public String       getOs()         { return os; }
        public String       getServer()     { return server; }
        public int          getConfidence() { return confidence; }
        public List<String> getSignals()    { return signals; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("[FINGERPRINT] Passive Fingerprint:");
            if (os     != null) sb.append("\n  OS: ").append(os)
                                  .append(" (confidence: ").append(confidence).append("%)");
            if (server != null) sb.append("\n  Stack: ").append(server);
            if (!signals.isEmpty()) {
                sb.append("\n  Signals:");
                signals.forEach(s -> sb.append("\n    • ").append(s));
            }
            return sb.toString();
        }
    }

    // ─── Entry point ───────────────────────────────────────────────────────────

    /**
     * Run passive fingerprinting on the given host/port.
     *
     * @param host   target hostname or IP
     * @param port   target port
     * @param banner already-captured raw banner (may be null/empty)
     * @return {@link FingerprintResult}, or {@code null} if no signals found
     */
    public static FingerprintResult fingerprint(String host, int port, String banner) {
        List<String> signals   = new ArrayList<>();
        String osGuess         = null;
        String serverGuess     = null;
        int    confidence      = 0;

        // 1. SSH analysis (works on the banner already captured)
        if (port == 22 || (banner != null && banner.startsWith("SSH-"))) {
            SshResult ssh = analyzeSSHBanner(banner);
            if (ssh != null) {
                if (ssh.os()     != null) { osGuess     = ssh.os();     }
                if (ssh.server() != null) { serverGuess = ssh.server(); }
                confidence = Math.max(confidence, ssh.confidence());
                signals.addAll(ssh.signals());
            }
        }

        // 2. HTTP behavioral analysis (opens its own raw socket)
        boolean isHttp = port == 80 || port == 443 || port == 8080 || port == 8443
                      || port == 8000 || port == 8888 || port == 3000 || port == 5000;
        if (isHttp) {
            HttpResult http = analyzeHttpBehavior(host, port);
            if (http != null) {
                if (http.os() != null && http.confidence() > confidence) {
                    osGuess    = http.os();
                    confidence = http.confidence();
                }
                if (http.server() != null) serverGuess = http.server();
                signals.addAll(http.signals());
            }
        }

        // 3. Generic banner protocol quirks
        if (banner != null && !banner.isEmpty()) {
            GenericResult gr = analyzeBannerQuirks(banner);
            if (gr != null) {
                if (gr.os() != null && gr.confidence() > confidence) {
                    osGuess    = gr.os();
                    confidence = gr.confidence();
                }
                signals.addAll(gr.signals());
            }
        }

        if (signals.isEmpty()) return null;
        return new FingerprintResult(osGuess, serverGuess, confidence, signals);
    }

    // ─── SSH fingerprinting ────────────────────────────────────────────────────

    private record SshResult(String os, String server, int confidence, List<String> signals) {}

    private static SshResult analyzeSSHBanner(String banner) {
        if (banner == null || !banner.startsWith("SSH-")) return null;

        List<String> signals = new ArrayList<>();
        String os            = null;
        int    confidence    = 0;

        // e.g. SSH-2.0-OpenSSH_8.4p1 Ubuntu-3ubuntu0.1
        Matcher m = Pattern.compile("SSH-[\\d.]+-([\\w._-]+)(?:\\s+(.+))?").matcher(banner);
        if (!m.find()) return null;

        String software    = m.group(1);
        String distroHint  = m.groupCount() >= 2 ? m.group(2) : null;

        signals.add("SSH software: " + software);

        // Distro suffix appended by distribution packages
        if (distroHint != null) {
            String d = distroHint.toLowerCase();
            if (d.startsWith("ubuntu")) {
                os = "Ubuntu Linux";  confidence = 90;
                signals.add("SSH distro suffix: " + distroHint + " → Ubuntu");
            } else if (d.startsWith("debian")) {
                os = "Debian Linux";  confidence = 90;
                signals.add("SSH distro suffix: " + distroHint + " → Debian");
            } else if (d.startsWith("freebsd")) {
                os = "FreeBSD";       confidence = 90;
                signals.add("SSH distro suffix: " + distroHint + " → FreeBSD");
            } else if (d.startsWith("alpine")) {
                os = "Alpine Linux";  confidence = 88;
                signals.add("SSH distro suffix: " + distroHint + " → Alpine");
            }
        }

        // OpenSSH version → approximate OS era (fallback when no distro hint)
        if (os == null && software.startsWith("OpenSSH_")) {
            Matcher vm = Pattern.compile("OpenSSH_([\\d.]+)").matcher(software);
            if (vm.find()) {
                try {
                    double ver = Double.parseDouble(vm.group(1));
                    if (ver >= 9.0) {
                        os = "Modern Linux/BSD (2022+)"; confidence = 45;
                        signals.add("OpenSSH " + vm.group(1) + " → post-2022 Linux/BSD");
                    } else if (ver >= 8.0) {
                        os = "Linux/BSD (2019-2022)";    confidence = 40;
                        signals.add("OpenSSH " + vm.group(1) + " → 2019-2022 era");
                    } else if (ver >= 7.4 && ver < 7.9) {
                        os = "Linux (RHEL 7 / CentOS 7 era)"; confidence = 50;
                        signals.add("OpenSSH " + vm.group(1) + " matches RHEL7/CentOS7 stock version");
                    }
                } catch (NumberFormatException ignored) { /* skip */ }
            }
        }

        // Dropbear → embedded Linux
        if (software.toLowerCase().contains("dropbear")) {
            os = "Embedded Linux (router/IoT)"; confidence = 80;
            signals.add("Dropbear SSH → embedded/IoT device");
        }

        // Cisco SSH
        if (software.toLowerCase().contains("cisco")) {
            os = "Cisco IOS/NX-OS"; confidence = 90;
            signals.add("Cisco SSH implementation detected");
        }

        return new SshResult(os, software, confidence, signals);
    }

    // ─── HTTP behavioral fingerprinting ───────────────────────────────────────

    private record HttpResult(String os, String server, int confidence, List<String> signals) {}

    /**
     * Makes a raw HEAD request using a plain socket so that response headers
     * are captured in the exact order the server sends them.
     * (Java's HttpURLConnection sorts headers alphabetically and would destroy
     * the ordering signal.)
     */
    private static HttpResult analyzeHttpBehavior(String host, int port) {
        List<String>              signals       = new ArrayList<>();
        LinkedHashMap<String, String> orderedHdrs = new LinkedHashMap<>();
        List<String>              headerOrder   = new ArrayList<>();

        try (Socket socket = new Socket()) {
            socket.setSoTimeout(TIMEOUT);
            socket.connect(new InetSocketAddress(host, port), TIMEOUT);

            OutputStream out = socket.getOutputStream();
            String req = "HEAD / HTTP/1.1\r\nHost: " + host
                       + "\r\nConnection: close\r\nAccept: */*\r\n\r\n";
            out.write(req.getBytes(StandardCharsets.UTF_8));
            out.flush();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String line;
            boolean statusLine = true;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                if (statusLine) { statusLine = false; continue; }
                int colon = line.indexOf(':');
                if (colon > 0) {
                    String name  = line.substring(0, colon).trim();
                    String value = line.substring(colon + 1).trim();
                    orderedHdrs.put(name.toLowerCase(), value);
                    headerOrder.add(name.toLowerCase());
                }
            }
        } catch (IOException e) {
            return null;
        }

        if (orderedHdrs.isEmpty()) return null;

        String os         = null;
        String server     = null;
        int    confidence = 0;

        // — ETag format —
        String etag = orderedHdrs.get("etag");
        if (etag != null) {
            ETagResult er = analyzeETag(etag);
            if (er != null) {
                if (er.server() != null) server = er.server();
                confidence = Math.max(confidence, er.confidence());
                signals.addAll(er.signals());
            }
        }

        // — Header order fingerprinting —
        String stackFromOrder = inferStackFromHeaderOrder(headerOrder);
        if (stackFromOrder != null) {
            signals.add("Header order pattern → " + stackFromOrder);
            if (server == null) server = stackFromOrder;
            confidence = Math.max(confidence, 55);
        }

        // — X-AspNet-Version (unambiguous Windows/IIS) —
        String aspNet = orderedHdrs.get("x-aspnet-version");
        if (aspNet != null) {
            os     = "Windows (IIS / ASP.NET)";
            server = "IIS + ASP.NET " + aspNet;
            confidence = Math.max(confidence, 90);
            signals.add("X-AspNet-Version: " + aspNet + " → Windows/IIS confirmed");
        }

        // — X-Powered-By —
        String poweredBy = orderedHdrs.get("x-powered-by");
        if (poweredBy != null) {
            signals.add("X-Powered-By: " + poweredBy);
            String pb = poweredBy.toLowerCase();
            if (pb.contains("asp.net")) {
                os = "Windows (IIS)";
                confidence = Math.max(confidence, 85);
            } else if (pb.contains("php")) {
                signals.add("PHP runtime detected → cross-platform (likely Linux)");
            } else if (pb.contains("express")) {
                signals.add("Express.js → Node.js runtime");
                if (server == null) server = "Node.js/Express";
            }
        }

        // — Keep-Alive header —
        String keepAlive = orderedHdrs.get("keep-alive");
        if (keepAlive != null) {
            signals.add("Keep-Alive: " + keepAlive);
            if (keepAlive.contains("timeout=5") && keepAlive.contains("max=100")) {
                signals.add("Keep-Alive params match Apache httpd default");
                if (server == null) server = "Apache httpd (inferred)";
                confidence = Math.max(confidence, 50);
            }
        } else if (orderedHdrs.containsKey("server")) {
            String srv = orderedHdrs.get("server");
            if (srv != null && srv.toLowerCase().contains("nginx")) {
                signals.add("No Keep-Alive header — consistent with nginx default config");
            }
        }

        // — Server header obfuscation detection —
        String serverHeader = orderedHdrs.get("server");
        if (serverHeader == null || serverHeader.isEmpty()) {
            signals.add("Server header absent — deliberately hidden");
            if (server != null) {
                signals.add("Stack inferred from behavioral signals despite hidden Server header");
            }
        } else {
            String sl = serverHeader.toLowerCase();
            boolean declared = sl.contains("apache") || sl.contains("nginx")
                            || sl.contains("iis")    || sl.contains("tomcat")
                            || sl.contains("node")   || sl.contains("express");
            if (!declared && server != null && !server.toLowerCase().contains(sl)) {
                signals.add("Server header obfuscated (\"" + serverHeader
                          + "\") — behavioral analysis suggests: " + server);
            }
        }

        // — OS inference from identified stack —
        if (os == null && server != null) {
            String sl = server.toLowerCase();
            if (sl.contains("iis"))  { os = "Windows"; confidence = Math.max(confidence, 85); }
            else if (sl.contains("apache") || sl.contains("nginx") || sl.contains("lighttpd")) {
                os = "Linux/Unix"; confidence = Math.max(confidence, 45);
            }
        }

        return new HttpResult(os, server, confidence, signals);
    }

    // ─── ETag ─────────────────────────────────────────────────────────────────

    private record ETagResult(String server, int confidence, List<String> signals) {}

    private static ETagResult analyzeETag(String etag) {
        List<String> signals = new ArrayList<>();
        // Strip surrounding quotes and W/ prefix
        String raw = etag.replaceAll("(?i)^W/|^\"|\"$", "").trim();

        // Apache: inode-size-mtime  →  three lowercase hex segments separated by '-'
        if (raw.matches("[0-9a-f]+-[0-9a-f]+-[0-9a-f]+")) {
            signals.add("ETag \"" + raw + "\" — inode-size-mtime format → Apache httpd");
            return new ETagResult("Apache httpd", 70, signals);
        }
        // nginx: timestamp-size  →  two lowercase hex segments
        if (raw.matches("[0-9a-f]+-[0-9a-f]+")) {
            signals.add("ETag \"" + raw + "\" — timestamp-size format → nginx");
            return new ETagResult("nginx", 65, signals);
        }
        // IIS: colon-delimited or all-uppercase hex
        if (raw.contains(":") || raw.matches("[0-9A-F]{8,}")) {
            signals.add("ETag \"" + raw + "\" — format consistent with IIS");
            return new ETagResult("IIS", 50, signals);
        }
        return null;
    }

    // ─── Header order scoring ─────────────────────────────────────────────────

    /**
     * Scores header ordering against known server profiles.
     *
     * Known sequences (simplified):
     *   Apache httpd  — Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, Vary, Keep-Alive, Connection
     *   nginx         — Server, Date, Content-Type, Content-Length, Last-Modified, Connection, ETag, Accept-Ranges
     *   IIS           — Content-Type, Last-Modified, Accept-Ranges, ETag, Server, X-Powered-By, Date, Content-Length
     *   Tomcat        — Server, Content-Type, Transfer-Encoding, Date  (no Content-Length for chunked)
     *   Node/Express  — X-Powered-By at position 0, ETag, Date, Connection
     */
    private static String inferStackFromHeaderOrder(List<String> order) {
        if (order.size() < 3) return null;

        int apache = 0, nginx = 0, iis = 0, node = 0, tomcat = 0;

        // Apache: Date tends to come before or at same position as Server; has last-modified + vary + keep-alive
        if (order.contains("last-modified") && order.contains("vary"))       apache += 2;
        if (order.contains("keep-alive"))                                     apache += 2;
        int dateIdx   = order.indexOf("date");
        int serverIdx = order.indexOf("server");
        if (dateIdx >= 0 && serverIdx >= 0 && dateIdx <= serverIdx)           apache++;

        // nginx: Server is 0 or 1, no keep-alive header
        if (!order.contains("keep-alive"))                                    nginx++;
        if (serverIdx >= 0 && serverIdx <= 1)                                 nginx += 2;
        if (order.contains("last-modified"))                                  nginx++;

        // IIS: x-powered-by, x-aspnet-version, content-type near top
        if (order.contains("x-powered-by"))                                   iis += 2;
        if (order.contains("x-aspnet-version"))                               iis += 3;
        int ctIdx = order.indexOf("content-type");
        if (ctIdx >= 0 && ctIdx <= 1)                                         iis++;

        // Node/Express: x-powered-by at index 0
        if (!order.isEmpty() && "x-powered-by".equals(order.get(0)))         node += 3;

        // Tomcat: transfer-encoding present, content-length absent → chunked
        if (order.contains("transfer-encoding") && !order.contains("content-length")) tomcat += 2;

        int max = Math.max(Math.max(apache, nginx), Math.max(iis, Math.max(node, tomcat)));
        if (max < 2) return null;

        if (max == iis)    return "IIS";
        if (max == apache) return "Apache httpd";
        if (max == nginx)  return "nginx";
        if (max == node)   return "Node.js/Express";
        if (max == tomcat) return "Apache Tomcat";
        return null;
    }

    // ─── Generic banner quirks ─────────────────────────────────────────────────

    private record GenericResult(String os, int confidence, List<String> signals) {}

    private static GenericResult analyzeBannerQuirks(String banner) {
        List<String> signals = new ArrayList<>();
        String os            = null;
        int    confidence    = 0;

        // vsFTPd → Linux
        if (banner.matches("220[- ].*vsFTPd.*")) {
            signals.add("vsFTPd banner → Linux server");
            os = "Linux"; confidence = 70;
        }

        // ProFTPD Debian build
        if (Pattern.compile("ProFTPD.*Debian", Pattern.CASE_INSENSITIVE).matcher(banner).find()) {
            signals.add("ProFTPD Debian build → Debian Linux");
            os = "Debian Linux"; confidence = 80;
        }

        // Microsoft FTP Service → Windows/IIS
        if (banner.contains("Microsoft FTP Service")) {
            signals.add("Microsoft FTP Service banner → Windows/IIS");
            os = "Windows"; confidence = 90;
        }

        // Postfix ESMTP → Linux
        if (banner.matches("220.*ESMTP Postfix.*")) {
            signals.add("Postfix ESMTP banner → Linux");
            os = "Linux"; confidence = 75;
        }

        // Microsoft Exchange
        if (banner.contains("Microsoft ESMTP MAIL Service")) {
            signals.add("Microsoft ESMTP MAIL Service → Windows/Exchange");
            os = "Windows"; confidence = 90;
        }

        // MySQL/MariaDB build tag leaks distro
        // e.g. "5.7.38-0ubuntu0.18.04.1" or "10.5.12-MariaDB-1:10.5.12+maria~buster"
        Matcher m = Pattern.compile("\\d+\\.\\d+\\.\\d+-([\\w.~+:@-]+)").matcher(banner);
        if (m.find()) {
            String buildTag = m.group(1).toLowerCase();
            if (buildTag.contains("ubuntu")) {
                signals.add("MySQL/MariaDB build tag: " + m.group(1) + " → Ubuntu");
                if (os == null) { os = "Ubuntu Linux"; confidence = 85; }
            } else if (buildTag.contains("debian") || buildTag.contains("buster") || buildTag.contains("bullseye")) {
                signals.add("MySQL/MariaDB build tag: " + m.group(1) + " → Debian");
                if (os == null) { os = "Debian Linux"; confidence = 85; }
            } else if (buildTag.contains("fedora") || buildTag.contains("centos") || buildTag.contains("rhel")) {
                signals.add("MySQL/MariaDB build tag: " + m.group(1) + " → RHEL/Fedora family");
                if (os == null) { os = "Linux (RHEL/Fedora)"; confidence = 85; }
            } else if (buildTag.contains("winx64") || buildTag.contains("win64") || buildTag.contains("win32")) {
                signals.add("MySQL/MariaDB Windows build: " + m.group(1));
                if (os == null) { os = "Windows"; confidence = 85; }
            }
        }

        if (signals.isEmpty()) return null;
        return new GenericResult(os, confidence, signals);
    }
}
