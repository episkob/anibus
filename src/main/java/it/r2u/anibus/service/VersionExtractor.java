package it.r2u.anibus.service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts software version strings from raw service banners.
 */
public class VersionExtractor {

    public static String extract(String banner) {
        if (banner == null || banner.isEmpty()) return "";

        // SSH: SSH-2.0-OpenSSH_8.4p1
        Matcher m = Pattern.compile("SSH-[\\d.]+-([\\w._-]+)").matcher(banner);
        if (m.find()) return m.group(1);

        // Apache / nginx / lighttpd / IIS
        m = Pattern.compile("(?i)(Apache|nginx|lighttpd|IIS)[/ ]?([\\d.]+)").matcher(banner);
        if (m.find()) return m.group(1) + "/" + m.group(2);

        // FTP daemons: ProFTPD 1.3.6 or 220 (vsFTPd 3.0.5)
        m = Pattern.compile("(?i)(ProFTPD|vsFTPd|Pure-FTPd|FileZilla)[/ ]?([\\d.]+)").matcher(banner);
        if (m.find()) return m.group(1) + " " + m.group(2);

        // Mail daemons: Postfix, Exim, Sendmail, Dovecot
        m = Pattern.compile("(?i)(Postfix|Exim|Sendmail|Dovecot)[/ ]?([\\d.]*)").matcher(banner);
        if (m.find()) {
            String ver = m.group(2);
            return m.group(1) + (ver.isEmpty() ? "" : " " + ver);
        }

        // Generic HTTP header: Server: xxx or X-Powered-By: xxx
        m = Pattern.compile("(?i)(?:Server|X-Powered-By):\\s*(.+?)(?:\\s{2}|$)").matcher(banner);
        if (m.find()) return m.group(1).trim();

        return "";
    }
}
