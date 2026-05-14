package it.r2u.anibus.ui;

import java.awt.AWTException;
import java.awt.Image;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.TrayIcon;
import java.awt.TrayIcon.MessageType;
import java.util.logging.Logger;

/**
 * System tray notification service.
 *
 * Shows OS-level balloon/toast notifications when a long-running scan
 * completes. Gracefully no-ops on systems where SystemTray is not supported.
 */
public class NotificationService {

    private static final Logger LOG = Logger.getLogger(NotificationService.class.getName());

    private TrayIcon trayIcon;
    private final boolean supported;

    public NotificationService() {
        if (isLinuxWaylandSession()) {
            supported = false;
            LOG.info("System tray disabled on Linux/Wayland session to avoid GTK runtime warnings");
            return;
        }
        supported = SystemTray.isSupported();
        if (!supported) {
            LOG.info("System tray not supported on this platform — notifications disabled");
            return;
        }
        try {
            // Use a 16×16 blank image as the tray icon (the OS will use a default otherwise)
            Image img = Toolkit.getDefaultToolkit().createImage(
                new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x10, 0x00, 0x10,
                           0x00, (byte)0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x21, (byte)0xF9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x2C, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x00,
                           0x02, 0x02, 0x44, 0x01, 0x00, 0x3B});
            trayIcon = new TrayIcon(img, "Anibus");
            trayIcon.setImageAutoSize(true);
            SystemTray.getSystemTray().add(trayIcon);
        } catch (AWTException | IllegalArgumentException e) {
            LOG.warning(() -> "Failed to install tray icon: " + e.getMessage());
            trayIcon = null;
        }
    }

    /**
     * Shows a notification with caption and body text.
     *
     * @param caption short title (e.g. "Scan Complete")
     * @param message body text
     * @param type    INFO, WARNING or ERROR
     */
    private void notify(String caption, String message, MessageType type) {
        if (!supported || trayIcon == null) return;
        trayIcon.displayMessage(caption, message, type);
    }

    public void notifyInfo(String caption, String message) {
        notify(caption, message, MessageType.INFO);
    }

    public void notifyWarning(String caption, String message) {
        notify(caption, message, MessageType.WARNING);
    }

    public void notifyError(String caption, String message) {
        notify(caption, message, MessageType.ERROR);
    }

    public void shutdown() {
        if (supported && trayIcon != null) {
            try {
                SystemTray.getSystemTray().remove(trayIcon);
            } catch (Exception ignored) {}
        }
    }

    private static boolean isLinuxWaylandSession() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (!os.contains("linux")) {
            return false;
        }
        String sessionType = System.getenv("XDG_SESSION_TYPE");
        return sessionType != null && sessionType.equalsIgnoreCase("wayland");
    }
}
