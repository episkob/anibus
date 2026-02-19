# Anibus — Port Scanner

A modern, iOS 17-inspired desktop port scanning application built with **JavaFX 22** and **Java 21**.

---

## Features

### Scanning
- Scan any hostname or IP address for open ports
- Configurable port range (e.g. `1-1024`)
- Adjustable thread count (10–500, default 100)
- Per-port **latency measurement** (ms)
- Graceful scan cancellation

### Information Extraction
- Automatic **service detection** for 50+ well-known ports (HTTP, SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kubernetes API, and more)
- **Banner grabbing** — sends HTTP `HEAD` probes on web ports for richer headers
- **Software version extraction** from banners (OpenSSH, Apache, nginx, ProFTPD, Postfix, etc.)
- Protocol & **encryption detection** (TLS, STARTTLS, HTTPS, SMTPS, LDAPS, etc.)

### UI & Workflow
- **Host Information panel** — shows IP, hostname, scan time, ports scanned, open ports count, and average latency (live-updated)
- **7-column results table** — Port, State, Service, Version, Protocol, Latency, Banner
- **Export to CSV** with all columns
- **Clear** results with one click
- **Copy row** or **Copy all** via right-click context menu
- Auto DNS resolution on focus-out
- iOS 17-style design: frosted-glass navbar, gradient buttons, thin scrollbars, rounded cards, color-coded state column

---

## Project Structure

```
src/
└── main/
    ├── java/
    │   ├── module-info.java
    │   └── it/r2u/anibus/
    │       ├── AnibusApplication.java     # JavaFX entry point
    │       ├── AnibusController.java      # UI controller (FXML)
    │       ├── PortScannerService.java    # Scanning, banner grab, version extraction
    │       └── PortScanResult.java        # Data model (7 fields)
    └── resources/
        └── it/r2u/anibus/
            ├── hello-view.fxml            # UI layout
            └── ios-style.css              # iOS 17 stylesheet
```

---

## Requirements

| Tool   | Version |
|--------|---------|
| Java   | 21+     |
| JavaFX | 22.0.1  |
| Maven  | 3.8+    |

---

## Build & Run

```bash
# Clone the repository
git clone https://github.com/your-username/anibus.git
cd anibus

# Run with Maven
./mvnw javafx:run
```

On Windows:

```cmd
mvnw.cmd javafx:run
```

---

## Usage

1. Enter the **target host** (hostname or IP address)
2. Enter the **port range** in the format `start-end` (e.g. `1-1024`)
3. Optionally adjust the **thread count**
4. Click **Start Scan**
5. The **Host Information** card appears with live stats
6. Results populate the table as ports are discovered
7. Click **Stop** to abort the scan at any time
8. Use **Export** to save results as CSV, or **Clear** to reset
9. Right-click any row to copy a single result or all results

---

## Tech Stack

- **Java 21** — language
- **JavaFX 22** — UI framework
- **Maven** — build tool
- **FXML** — declarative UI layout
- **CSS** — iOS 17-style theming

---

## License

MIT License. See `LICENSE` for details.
