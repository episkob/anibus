# Anibus — Advanced Port Scanner

A modern desktop port scanning application with enhanced security analysis, built with **Anibus Design System**, **JavaFX 21.0.5** and **Java 21**.

> **Version:** 1.3.0 · **Author:** Iaroslav Tsymbaliuk · **Position:** Intern (2025–2026) @ r2u

---

## Features

### Core Scanning
- Scan any hostname or IP address for open ports
- Configurable port range (e.g. `1-65535`)
- Adjustable thread count (10–500, default 10)
- Per-port **latency measurement** (ms)
- Graceful scan cancellation with SOLID architecture

### Enhanced Service Detection
- Two scan modes: **Fast Port Scan** and **Service Detection**
- **Advanced service fingerprinting** for 100+ services (HTTP, SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kubernetes API, Jenkins, and more)
- **Banner grabbing** with protocol-specific probes (HTTP HEAD, SSH greeting, SMTP, FTP, MySQL handshake)
- **Software version extraction** from banners (OpenSSH, Apache, nginx, ProFTPD, Postfix, etc.)
- **Operating system detection** via TCP fingerprinting and banner analysis
- **Vulnerability scanning** with CVE database matching (HIGH/MEDIUM/CRITICAL severity levels)
- **Geolocation services** — IP location, ISP, ASN, cloud provider detection
- **SSL/TLS certificate analysis** — expiration dates, self-signed detection, certificate details

### Security Analysis
- **Keycloak IAM detection** — automatically detects Keycloak servers on `/auth/`, `/keycloak/`, custom paths
- **Cryptographic key extraction** — finds exposed public/private keys and client secrets
- **Multi-realm support** — detects `master` and custom realms
- **Security headers analysis** — Content Security Policy, HSTS, X-Frame-Options, etc.
- **HTTP technology detection** — CMS identification (WordPress, Drupal, Magento), web servers, frameworks
- **IoT device detection** — IP cameras, DVRs, routers with default credential warnings

### Information Extraction
- **Web source code analysis** — detects leaked credentials, API keys, configuration files
- **Cloud service detection** — Cloudflare, AWS, Azure, Akamai, WAF/CDN identification  
- **Software stack analysis** — Kubernetes, Docker, Jenkins CI/CD, HashiCorp tools

### UI & Workflow
- **Dark theme** — complete dark mode design with optimized contrast and readability
- **Console view** — toggle between table and terminal-style console output with formatted results
- **SSL/TLS detection** — automatic HTTPS support check when resolving hosts (displays checkmark/X indicator)
- **Smart URL handling** — auto-removes http:// and https:// prefixes, extracts hostname from full URLs
- **Network status indicator** — live connection status in the status bar ([ONLINE], [LOCAL], [OFFLINE]), polled every 5 seconds
- **Host Information panel** — shows IP, hostname, scan time, ports scanned, open ports count, and average latency (live-updated)
- **Export to CSV or XML** with all columns and enhanced service detection data
- **Clear** results with one click
- **Copy row** or **Copy all** via right-click context menu
- **Copy IP address** from resolved host label via right-click
- Auto DNS resolution on focus-out
- **Anibus Design System**: frosted-glass navbar, gradient buttons, thin scrollbars, rounded cards, color-coded state column
- **Text-based output** — clean ASCII formatting for universal console compatibility

---

## Project Structure

```
src/
└── main/
    ├── java/
    │   ├── module-info.java
    │   └── it/r2u/anibus/
    │       ├── AnibusApplication.java          # JavaFX entry point
    │       ├── AnibusController.java           # UI controller (SOLID-refactored, lean & focused)
    │       │
    │       ├── coordinator/                     # Scan orchestration (Strategy & Facade patterns)
    │       │   ├── ScanStrategy.java            # Strategy interface for scan types
    │       │   ├── ScanContext.java             # Builder pattern for scan parameters
    │       │   ├── ScanCoordinator.java         # Facade for managing strategies
    │       │   ├── StandardScanStrategy.java    # Fast TCP port scanning strategy
    │       │   └── ServiceDetectionStrategy.java # Enhanced service fingerprinting strategy
    │       │
    │       ├── handlers/                        # Command pattern action handlers
    │       │   ├── ScanActionHandler.java       # Scan lifecycle & UI updates
    │       │   ├── ClipboardActionHandler.java  # Clipboard operations
    │       │   ├── ExportActionHandler.java     # Export functionality
    │       │   └── TracerouteActionHandler.java # Network path tracing
    │       │
    │       ├── model/
    │       │   ├── PortScanResult.java          # Data model (7 fields)
    │       │   └── PortRegistry.java            # Service name & protocol/encryption lookup tables
    │       │
    │       ├── network/
    │       │   ├── HostResolver.java            # DNS resolution & SSL detection
    │       │   └── NetworkStatusMonitor.java    # Network connectivity monitoring
    │       │
    │       ├── service/
    │       │   ├── PortScannerService.java      # Core scanning logic
    │       │   ├── ScanTask.java                # Background Task<Void> with callbacks
    │       │   ├── ServiceDetectionTask.java    # Enhanced detection task
    │       │   ├── EnhancedServiceDetector.java # Deep service fingerprinting
    │       │   ├── BannerGrabber.java           # HTTP HEAD / raw greeting banner grabber
    │       │   ├── VersionExtractor.java        # Regex-based version extraction
    │       │   ├── ExportService.java           # CSV and XML export
    │       │   ├── OSDetector.java              # Operating system detection
    │       │   ├── VulnerabilityScanner.java    # CVE database matching
    │       │   ├── GeolocationService.java      # IP geolocation via ip-api.com
    │       │   ├── HTTPAnalyzer.java            # SSL certs, security headers, CMS detection
    │       │   ├── TracerouteService.java       # Network path tracing
    │       │   ├── IoTDetector.java             # IP camera & IoT device detection
    │       │   ├── KeycloakDetector.java        # Keycloak IAM detection & key extraction
    │       │   └── SoftwareStackDetector.java   # Technology stack analysis
    │       │
    │       └── ui/
    │           ├── AlertHelper.java             # Anibus design modal alert dialogs
    │           ├── ClipboardService.java        # Clipboard copy utilities
    │           ├── ConsoleViewManager.java      # Console output management
    │           ├── InfoCardManager.java         # Host info panel management
    │           └── TableConfigurator.java       # TableView column setup
    │
    └── resources/
        └── it/r2u/anibus/
            ├── hello-view.fxml                  # UI layout
            ├── anibus-style.css                 # Anibus Design System stylesheet
            └── app.properties                   # Maven-filtered runtime version
```

---

## Requirements

| Tool   | Version |
|--------|---------|
| Java   | 21+     |
| JavaFX | 21.0.5  |
| Maven  | 3.8+    |

---

## Build & Run

```bash
# Clone the repository
git clone https://github.com/episkob/anibus.git
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

1. **Select scan mode** - Choose between **Fast Port Scan** (basic connectivity) or **Service Detection** (comprehensive analysis)
2. Enter the **target host** (hostname or IP address)
3. Enter the **port range** in the format `start-end` (e.g. `1-65535` or `80,443`)
4. Optionally adjust the **thread count** (higher = faster, but more aggressive)
5. Click **Start Scan**
6. The **Host Information** card appears with live scan statistics
7. Results populate the table as ports are discovered
8. With **Service Detection**, see enhanced data: OS detection, vulnerabilities, geolocation, Keycloak analysis
9. Click **Stop** to abort the scan at any time
10. Use **Export** to save results as **CSV or XML** with full analysis data, or **Clear** to reset
11. Right-click any row to copy results or IP addresses

---

## Tech Stack

- **Java 21** — language
- **JavaFX 21.0.5** — UI framework
- **Maven** — build tool
- **FXML** — declarative UI layout
- **CSS** — Anibus Design System theming

---

## License

MIT License. See `LICENSE` for details.
