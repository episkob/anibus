# Anibus — Advanced Network Security Scanner

> **Version:** 1.7.1 · **Author:** Iaroslav Tsymbaliuk · **Position:** Intern (2025–2026) @ r2u

A full-featured desktop network security scanner built with **Java 21 (JPMS)**, **JavaFX 21.0.5**, and a custom **Bootstrap 5 Dark** CSS theme.
Anibus goes far beyond a simple port scanner — it combines service fingerprinting, CVE matching, JavaScript source analysis, SQL injection testing, geolocation, SSL/TLS inspection and infrastructure detection into a single self-contained desktop application.

---

## Table of Contents

- [What's New in 1.7.1](#whats-new-in-170)
- [Feature Overview](#feature-overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Design Patterns](#design-patterns)
- [UI Layout](#ui-layout)
- [Tech Stack](#tech-stack)
- [Requirements](#requirements)
- [Build & Run](#build--run)
- [Usage Guide](#usage-guide)
- [Testing](#testing)
- [Export Formats](#export-formats)
- [License](#license)

---

## What's New in 1.7.1

| Area | Change |
|------|--------|
| Architecture | Service layer reorganised into 6 focused subpackages |
| Model | `LeakInfo` moved to top-level `model/` as an immutable class |
| DI | Constructor injection throughout — zero DI frameworks |
| UI | Full sidebar + TabPane redesign |
| Theme | Complete Bootstrap 5 Dark CSS rewrite |
| Leak detection | Sensitive data exclusively in JS Analysis tab (not in scan banners) |
| Tests | 49 JUnit 5 unit tests |
| Language | English-only interface |
| Export | JS Analysis now exports to CSV or XML (same flow as port scan) |

---

## Feature Overview

### Port Scanning
- Scan any hostname, IP or URL
- Configurable port range (`1-65535`) and thread count (default: 10 virtual threads)
- Per-port latency measurement in milliseconds
- Real-time progress bar and live statistics
- Graceful cancellation at any point

### Enhanced Service Detection

Anibus uses multi-layer banner analysis and protocol-specific probes to identify services accurately:

| Layer | What it does |
|-------|-------------|
| Banner grabbing | HTTP HEAD, SSH greeting, SMTP EHLO, FTP, MySQL handshake |
| Version extraction | Parses `Server:` headers, SSH banners, Redis `INFO`, FTP greeting |
| OS detection | TCP fingerprinting + banner heuristics |
| CVE matching | Matches extracted versions against an embedded vulnerability database |
| Geolocation | IP → location, ISP, ASN, cloud provider (ip-api.com) |
| SSL/TLS | Expiry date, issuer, self-signed certificate detection |

Supported services: HTTP/HTTPS, SSH, FTP, SMTP, DNS, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kibana, Kubernetes API, Jenkins, Grafana, Prometheus, RabbitMQ, Kafka, ZooKeeper, LDAP, Memcached, Cassandra, CouchDB, Neo4j, InfluxDB, Splunk, Vault, Consul, Etcd, and many more.

### Security Analysis

| Feature | Description |
|---------|-------------|
| **Keycloak IAM** | Detects Keycloak realms, extracts exposed crypto keys and client secrets |
| **Security headers** | Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy |
| **CMS detection** | WordPress, Drupal, Magento, Joomla, 1C-Bitrix — version fingerprinting |
| **IoT devices** | IP cameras, DVR/NVR, routers — warns about default credentials |
| **Container detection** | Docker API, Kubernetes API, Rancher, Portainer |
| **Cloud metadata** | Probes AWS/GCP/Azure instance metadata endpoints |

### JavaScript Security Analysis (JS Analysis tab)

Fetches and parses JS source files from the target, including Webpack/Vite/Rollup hashed bundles discovered through HTML:

| Analysis | Details |
|----------|---------|
| **API endpoint mapping** | REST/GraphQL endpoints, HTTP methods, URL templates from JS bundles |
| **DB credential extraction** | Connection strings for 30+ engines: MongoDB, MySQL, PostgreSQL, Redis, Elasticsearch, Cassandra, Neo4j, InfluxDB, RabbitMQ, DynamoDB, Supabase, PlanetScale, and more |
| **Database schema inference** | Tables, columns, relationships inferred from ORM/query patterns |
| **Infrastructure detection** | Docker, Kubernetes, AWS/GCP/Azure, Nginx, Traefik, Cloudflare, Fastly with confidence scores |
| **Framework detection** | React, Vue, Angular, Next.js, Nuxt.js, SvelteKit, Remix, Astro, Gatsby, Alpine.js, Solid.js, Qwik, and 20+ more |
| **Sensitive info detection** | API keys, secret tokens, private keys, JWT secrets, OAuth credentials |

Results are shown as an expandable **TreeView** categorised by finding type.

### SQL Injection Testing

- **110+ payloads** across 12 categories:
  - Error-based, UNION-based, time-based (sleep/benchmark), boolean-based
  - Auth-bypass, stacked queries, NoSQL, XPath, LDAP injection
  - Encoding evasion (URL, hex, double-URL, Unicode, mixed-case)
- **CMS-specific profiles**: WordPress (`wp-login.php`, `xmlrpc.php`), Joomla, Drupal, Magento, 1C-Bitrix, OpenCart, PrestaShop, ModX, Shopify
- **Automatic form discovery**: parses `<form>`, `<input>`, `<select>`, `<textarea>`
- **Response analysis**: detects SQL errors from MySQL, PostgreSQL, MSSQL, SQLite, Oracle, MongoDB, and time-based delays

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AnibusController                      │
│         (JavaFX FXML controller, UI thread only)         │
└───────┬─────────────────────────────────┬───────────────┘
        │                                 │
        ▼                                 ▼
┌───────────────┐                ┌────────────────────┐
│ ScanCoordinator│               │  Action Handlers   │
│ Strategy+Facade│               │ ScanActionHandler  │
│               │                │ ExportActionHandler│
│  ScanContext  │                │ ClipboardHandler   │
│  ScanStrategy │                └────────────────────┘
└───────┬───────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│                Service Layer                 │
│                                             │
│  service/core/        service/detection/    │
│  PortScannerService   EnhancedServiceDet.   │
│  BannerGrabber        OSDetector            │
│  HTTPAnalyzer         IoTDetector           │
│  VulnScanner          KeycloakDetector      │
│                       SoftwareStackDet.     │
│                       ContainerDetector     │
│                                             │
│  service/analysis/    service/network/      │
│  JSSecurityAnalyzer   SubnetScanner         │
│  JSDatabaseAnalyzer   TracerouteService     │
│  WebSourceAnalyzer    ReverseDnsExpander    │
│  SQLInjectionAnalyzer CloudMetadataProbe    │
│                                             │
│  service/export/      service/geo/          │
│  ExportService        GeolocationService    │
└─────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│                  Model Layer                 │
│  LeakInfo · PortScanResult · PortRegistry   │
│  JavaScriptAnalysisResult · EndpointInfo    │
│  DatabaseSchemaInfo · DataStructureInfo     │
│  ArchitectureInfo                           │
└─────────────────────────────────────────────┘
```

### Data Flow

1. User enters target + options → **ScanCoordinator** creates a `ScanContext`
2. **PortScannerService** spawns virtual thread tasks per port chunk
3. Each open port → **EnhancedServiceDetector** → banner → version → CVE check
4. **GeolocationService** resolves IP metadata in parallel
5. JS Analysis enabled → **JavaScriptSecurityAnalyzer** fetches and parses JS bundles
6. SQL Injection enabled → **SQLInjectionAnalyzer** discovers forms and probes them
7. Results stream back via `Platform.runLater()` — UI updates are always on the JavaFX thread
8. **ExportService** / **ExportActionHandler** write CSV or XML on demand

---

## Project Structure

```
src/main/java/it/r2u/anibus/
├── AnibusApplication.java               # JavaFX Application entry point
├── AnibusController.java                # Main FXML controller
│
├── coordinator/
│   ├── ScanCoordinator.java             # Orchestrates full scan pipeline
│   ├── ScanContext.java                 # Mutable scan state container
│   ├── ScanStrategy.java               # Strategy interface
│   ├── StandardScanStrategy.java       # Default scan flow
│   └── ServiceDetectionStrategy.java   # Detection-focused flow
│
├── handlers/                            # Command pattern — one class per UI action
│   ├── ScanActionHandler.java
│   ├── ExportActionHandler.java         # CSV/XML export for port scan + JS analysis
│   ├── ClipboardActionHandler.java
│   └── TracerouteActionHandler.java
│
├── model/                               # Immutable data classes
│   ├── LeakInfo.java                   # Sensitive info record + priority inference
│   ├── PortScanResult.java
│   ├── PortRegistry.java               # Known port/service name map (1000+ entries)
│   ├── JavaScriptAnalysisResult.java
│   ├── EndpointInfo.java
│   ├── DatabaseSchemaInfo.java
│   ├── DataStructureInfo.java
│   └── ArchitectureInfo.java
│
├── network/
│   ├── HostResolver.java               # DNS resolution + URL normalisation
│   └── NetworkStatusMonitor.java       # Periodic connectivity check
│
├── service/
│   ├── analysis/
│   │   ├── JavaScriptSecurityAnalyzer.java    # JS bundle fetcher + analysis orchestrator
│   │   ├── JavaScriptDatabaseAnalyzer.java    # DB credential + schema detection
│   │   ├── WebSourceAnalyzer.java             # HTML/JS source parser
│   │   └── SQLInjectionAnalyzer.java          # Form discovery + payload injection
│   │
│   ├── core/
│   │   ├── PortScannerService.java            # Virtual-thread port scanner
│   │   ├── ScanTask.java                      # Per-port Callable
│   │   ├── ServiceDetectionTask.java          # Post-scan deep detection
│   │   ├── BannerGrabber.java                 # Raw banner acquisition
│   │   ├── HTTPAnalyzer.java                  # HTTP-layer analysis
│   │   └── VulnerabilityScanner.java          # CVE matching engine
│   │
│   ├── detection/
│   │   ├── EnhancedServiceDetector.java       # Main detection dispatcher
│   │   ├── OSDetector.java                    # OS fingerprinting
│   │   ├── PassiveFingerprinter.java          # Passive traffic analysis
│   │   ├── IoTDetector.java                   # Camera/DVR/router detection
│   │   ├── KeycloakDetector.java              # Keycloak realm scraper
│   │   ├── SoftwareStackDetector.java         # CMS/framework identification
│   │   └── ContainerDetector.java             # Docker/Kubernetes detection
│   │
│   ├── export/
│   │   └── ExportService.java                 # Port scan CSV/XML writer
│   │
│   ├── geo/
│   │   └── GeolocationService.java            # ip-api.com integration
│   │
│   └── network/
│       ├── SubnetScanner.java                 # CIDR range expansion
│       ├── TracerouteService.java             # ICMP/TCP traceroute
│       ├── ReverseDnsExpander.java            # PTR record lookup
│       ├── CloudMetadataProbe.java            # AWS/GCP/Azure IMDS probe
│       └── VersionExtractor.java             # Regex-based version parsing
│
└── ui/
    ├── AlertHelper.java
    ├── ClipboardService.java
    ├── ConsoleViewManager.java
    ├── InfoCardManager.java
    └── TableConfigurator.java

src/main/resources/it/r2u/anibus/
├── hello-view.fxml                            # Full UI layout (sidebar + TabPane)
├── anibus-style.css                           # Bootstrap 5 Dark custom theme
└── logging.properties

src/test/java/it/r2u/anibus/
├── service/core/PortScannerServiceTest.java         # 9 tests
├── model/LeakInfoTest.java                          # 22 tests
├── service/analysis/WebSourceAnalyzerTest.java      # 8 tests
├── service/WebSourceAnalyzerLeakInfoTest.java       # 3 tests
└── service/JavaScriptSecurityAnalyzerServiceInferenceTest.java  # 7 tests
```

---

## Design Patterns

| Pattern | Where used | Why |
|---------|-----------|-----|
| **Strategy** | `ScanStrategy` / `ScanCoordinator` | Swap scan algorithm without changing the controller |
| **Command** | `*ActionHandler` classes | Decouple UI actions from business logic; one class = one responsibility |
| **Facade** | `ScanCoordinator` | Single entry point for a complex multi-service scan pipeline |
| **Builder** | `JavaScriptAnalysisResult` | Collect async results incrementally |
| **Constructor Injection** | All services | Explicit dependencies, testable, JPMS-safe, zero framework overhead |
| **Observer** | `Platform.runLater()`, `Task<>` | Thread-safe UI updates from background scan threads |

### Why no DI framework?

Java 21 JPMS conflicts with most DI frameworks (Spring, Guice) because they rely on deep reflection across module boundaries. Constructor injection provides the same decoupling with zero framework overhead and full JPMS compliance.

### Why virtual threads?

Port scanning is purely I/O-bound. Java 21 virtual threads (`Executors.newVirtualThreadPerTaskExecutor()`) allow hundreds of concurrent socket connections with negligible memory overhead — no reactive programming complexity required.

---

## UI Layout

```
┌──────────────────────────────── Anibus 1.7.1 ─────────────────────────────────┐
│ [●] Anibus  ░░░░░░░░░░░░░░░░░░░░░░░░░░  ● Connected  192.168.1.1              │  ← Nav bar
│───────────────────────────────────────────────────────────────────────────────│
│ ┌── Scan Target ───────────────┐  ┌── [Scan Results] [JS Analysis] ──────────┐│
│ │ Host: [example.com_______]   │  │  Scan Results               [Export][Clear]││
│ │ Ports:[1-1024] Threads:[10]  │  │ ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  ││
│ │ ☑ JavaScript Analysis        │  │  ╔══ PORT 22 — SSH ═════════════════╗   ││
│ │ ☑ SQL Injection Testing      │  │  ║ OpenSSH 8.9p1 Ubuntu            ║   ││
│ │ [▶ Start Scan       ] [Stop] │  │  ║ CVE-2023-38408  HIGH            ║   ││
│ │ ████████████░░░░░  67%       │  │  ╚══════════════════════════════════╝   ││
│ └──────────────────────────────┘  │  ╔══ PORT 80 — HTTP ════════════════╗  ││
│ ┌── Host Info ─────────────────┐  │  ║ nginx/1.24.0  WordPress 6.4.2   ║  ││
│ │ IP                           │  │  ╚══════════════════════════════════╝  ││
│ │ 93.184.216.34                │  └────────────────────────────────────────┘│
│ │ Hostname                     │                                             │
│ │ example.com                  │                                             │
│ │ Scan Time    │ Ports Scanned │                                             │
│ │ 4.2s         │ 1024          │                                             │
│ │ Open Ports   │ Avg Latency   │                                             │
│ │ 3            │ 12ms          │                                             │
│ └──────────────────────────────┘                                             │
│───────────────────────────────────────────────────────────────────────────────│
│ ● Scan complete — 3 open ports found                                           │  ← Status bar
└───────────────────────────────────────────────────────────────────────────────┘
```

**Left panel (300 px):**
- **Scan Target card** — host input with live DNS resolution, port range, thread spinner, two checkboxes, Start/Stop buttons, progress bar
- **Host Info card** — appears after scan; IP and hostname (text-wrapping), 2-column grid for Scan Time / Ports Scanned / Open Ports / Avg Latency

**Right panel (flexible):**
- **Scan Results tab** — monospace dark console with formatted ASCII service banners
- **JS Analysis tab** — stats bar + expandable TreeView of findings + Export button

---

## Tech Stack

| Technology | Version | Role |
|-----------|---------|------|
| Java | 21 (LTS) | Language, JPMS module system, virtual threads |
| JavaFX | 21.0.5 | UI framework (FXML + CSS) |
| Bootstrap 5 Dark (CSS) | Custom port | Visual design system |
| Maven Shade Plugin | 3.5.0 | Fat JAR with bundled JavaFX natives |
| JUnit 5 | 5.10.2 | Unit testing |
| junit-jupiter-params | 5.10.2 | Parameterised tests |

---

## Requirements

| Tool | Version | Notes |
|------|---------|-------|
| Java | **21+** | LTS recommended |
| Maven | 3.8+ | Or use included `./mvnw` wrapper |
| JavaFX | — | Bundled in the fat JAR — no separate install |
| OS | Linux / Windows / macOS | All platforms |

---

## Build & Run

**Clone and run directly:**

```bash
git clone https://github.com/episkob/anibus.git
cd anibus
./mvnw javafx:run
```

**Build the fat JAR:**

```bash
./mvnw clean package -DskipTests
java -jar target/anibus-1.7.1.jar
```

**Windows:**

```cmd
mvnw.cmd clean package -DskipTests
java -jar target\anibus-1.7.1.jar
```

**Linux — Wayland / XWayland:**

```bash
xhost +local:
DISPLAY=:0 java -jar target/anibus-1.7.1.jar
```

**From a Flatpak VS Code terminal:**

```bash
flatpak-spawn --host xhost +local:
DISPLAY=:0 java -jar target/anibus-1.7.1.jar
```

---

## Usage Guide

### 1 — Enter a target

Type a hostname, IP address or full URL. DNS resolves automatically when you leave the field. An SSL indicator appears if port 443 responds.

### 2 — Configure options

| Setting | Description |
|---------|-------------|
| **Ports** | Range like `1-1024` or comma list `22,80,443,8080` |
| **Threads** | Concurrent connections (1–200, default 10) |
| **JavaScript Analysis** | Fetch and parse JS bundles for secrets and endpoints |
| **SQL Injection Testing** | Auto-discover forms and probe with 110+ payloads |

### 3 — Run the scan

Click **▶ Start Scan**. Progress bar and status bar update live.

### 4 — Read scan results

The **Scan Results** tab shows formatted service banners: version, OS hint, CVE warnings, geolocation, SSL details.

### 5 — Check JS Analysis

Switch to **JS Analysis** tab to see: API endpoints, sensitive credentials, DB schemas, data structures, infrastructure and framework detection.

### 6 — Export

Both tabs have an independent **Export** button that opens a format dialog:
- **CSV** — human-readable spreadsheet-compatible format
- **XML** — structured, machine-parseable format

---

## Testing

```bash
./mvnw test
```

| Test class | Tests | Covers |
|-----------|-------|--------|
| `PortScannerServiceTest` | 9 | Port range parsing, thread safety, null inputs |
| `LeakInfoTest` | 22 | Priority inference, placeholder detection, builder |
| `WebSourceAnalyzerTest` | 8 | JS source parsing, endpoint extraction |
| `WebSourceAnalyzerLeakInfoTest` | 3 | LeakInfo integration |
| `JavaScriptSecurityAnalyzerServiceInferenceTest` | 7 | DB engine and framework detection |
| **Total** | **49** | |

---

## Export Formats

### Port Scan — CSV
```
Port,Protocol,Service,State,Banner,Version,Latency(ms),CVE,Severity
22,TCP,SSH,OPEN,OpenSSH 8.9p1,8.9p1,8,CVE-2023-38408,HIGH
80,TCP,HTTP,OPEN,nginx/1.24.0,,12,,
```

### JS Analysis — CSV
```
## ENDPOINTS
Method,URL,Dynamic
GET,"/api/v1/users",false
POST,"/api/v1/auth/login",true

## SENSITIVE INFORMATION
Type,Value,Priority,Placeholder
API_KEY,"sk-prod-abc123...",1,false

## DATABASE SCHEMAS
Table,DatabaseType,Confidence,Columns
users,POSTGRESQL,95%,"id|email|password_hash"
```

### JS Analysis — XML
```xml
<jsAnalysis>
  <meta target="example.com" timestamp="2026-05-06T10:30:00" analysisTimeMs="3200"/>
  <endpoints>
    <endpoint method="GET" dynamic="false"><url>/api/v1/users</url></endpoint>
  </endpoints>
  <sensitiveInfo>
    <leak type="API_KEY" priority="1" placeholder="false">
      <value>sk-prod-abc123...</value>
    </leak>
  </sensitiveInfo>
  <databaseSchemas>
    <schema table="users" dbType="POSTGRESQL" confidence="0.95">
      <column name="id" type="INTEGER"/>
      <column name="email" type="VARCHAR"/>
    </schema>
  </databaseSchemas>
</jsAnalysis>
```

---

## License

MIT License. See `LICENSE` for details.
