# Anibus — Scanner di Sicurezza di Rete Avanzato

> **Versione:** 2.2.0 · **Autore:** Iaroslav Tsymbaliuk · **Ruolo:** Intern (2025–2026) @ r2u

Uno scanner di sicurezza di rete desktop completo, realizzato con **Java 21 (JPMS)**, **JavaFX 21.0.5** e un tema **Bootstrap 5 Dark** personalizzato.
Anibus va ben oltre un semplice port scanner: combina fingerprinting dei servizi, corrispondenza CVE, analisi dei sorgenti JavaScript, test di SQL injection, geolocalizzazione, ispezione SSL/TLS e rilevamento dell'infrastruttura in un'unica applicazione autonoma.

---

## Indice

- [Novità](#novità)
- [Panoramica Funzionalità](#panoramica-funzionalità)
- [Architettura](#architettura)
- [Struttura del Progetto](#struttura-del-progetto)
- [Design Pattern](#design-pattern)
- [Interfaccia Utente](#interfaccia-utente)
- [Stack Tecnologico](#stack-tecnologico)
- [Requisiti](#requisiti)
- [Build & Run](#build--run)
- [Guida all'Utilizzo](#guida-allutilizzo)
- [Testing](#testing)
- [Formati di Export](#formati-di-export)
- [Licenza](#licenza)

---

## Novità

La build attuale è un salto importante oltre il semplice port scanner: Anibus è ora una suite completa di audit web/API/infrastruttura. Di seguito i punti chiave.

### Nuovi analizzatori di sicurezza

| Modulo | Cosa fa |
|--------|--------|
| **XSS Detector** | XSS reflected + DOM-based + stored, payload context-aware (HTML/attr/JS/URL/CSS/comment), set polyglot, generazione PoC link e `curl` |
| **SSRF Detector** | Manipolazione URL-param, accesso a cloud-metadata, schemi `file://`/`dict://`/`gopher://`/`ftp://`, bypass IPv6-mapped, octal/hex/decimal/short-form IP e `nip.io` rebinding |
| **XXE Detector** | XXE inline + OOB tramite server DTD loopback embedded, blind XXE/SSRF via diff sulla lunghezza della risposta |
| **CORS Misconfiguration** | Reflection Origin, combo credentials + wildcard, `Origin: null`, header pre-flight, sweep per-endpoint |
| **JWT Analyzer** | `alg:none`, HMAC debole, expired, JWK/JWKS, `kid` injection / path traversal / SQLi, alg-confusion, TTL-diff coppia access/refresh, claim-tamper helper |
| **GraphQL Introspection** | 10 path schema, depth-limit probe, batch-query abuse, generazione automatica query/mutation |
| **Subdomain Takeover** | 50+ fingerprint provider (Vercel/Render/Fly.io/Pantheon/Tumblr/Acquia/Railway/…), ricorsione CNAME, baseline DNS-wildcard contro falsi positivi |
| **Auth Crawling** | Basic / Bearer / OAuth2 client_credentials / Digest (RFC 7616) / form-login con estrazione CSRF automatica / **NTLM v2** (MD4 + HMAC-MD5 propri, senza librerie esterne) |
| **Tech Stack Fingerprinter 2.0** | 40+ firme: web server, CMS, framework JS, CDN, analytics, runtime cookie-based — con cattura versione |
| **Service Misconfiguration** | `.git/config`, `.env`, `/actuator/env`, `/server-status`, `/phpinfo.php`, Docker/K8s/etcd esposti — confidence content-based |
| **Container Exposure** | Probe API Docker / Kubernetes / etcd (solo GET read-only) |
| **Weak TLS Policy** | TLS 1.0/1.1, cipher deboli, self-signed, audit OCSP/HSTS/ALPN, trust catena via JVM TrustManager |
| **Auth Surface Auditor** | Discovery login endpoint, probe rate-limit a burst, detect token captcha e header lockout |
| **Heartbleed Checker** | TLS heartbeat raw con verifica strutturale della risposta e guard anti-FP |
| **Passive Recon** | Title/headers/robots/sitemap, fingerprint hash favicon (Jenkins/GitLab/Confluence/JIRA/Grafana/…), `<meta name="generator">`, estrazione origin da CSP, OSINT email harvest, analisi cross-origin (TAO/CORP/COOP/COEP/ACAO) |
| **Cookie Flags Auditor** | Audit `Set-Cookie` (`Secure`/`HttpOnly`/`SameSite`), severity più alta per cookie di auth |
| **Secrets Validation** | Validazione formale AWS/GitHub/Stripe/Telegram/Slack/Google/NPM/Docker PAT, GCP service-account JSON, chiavi PEM, dizionario fuzzy, filtro placeholder |
| **SQLi Boolean-Blind + OOB** | Diff per lunghezza/status-code, primitive OOB MSSQL/Oracle/PostgreSQL/MySQL via loopback callback, 8 payload time-based |
| **JS Endpoint Reachability** | Probe liveness + metodo/status per ogni endpoint estratto dai bundle JS |
| **AI Summary** | Executive summary euristico (EN/RU) per JS Analysis — severity bucket, top risk-scored, raccomandazioni type-aware, senza LLM esterno |
| **SourceMap Exploit Context** | Ogni LeakInfo è annotato con categoria di attacco, narrativa, raccomandazione e link CVE/OWASP |

### Rete e infrastruttura

- **ASN/BGP enrichment** via Team Cymru bulk whois, **mappa GeoIP** con ASCII chart per paese
- **Multi-target batch scan** con report aggregato (`BatchScanService`)
- **Banner timeline** — store TSV + diff fra scansioni
- **Traceroute** in modalità ICMP / TCP / UDP con metriche packet-loss; **Topology Map** con clustering /24 + ASN
- **WHOIS Lookup** con fallback RDAP, normalizzazione registrar/abuse (IANA root → autoritativo)
- **SSL/TLS Deep Audit** — protocollo, cipher, catena, SAN, OCSP, HSTS, ALPN
- **DNS AXFR** zone transfer (raw TCP/53), **HTTP/2 + HTTP/3** via ALPN + `Alt-Svc`, probe **WebSocket**
- Supporto **IPv6** in `HostResolver`

### CVE intelligence

- **Cache NVD offline** (`CveDbCacheService`, NVD 2.0 API, file flat `.cvecache`)
- **EPSS + CISA KEV** prioritization (`EpssKevService`)
- **Exploit maturity** (WEAPONIZED / POC / THEORETICAL) e stima età CVE
- **PoC link**: NVD, MITRE, Exploit-DB, PacketStorm, vendor advisory
- Fingerprint estesi: Node.js / Jetty / WildFly / JBoss / OpenSSL / Spring / IIS / GitLab

### Sottosistema Proxy

- **Visual Proxy Chain Manager** — drag-and-drop, card `ACTIVE CHAIN`, dialogo `Build Chain` (localizzato EN/IT/RU)
- Controlli di routing avanzati, politiche di rotazione, comportamento catena più flessibile
- Selezione proxy geo-aware, validazione reactive triple-handshake, pool persistente in `~/.anibus/proxy-pool.json`

### UI ed export

- **Storico scansioni** in `~/.anibus/history/` con menu contestuale di confronto e re-run
- Scheda **Statistic Dashboard** con grafici porte/servizi/rischio
- **Switch tema chiaro/scuro**, **notifiche tray**, **scorciatoie da tastiera** (F5 / Esc / Ctrl+S / Ctrl+L / Ctrl+F)
- Export **PDF e HTML stilizzato** (JavaFX PrinterJob), **filtro realtime in console**
- **Raggruppamento CVE per severity** (CRITICAL / HIGH / MEDIUM / LOW), ordinamento JS Analysis per priorità
- **Wordlist selector** per Subdomain, payload SQLi ed Endpoint; indicatore wordlist attive in Scan Target
- Modalità **porta singola e range**, opzioni scheduler avanzate, log di stato realtime con timestamp
- **Diff View** fra due export XML salvati

### Architettura e qualità

- **Thread virtuali (JEP 444)** in `ScanTask`, `ServiceDetectionTask`, `JavaScriptSecurityAnalyzer`, `ReactiveValidator`, `ReverseDnsExpander` e tutti i percorsi blocking-IO
- **DI manuale** in `AnibusApplication` (no reflection, JPMS-clean)
- **Facciata HTTP unificata** `HttpClientFactory.open(url, profile)` con trust-all TLS, retry + exponential backoff + jitter
- **Registry timeout profile** (FAST 2s / NORMAL 5s / SLOW 10s / VERY_SLOW 20–30s)
- **Named daemon ThreadFactory** + graceful shutdown con isolamento errori per servizio
- **Test ArchUnit** sui confini moduli, validazione FXML, parità chiavi Messages_en/it/ru
- **162 unit test** distribuiti su 50+ classi di test

---

## Panoramica Funzionalità

### Scansione Porte
- Scansione di qualsiasi hostname, IP o URL
- Range di porte configurabile (`1-65535`) e numero di thread (default: 10 thread virtuali)
- Misurazione latenza per porta (ms)
- Barra di avanzamento in tempo reale e statistiche live
- Interruzione sicura in qualsiasi momento

### Rilevamento Servizi Avanzato

Analisi banner multi-livello e sonde specifiche del protocollo:

| Livello | Cosa fa |
|---------|--------|
| Acquisizione banner | HTTP HEAD, greeting SSH, SMTP EHLO, FTP, handshake MySQL |
| Estrazione versione | Parsing intestazioni `Server:`, banner SSH, Redis `INFO`, greeting FTP |
| Rilevamento OS | TCP fingerprinting + analisi banner |
| Corrispondenza CVE | Confronta versioni con database vulnerabilità incorporato |
| Geolocalizzazione | IP → posizione, ISP, ASN, cloud provider |
| SSL/TLS | Data scadenza, emittente, rilevamento certificati autofirmati |

Servizi supportati: HTTP/HTTPS, SSH, FTP, SMTP, DNS, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kibana, Kubernetes API, Jenkins, Grafana, Prometheus, RabbitMQ, Kafka, ZooKeeper, LDAP, Memcached, Cassandra, CouchDB, Neo4j, InfluxDB, Splunk, Vault, Consul, Etcd e molti altri.

### Analisi di Sicurezza

| Funzionalità | Descrizione |
|-------------|------------|
| **Keycloak IAM** | Rileva server Keycloak, estrae chiavi crittografiche esposte e segreti client |
| **Header di sicurezza** | Verifica CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy |
| **Rilevamento CMS** | WordPress, Drupal, Magento, Joomla, 1C-Bitrix — fingerprinting versioni |
| **Dispositivi IoT** | Telecamere IP, DVR/NVR, router — avvisi credenziali predefinite |
| **Rilevamento container** | Docker API, Kubernetes API, Rancher, Portainer |
| **Metadati cloud** | Sonda endpoint AWS/GCP/Azure IMDS |

### Analisi JavaScript (scheda JS Analysis)

Recupera e analizza i file JavaScript del target, inclusi bundle Webpack/Vite/Rollup con nomi hashati scoperti tramite HTML:

| Analisi | Dettagli |
|---------|---------|
| **Mapping endpoint API** | Endpoint REST/GraphQL, metodi HTTP, template URL da bundle JS |
| **Estrazione credenziali DB** | Connection string per 30+ engine: MongoDB, MySQL, PostgreSQL, Redis, Elasticsearch, Cassandra, Neo4j, InfluxDB, RabbitMQ, DynamoDB, Supabase, PlanetScale e altri |
| **Inferenza schema DB** | Tabelle, colonne, relazioni da pattern ORM/query in JS |
| **Rilevamento infrastruttura** | Docker, Kubernetes, AWS/GCP/Azure, Nginx, Traefik, Cloudflare, Fastly con punteggio di confidenza |
| **Rilevamento framework** | React, Vue, Angular, Next.js, Nuxt.js, SvelteKit, Remix, Astro, Gatsby, Alpine.js, Solid.js, Qwik e 20+ altri |
| **Informazioni sensibili** | API key, token segreti, chiavi private, JWT secret, credenziali OAuth |

I risultati sono mostrati in un **TreeView** espandibile categorizzato per tipo di rilevamento.

### SQL Injection Testing

- **110+ payload** in 12 categorie:
  - Error-based, UNION-based, time-based (sleep/benchmark), boolean-based
  - Auth-bypass, stacked query, NoSQL, XPath, LDAP injection
  - Evasione encoding (URL, hex, double-URL, Unicode, mixed-case)
- **Profili CMS**: WordPress (`wp-login.php`, `xmlrpc.php`), Joomla, Drupal, Magento, 1C-Bitrix, OpenCart, PrestaShop, ModX, Shopify
- **Scoperta automatica form**: parsing di `<form>`, `<input>`, `<select>`, `<textarea>`
- **Analisi risposta**: rileva errori SQL da MySQL, PostgreSQL, MSSQL, SQLite, Oracle, MongoDB e ritardi time-based

---

## Architettura

```
┌─────────────────────────────────────────────────────────┐
│                    AnibusController                      │
│       (Controller FXML JavaFX, solo thread UI)           │
└───────┬─────────────────────────────────┬───────────────┘
        │                                 │
        ▼                                 ▼
┌───────────────┐                ┌────────────────────┐
│ ScanCoordinator│               │  Action Handler    │
│ Strategy+Facade│               │ ScanActionHandler  │
│               │                │ ExportActionHandler│
│  ScanContext  │                │ ClipboardHandler   │
│  ScanStrategy │                └────────────────────┘
└───────┬───────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│               Layer dei Servizi              │
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
│               Layer dei Modelli              │
│  LeakInfo · PortScanResult · PortRegistry   │
│  JavaScriptAnalysisResult · EndpointInfo    │
│  DatabaseSchemaInfo · DataStructureInfo     │
│  ArchitectureInfo                           │
└─────────────────────────────────────────────┘
```

### Flusso dei Dati

1. L'utente inserisce target + opzioni → **ScanCoordinator** crea un `ScanContext`
2. **PortScannerService** avvia task su thread virtuali, uno per porta
3. Ogni porta aperta → **EnhancedServiceDetector** → banner → versione → CVE
4. **GeolocationService** risolve metadati IP in parallelo
5. JS Analysis abilitata → **JavaScriptSecurityAnalyzer** recupera e analizza bundle
6. SQL Injection abilitata → **SQLInjectionAnalyzer** scopre form e li testa
7. Risultati restituiti tramite `Platform.runLater()` — UI sempre sul thread JavaFX
8. **ExportService** / **ExportActionHandler** scrivono CSV o XML su richiesta

---

## Struttura del Progetto

```
src/main/java/it/r2u/anibus/
├── AnibusApplication.java               # Entry point JavaFX Application
├── AnibusController.java                # Controller FXML principale
│
├── coordinator/
│   ├── ScanCoordinator.java             # Orchestrazione pipeline scansione completa
│   ├── ScanContext.java                 # Container stato scansione mutabile
│   ├── ScanStrategy.java               # Interfaccia Strategy
│   ├── StandardScanStrategy.java       # Flusso scansione predefinito
│   └── ServiceDetectionStrategy.java   # Flusso orientato al rilevamento
│
├── handlers/                            # Command pattern — una classe per azione UI
│   ├── ScanActionHandler.java
│   ├── ExportActionHandler.java         # Export CSV/XML per port scan + JS analysis
│   ├── ClipboardActionHandler.java
│   └── TracerouteActionHandler.java
│
├── model/                               # Classi dati immutabili
│   ├── LeakInfo.java                   # Record leak + inferenza priorità
│   ├── PortScanResult.java
│   ├── PortRegistry.java               # Mappa porta/nome servizio (1000+ voci)
│   ├── JavaScriptAnalysisResult.java
│   ├── EndpointInfo.java
│   ├── DatabaseSchemaInfo.java
│   ├── DataStructureInfo.java
│   └── ArchitectureInfo.java
│
├── network/
│   ├── HostResolver.java               # Risoluzione DNS + normalizzazione URL
│   └── NetworkStatusMonitor.java       # Verifica connettività periodica
│
├── service/
│   ├── analysis/
│   │   ├── JavaScriptSecurityAnalyzer.java    # Fetcher bundle + orchestratore analisi
│   │   ├── JavaScriptDatabaseAnalyzer.java    # Rilevamento credenziali DB + schemi
│   │   ├── WebSourceAnalyzer.java             # Parser HTML/JS (script inline, link)
│   │   └── SQLInjectionAnalyzer.java          # Scoperta form + iniezione payload
│   │
│   ├── core/
│   │   ├── PortScannerService.java            # Scanner porte su thread virtuali
│   │   ├── ScanTask.java                      # Callable per singola porta
│   │   ├── ServiceDetectionTask.java          # Rilevamento approfondito post-scan
│   │   ├── BannerGrabber.java                 # Acquisizione banner grezzo
│   │   ├── HTTPAnalyzer.java                  # Analisi livello HTTP
│   │   └── VulnerabilityScanner.java          # Engine corrispondenza CVE
│   │
│   ├── detection/
│   │   ├── EnhancedServiceDetector.java       # Dispatcher principale rilevamento
│   │   ├── OSDetector.java                    # Fingerprinting OS
│   │   ├── PassiveFingerprinter.java          # Analisi traffico passiva
│   │   ├── IoTDetector.java                   # Rilevamento telecamere/DVR/router
│   │   ├── KeycloakDetector.java              # Scraper realm Keycloak
│   │   ├── SoftwareStackDetector.java         # Identificazione CMS/framework
│   │   └── ContainerDetector.java             # Rilevamento Docker/Kubernetes
│   │
│   ├── export/
│   │   └── ExportService.java                 # Writer CSV/XML per port scan
│   │
│   ├── geo/
│   │   └── GeolocationService.java            # Integrazione ip-api.com
│   │
│   └── network/
│       ├── SubnetScanner.java                 # Espansione range CIDR
│       ├── TracerouteService.java             # Traceroute ICMP/TCP
│       ├── ReverseDnsExpander.java            # Lookup record PTR
│       ├── CloudMetadataProbe.java            # Sonda AWS/GCP/Azure IMDS
│       └── VersionExtractor.java             # Estrazione versione via regex
│
└── ui/
    ├── AlertHelper.java                       # Dialog stilizzati
    ├── ClipboardService.java                  # Integrazione clipboard di sistema
    ├── ConsoleViewManager.java                # Rendering scheda console
    ├── InfoCardManager.java                   # Aggiornamento card Host Info

src/main/resources/it/r2u/anibus/
├── hello-view.fxml                            # Layout UI completo (sidebar + TabPane)
├── anibus-style.css                           # Tema personalizzato Bootstrap 5 Dark
└── logging.properties

src/test/java/it/r2u/anibus/
├── service/core/PortScannerServiceTest.java         # 9 test
├── model/LeakInfoTest.java                          # 22 test
├── service/analysis/WebSourceAnalyzerTest.java      # 8 test
├── service/WebSourceAnalyzerLeakInfoTest.java       # 3 test
└── service/JavaScriptSecurityAnalyzerServiceInferenceTest.java  # 7 test
```

---

## Design Pattern

| Pattern | Dove usato | Perché |
|---------|-----------|--------|
| **Strategy** | `ScanStrategy` / `ScanCoordinator` | Sostituire l'algoritmo di scansione senza modificare il controller |
| **Command** | Classi `*ActionHandler` | Disaccoppiare azioni UI dalla logica; una classe = una responsabilità |
| **Facade** | `ScanCoordinator` | Unico punto d'ingresso per pipeline multi-servizio complessa |
| **Builder** | `JavaScriptAnalysisResult` | Raccolta incrementale di risultati asincroni |
| **Constructor Injection** | Tutti i servizi | Dipendenze esplicite, testabilità, compatibilità JPMS, zero overhead |
| **Observer** | `Platform.runLater()`, `Task<>` | Aggiornamenti UI thread-safe da thread di scansione in background |

### Perché nessun framework DI?

Java 21 JPMS è incompatibile con la maggior parte dei framework DI (Spring, Guice) perché si basano sulla reflection attraverso i confini dei moduli. L'iniezione via costruttore fornisce lo stesso disaccoppiamento senza overhead e con piena compatibilità JPMS.

### Perché i thread virtuali?

La scansione delle porte è puramente I/O-bound. I thread virtuali di Java 21 (`Executors.newVirtualThreadPerTaskExecutor()`) permettono centinaia di connessioni socket concorrenti con overhead di memoria trascurabile — senza la complessità della programmazione reattiva.

---

## Interfaccia Utente

```
┌────────────────────────────────── Anibus 2.2.0 ─────────────────────────────────────┐
│ [●] Anibus  ░░░░░░░░░░░░░░░░░░░░░░░░  ● Connesso  192.168.1.1                │  ← Nav bar
│───────────────────────────────────────────────────────────────────────────────│
│ ┌── Scan Target ───────────────┐  ┌── [Scan Results] [JS Analysis] ──────────┐│
│ │ Host: [example.com_______]   │  │  Scan Results               [Export][Clear]││
│ │ Ports:[1-1024] Threads:[10]  │  │ ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄  ││
│ │ ☑ JavaScript Analysis        │  │  ╔══ PORTA 22 — SSH ══════════════════╗  ││
│ │ ☑ SQL Injection Testing      │  │  ║ OpenSSH 8.9p1 Ubuntu              ║  ││
│ │ [▶ Start Scan       ] [Stop] │  │  ║ CVE-2023-38408  HIGH              ║  ││
│ │ ████████████░░░░░  67%       │  │  ╚═══════════════════════════════════╝  ││
│ └──────────────────────────────┘  │  ╔══ PORTA 80 — HTTP ═════════════════╗  ││
│ ┌── Host Info ─────────────────┐  │  ║ nginx/1.24.0  WordPress 6.4.2    ║  ││
│ │ IP                           │  │  ╚═══════════════════════════════════╝  ││
│ │ 93.184.216.34                │  └────────────────────────────────────────┘│
│ │ Hostname                     │                                             │
│ │ example.com                  │                                             │
│ │ Scan Time    │ Ports Scanned │                                             │
│ │ 4.2s         │ 1024          │                                             │
│ │ Open Ports   │ Avg Latency   │                                             │
│ │ 3            │ 12ms          │                                             │
│ └──────────────────────────────┘                                             │
│───────────────────────────────────────────────────────────────────────────────│
│ ● Scansione completata — trovate 3 porte aperte                               │  ← Status bar
└───────────────────────────────────────────────────────────────────────────────┘
```

**Pannello sinistro (300 px):**
- **Card Scan Target** — campo host con risoluzione DNS live, range porte, spinner thread, due checkbox, pulsanti Start/Stop, barra avanzamento
- **Card Host Info** — appare dopo la scansione; IP e hostname (con a capo automatico), griglia 2 colonne: Scan Time / Ports Scanned / Open Ports / Avg Latency

**Pannello destro (flessibile):**
- **Scheda Scan Results** — console monospace scura con banner ASCII formattati per servizio
- **Scheda JS Analysis** — barra statistiche + TreeView espandibile + pulsante Export

---

## Stack Tecnologico

| Tecnologia | Versione | Ruolo |
|-----------|---------|-------|
| Java | 21 (LTS) | Linguaggio, sistema moduli JPMS, thread virtuali |
| JavaFX | 21.0.5 | Framework UI (FXML + CSS) |
| Bootstrap 5 Dark (CSS) | Port personalizzato | Sistema di design |
| Maven Shade Plugin | 3.5.1 | Fat JAR con librerie native JavaFX integrate |
| JUnit 5 | 5.10.2 | Unit testing |
| junit-jupiter-params | 5.10.2 | Test parametrizzati |

---

## Requisiti

| Strumento | Versione | Note |
|-----------|---------|------|
| Java | **21+** | LTS raccomandato |
| Maven | 3.8+ | O il wrapper incluso `./mvnw` |
| JavaFX | — | Integrato nel fat JAR — nessuna installazione separata |
| OS | Linux / Windows / macOS | Tutte le piattaforme |

---

## Build & Run

**Clone e avvio diretto:**

```bash
git clone https://github.com/episkob/anibus.git
cd anibus
./mvnw javafx:run
```

**Costruire il fat JAR:**

```bash
./mvnw clean package -DskipTests
java -jar anibus-2.2.0.jar
```

Lo shaded JAR eseguibile viene generato nella root del progetto come `anibus-2.2.0.jar`.

**Windows:**

```cmd
mvnw.cmd clean package -DskipTests
java -jar anibus-2.2.0.jar
```

**Linux — Wayland / XWayland:**

```bash
xhost +local:
DISPLAY=:0 java -jar anibus-2.2.0.jar
```

**Da un terminale Flatpak VS Code:**

```bash
flatpak-spawn --host xhost +local:
DISPLAY=:0 java -jar anibus-2.2.0.jar
```

---

## Guida all'Utilizzo

### 1 — Inserire il target

Digita un hostname, indirizzo IP o URL completo. Il DNS si risolve automaticamente alla perdita del focus. Un indicatore SSL appare se la porta 443 risponde.

### 2 — Configurare le opzioni

| Impostazione | Descrizione |
|-------------|------------|
| **Ports** | Range come `1-1024` o lista separata da virgole `22,80,443,8080` |
| **Threads** | Connessioni parallele (1–200, default 10) |
| **JavaScript Analysis** | Recupera e analizza bundle JS per segreti ed endpoint |
| **SQL Injection Testing** | Scoperta automatica form e test con 110+ payload |

### 3 — Avviare la scansione

Clicca **▶ Start Scan**. La barra di avanzamento e la status bar si aggiornano in tempo reale.

### 4 — Leggere i risultati

La scheda **Scan Results** mostra banner formattati: versione, OS, avvisi CVE, geolocalizzazione, dati SSL.

### 5 — Scheda JS Analysis

Passa a **JS Analysis** per vedere: endpoint API, credenziali sensibili, schemi DB, strutture dati, infrastruttura e framework rilevati.

### 6 — Export

Entrambe le schede hanno un pulsante **Export** indipendente che apre un dialogo di scelta formato:
- **CSV** — formato leggibile, compatibile con fogli di calcolo
- **XML** — formato strutturato, analizzabile da macchina

---

## Testing

```bash
./mvnw test
```

| Classe di test | Test | Copre |
|--------------|------|-------|
| `LeakInfoTest` | 14 | Inferenza priorità, rilevamento placeholder, builder |
| `RetryPolicyTest` | 9 | Logica retry HTTP e backoff |
| `PortScannerServiceTest` | 7 | Parsing range porte, thread safety, input null |
| `JavaScriptSecurityAnalyzerServiceInferenceTest` | 7 | Rilevamento engine DB e framework |
| `ProxyRoutingServiceTest` | 6 | Routing e selezione proxy |
| `NtlmMessagesTest` | 6 | Parsing autenticazione NTLM |
| `FaviconFingerprintDatabaseTest` | 6 | Fingerprinting hash favicon |
| `ContainerExposureCheckerTest` | 6 | Rilevamento API container esposte |
| `AuthCrawlerTest` | 6 | Crawling autenticato con gestione sessione |
| `WebSourceAnalyzerTest` | 5 | Parsing sorgenti JS, estrazione endpoint |
| `SQLInjectionAnalyzerTest` | 5 | Esecuzione payload SQL injection |
| `ServiceMisconfigurationCheckerTest` | 5 | Pattern di misconfigurazioni servizi |
| `ModuleBoundaryTest` | 5 | Verifica confini moduli JPMS |
| `HarPostmanParserTest` | 5 | Import collezioni HAR/Postman |
| `
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

## Licenza

MIT License. Vedi `LICENSE` per i dettagli.
