# Anibus — Scanner di Porte Avanzato

Un'applicazione desktop moderna per la scansione delle porte con analisi di sicurezza approfondita, realizzata con **Anibus Design System**, **JavaFX 21.0.5** e **Java 21**.

> **Versione:** 1.3.0 · **Autore:** Iaroslav Tsymbaliuk · **Ruolo:** Intern (2025–2026) @ r2u

---

## Funzionalità

### Scansione Base
- Scansione di qualsiasi hostname o indirizzo IP alla ricerca di porte aperte
- Intervallo di porte configurabile (es. `1-65535`)
- Numero di thread regolabile (10–500, predefinito 10)
- Misurazione della **latenza** per ogni porta (ms)
- Interruzione della scansione sicura con architettura SOLID

### Rilevamento Servizi Avanzato
- Due modalità di scansione: **Scansione Veloce** e **Rilevamento Servizi**
- **Fingerprinting avanzato dei servizi** per oltre 100 servizi (HTTP, SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kubernetes API, Jenkins, ecc.)
- **Acquisizione banner** con sonde specifiche del protocollo (HTTP HEAD, saluto SSH, SMTP, FTP, handshake MySQL)
- **Estrazione versione software** dai banner (OpenSSH, Apache, nginx, ProFTPD, Postfix, ecc.)
- **Rilevamento sistema operativo** tramite impronte TCP e analisi banner
- **Scansione vulnerabilità** con corrispondenza database CVE (livelli di severità ALTO/MEDIO/CRITICO)
- **Servizi di geolocalizzazione** — posizione IP, ISP, ASN, rilevamento provider cloud
- **Analisi certificati SSL/TLS** — date di scadenza, rilevamento autofirmati, dettagli certificato

### Analisi Sicurezza
- **Rilevamento Keycloak IAM** — rileva automaticamente server Keycloak su `/auth/`, `/keycloak/`, percorsi personalizzati
- **Estrazione chiavi crittografiche** — trova chiavi pubbliche/private esposte e segreti client
- **Supporto multi-realm** — rileva realm `master` e personalizzati
- **Analisi header di sicurezza** — Content Security Policy, HSTS, X-Frame-Options, ecc.
- **Rilevamento tecnologie HTTP** — identificazione CMS (WordPress, Drupal, Magento), server web, framework
- **Rilevamento dispositivi IoT** — telecamere IP, DVR, router con avvisi credenziali predefinite

### Estrazione Informazioni
- **Analisi codice sorgente web** — rileva credenziali trapelate, chiavi API, file di configurazione
- **Analisi approfondita JavaScript** — scansione avanzata del codice sorgente JS con pieno supporto HTTPS, estrazione automatica degli script inline `<script>`, rilevamento file con hash (bundle Webpack, Vite, Rollup), rilevamento `<link rel="modulepreload">` e analisi del contenuto della pagina HTML (meta tag, JSON-LD, configurazioni integrate). Tre modalità: **Basic** (controllo rapido endpoint + sicurezza), **Deep** (rilevamento pattern completo, estrazione credenziali DB) e **Comprehensive** (analisi architetturale + valutazione minacce classificate)
- **Mappatura endpoint** — estrae automaticamente endpoint REST/GraphQL, metodi HTTP, URL e parametri da bundle JavaScript, script inline e sorgente pagina HTML
- **Inferenza schema database** — rileva nomi di tabelle, colonne e relazioni dai pattern di query nel codice JS
- **Estrazione credenziali database** — trova stringhe di connessione per MongoDB, MySQL, PostgreSQL, Redis e altri DB nei file JS (classificate per criticità)
- **Rilevamento pattern architetturali** — identifica pattern MVC, SPA, micro-servizi e serverless dalla struttura JS
- **Rilevamento servizi cloud** — Cloudflare, AWS, Azure, Akamai, identificazione WAF/CDN
- **Rilevamento piattaforme container** — Docker, Kubernetes, Podman e rilevamento orchestrazione tramite fingerprinting passivo header HTTP (Envoy/Istio, Kong, Traefik) e probing attivo API (Docker API, K8s API, Kubelet, cAdvisor, Portainer, OCI Registry)
- **Analisi stack software** — Kubernetes, Docker, Jenkins CI/CD, strumenti HashiCorp

### Analisi SQL Injection
- **Test automatizzato di SQL injection** — test endpoint CMS-aware con oltre 110 payload in 12 categorie (error-based, UNION, time-based, boolean-based, auth-bypass, stacked queries, encoding evasion, integer injection, NoSQL, XPath, LDAP)
- **Profili di injection specifici per CMS** — endpoint vulnerabili preconfigurati per WordPress, Joomla, Drupal, Magento, 1C-Bitrix, OpenCart, PrestaShop, ModX, Shopify, più target generici
- **Rilevamento CMS automatico** — identifica automaticamente il CMS target dalle risposte HTTP e seleziona il profilo di injection corrispondente
- **Scoperta automatica form HTML** — analizza `<form>`, `<a href>`, `<input>`, `<select>` e `<textarea>` per scoprire endpoint iniettabili
- **Sistema payload modulare** — file per categoria e per CMS con discovery tramite `index.txt` per facile manutenzione ed estensibilità
- **Analisi delle risposte** — rileva errori SQL da 7 motori database (MySQL, PostgreSQL, Oracle, MSSQL, SQLite, MongoDB, MariaDB), pattern di leak dati e ritardi temporali

### Interfaccia e Flusso di Lavoro
- **Tema scuro** — design completo in modalità dark con contrasto e leggibilità ottimizzati
- **Vista console** — alternanza tra visualizzazione tabella e output console in stile terminale con risultati formattati
- **Rilevamento SSL/TLS** — controllo automatico del supporto HTTPS durante la risoluzione degli host (indicatore spunta/X)
- **Gestione intelligente degli URL** — rimozione automatica dei prefissi http:// e https://, estrazione dell'hostname dagli URL completi
- **Indicatore stato rete** — stato connessione in tempo reale nella barra di stato ([ONLINE], [LOCALE], [OFFLINE]), aggiornato ogni 5 secondi
- **Pannello informazioni host** — IP, hostname, tempo di scansione, porte analizzate, porte aperte, latenza media (aggiornamento in tempo reale)
- **Esportazione in CSV o XML** con tutte le colonne e dati del rilevamento servizi avanzato
- **Cancellazione** dei risultati con un clic
- **Copia riga** o **copia tutti** tramite menu contestuale
- **Copia indirizzo IP** dall'etichetta dell'host risolto tramite clic destro
- Risoluzione DNS automatica alla perdita del focus
- **Anibus Design System**: barra di navigazione effetto vetro, pulsanti con gradiente, barre di scorrimento sottili, schede arrotondate, colonna stato colorata
- **Output testuale** — formattazione ASCII pulita per compatibilità universale con console

---

## Struttura del Progetto

```
src/
└── main/
    ├── java/
    │   ├── module-info.java
    │   └── it/r2u/anibus/
    │       ├── AnibusApplication.java          # Punto di ingresso JavaFX
    │       ├── AnibusController.java           # Controller UI (refactoring SOLID, snello e focalizzato)
    │       │
    │       ├── coordinator/                     # Orchestrazione scan (pattern Strategy & Facade)
    │       │   ├── ScanStrategy.java            # Interfaccia strategia per tipi di scansione
    │       │   ├── ScanContext.java             # Pattern Builder per parametri scansione
    │       │   ├── ScanCoordinator.java         # Facade per gestione strategie
    │       │   ├── StandardScanStrategy.java    # Strategia scansione TCP veloce
    │       │   └── ServiceDetectionStrategy.java # Strategia rilevamento servizi avanzato
    │       │
    │       ├── handlers/                        # Handler azioni (pattern Command)
    │       │   ├── ScanActionHandler.java       # Ciclo vita scansione e aggiornamenti UI
    │       │   ├── ClipboardActionHandler.java  # Operazioni appunti
    │       │   ├── ExportActionHandler.java     # Funzionalità esportazione
    │       │   └── TracerouteActionHandler.java # Tracciamento percorso rete
    │       │
    │       ├── model/
    │       │   ├── PortScanResult.java          # Modello dati (7 campi)
    │       │   ├── PortRegistry.java            # Tabelle di servizi e protocolli/cifratura
    │       │   ├── ArchitectureInfo.java        # Risultato analisi pattern architetturali JS
    │       │   ├── DataStructureInfo.java       # Strutture dati rilevate dal codice JS
    │       │   ├── DatabaseSchemaInfo.java      # Schema DB inferito dalle query JS
    │       │   ├── EndpointInfo.java            # Dettagli degli endpoint API estratti
    │       │   └── JavaScriptAnalysisResult.java # Risultato aggregato dell'analisi sicurezza JS
    │       │
    │       ├── network/
    │       │   ├── HostResolver.java            # Risoluzione DNS e rilevamento SSL
    │       │   └── NetworkStatusMonitor.java    # Monitoraggio connettività rete
    │       │
    │       ├── service/
    │       │   ├── PortScannerService.java      # Logica scansione principale
    │       │   ├── ScanTask.java                # Task<Void> in background con callbacks
    │       │   ├── ServiceDetectionTask.java    # Task rilevamento avanzato
    │       │   ├── EnhancedServiceDetector.java # Fingerprinting servizi approfondito
    │       │   ├── BannerGrabber.java           # Acquisizione banner (HTTP HEAD / greeting raw)
    │       │   ├── VersionExtractor.java        # Estrazione versione (regex)
    │       │   ├── ExportService.java           # Esportazione CSV e XML
    │       │   ├── OSDetector.java              # Rilevamento sistema operativo
    │       │   ├── VulnerabilityScanner.java    # Corrispondenza database CVE
    │       │   ├── GeolocationService.java      # Geolocalizzazione IP via ip-api.com
    │       │   ├── HTTPAnalyzer.java            # Certificati SSL, header sicurezza, rilevamento CMS
    │       │   ├── TracerouteService.java       # Tracciamento percorso rete
    │       │   ├── IoTDetector.java             # Rilevamento telecamere IP e dispositivi IoT
    │       │   ├── KeycloakDetector.java        # Rilevamento Keycloak IAM ed estrazione chiavi
    │       │   ├── SoftwareStackDetector.java   # Analisi stack tecnologico
    │       │   ├── ContainerDetector.java        # Rilevamento piattaforme container Docker/K8s/Podman
    │       │   ├── SubnetScanner.java            # Scansione intervallo subnet
    │       │   ├── WebSourceAnalyzer.java        # Analisi perdite nel codice sorgente web
    │       │   ├── JavaScriptSecurityAnalyzer.java # Analisi sicurezza JS avanzata (HTTPS, script inline, file hash, architettura)
    │       │   ├── JavaScriptDatabaseAnalyzer.java # Estrazione credenziali DB e stringhe di connessione da JS
    │       │   └── SQLInjectionAnalyzer.java     # Test SQL injection con profili CMS e scoperta form HTML
    │       │
    │       └── ui/
    │           ├── AlertHelper.java             # Dialoghi di avviso Anibus Design System
    │           ├── ClipboardService.java        # Utilità copia negli appunti
    │           ├── ConsoleViewManager.java      # Gestione output console
    │           ├── InfoCardManager.java         # Gestione pannello info host
    │           └── TableConfigurator.java       # Configurazione colonne tabella
    │
    └── resources/
        └── it/r2u/anibus/
            ├── hello-view.fxml                  # Layout dell'interfaccia
            ├── anibus-style.css                 # Foglio di stile Anibus Design System
            ├── app.properties                   # Versione runtime filtrata da Maven
            └── injections/                      # Payload SQL injection e profili CMS
                ├── payloads/                    # 12 file per categoria (error-based, UNION, time-based, ecc.)
                │   ├── index.txt
                │   ├── error-based.txt
                │   ├── union-based.txt
                │   └── ...                      # boolean-based, auth-bypass, nosql, xpath, ldap, ecc.
                └── cms/                         # 10 profili endpoint specifici per CMS
                    ├── index.txt
                    ├── wordpress.txt
                    ├── joomla.txt
                    └── ...                      # drupal, magento, bitrix, opencart, ecc.
```

---

## Requisiti

| Strumento | Versione |
|-----------|----------|
| Java      | 21+      |
| JavaFX    | 21.0.5   |
| Maven     | 3.8+     |

---

## Compilazione e Avvio

```bash
# Clonare il repository
git clone https://github.com/episkob/anibus.git
cd anibus

# Avvio con Maven
./mvnw javafx:run
```

Su Windows:

```cmd
mvnw.cmd javafx:run
```

---

## Utilizzo

1. **Selezionare la modalità di scansione** — «Scansione Veloce» (connettività base) o «Rilevamento Servizi» (analisi completa)
2. Inserire l'**host di destinazione** (hostname o indirizzo IP)
3. Inserire l'**intervallo di porte** nel formato `inizio-fine` (es. `1-65535` o `80,443`)
4. Facoltativamente, regolare il **numero di thread** (più alto = più veloce, ma più aggressivo)
5. Cliccare su **Start Scan**
6. Appare il **pannello informazioni host** con statistiche di scansione in tempo reale
7. I risultati popolano la tabella man mano che le porte vengono scoperte
8. Con **Rilevamento Servizi**, vedere dati migliorati: rilevamento OS, vulnerabilità, geolocalizzazione, analisi Keycloak
9. Cliccare su **Stop** per interrompere la scansione in qualsiasi momento
10. Usare **Export** per salvare i risultati come **CSV o XML** con dati di analisi completi, o **Clear** per resettare
11. Cliccare con il tasto destro su qualsiasi riga per copiare risultati o indirizzi IP
7. Cliccare **Stop** per interrompere la scansione in qualsiasi momento
8. Usare **Export** per salvare in **CSV o XML**, oppure **Clear** per azzerare
9. Fare clic destro per copiare una riga o tutti i risultati

---

## Stack Tecnologico

- **Java 21** — linguaggio di programmazione
- **JavaFX 21.0.5** — framework UI
- **Maven** — strumento di build
- **FXML** — layout dichiarativo dell'interfaccia
- **CSS** — tema Anibus Design System

---

## Licenza

Licenza MIT. Vedere il file `LICENSE` per i dettagli.
