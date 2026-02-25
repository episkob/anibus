# Anibus — Scanner di Porte

Un'applicazione desktop moderna per la scansione delle porte, realizzata con **Anibus Design System**, **JavaFX 21.0.5** e **Java 21**.

> **Versione:** 1.1.0 · **Autore:** Iaroslav Tsymbaliuk · **Ruolo:** Intern (2025–2026) @ r2u

---

## Funzionalità

### Scansione
- Scansione di qualsiasi hostname o indirizzo IP alla ricerca di porte aperte
- Intervallo di porte configurabile (es. `1-1024`)
- Numero di thread regolabile (10–500, predefinito 10)
- Misurazione della **latenza** per ogni porta (ms)
- Interruzione della scansione in modo sicuro

### Estrazione delle Informazioni
- **Rilevamento automatico del servizio** per oltre 50 porte note (HTTP, SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kubernetes API, ecc.)
- **Acquisizione banner** — le porte HTTP ricevono header completi tramite richiesta `HEAD`
- **Estrazione della versione software** dai banner (OpenSSH, Apache, nginx, ProFTPD, Postfix, ecc.)
- Rilevamento di protocollo e **cifratura** (TLS, STARTTLS, HTTPS, SMTPS, LDAPS, ecc.)

### Interfaccia e Flusso di Lavoro
- **Indicatore di rete (semaforo)** — punto animato nella barra di stato (🟢 internet, 🟡 solo rete locale, 🔴 nessuna connessione), aggiornato ogni 5 secondi
- **Pannello informazioni host** — IP, hostname, tempo di scansione, porte analizzate, porte aperte, latenza media (aggiornamento in tempo reale)
- **Tabella risultati con 7 colonne** — Porta, Stato, Servizio, Versione, Protocollo, Latenza, Banner
- **Esportazione in CSV o XML** con tutte le colonne
- **Cancellazione** dei risultati con un clic
- **Copia riga** o **copia tutti** tramite menu contestuale
- Risoluzione DNS automatica alla perdita del focus
- **Anibus Design System**: barra di navigazione effetto vetro, pulsanti con gradiente, barre di scorrimento sottili, schede arrotondate, colonna stato colorata

---

## Struttura del Progetto

```
src/
└── main/
    ├── java/
    │   ├── module-info.java
    │   └── it/r2u/anibus/
    │       ├── AnibusApplication.java          # Punto di ingresso JavaFX
    │       ├── AnibusController.java           # Controller UI — collega tutti i servizi
    │       │
    │       ├── model/
    │       │   ├── PortScanResult.java          # Modello dati (7 campi)
    │       │   └── PortRegistry.java            # Tabelle di servizi e protocolli/cifratura
    │       │
    │       ├── service/
    │       │   ├── PortScannerService.java      # Coordinatore: sonda latenza e parsing intervallo
    │       │   ├── ScanTask.java                # Task<Void> in background con callbacks
    │       │   ├── BannerGrabber.java           # Acquisizione banner (HTTP HEAD / greeting raw)
    │       │   ├── VersionExtractor.java        # Estrazione versione software dai banner (regex)
    │       │   └── ExportService.java           # Esportazione CSV e XML con dialogo scelta formato
    │       │
    │       └── ui/
    │           ├── AlertHelper.java             # Dialoghi di avviso Anibus Design System
    │           ├── ClipboardService.java        # Utilità copia negli appunti
    │           └── TableConfigurator.java       # Configurazione colonne e celle della tabella
    │
    └── resources/
        └── it/r2u/anibus/
            ├── hello-view.fxml                  # Layout dell'interfaccia
            ├── anibus-style.css                 # Foglio di stile Anibus Design System
            └── app.properties                   # Versione runtime filtrata da Maven
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

1. Inserire l'**host di destinazione** (hostname o indirizzo IP)
2. Inserire l'**intervallo di porte** nel formato `inizio-fine` (es. `1-1024`)
3. Facoltativamente, regolare il **numero di thread**
4. Cliccare su **Start Scan**
5. Appare il **pannello informazioni host** con statistiche in tempo reale
6. I risultati popolano la tabella man mano che le porte vengono scoperte
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
