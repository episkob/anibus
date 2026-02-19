# Anibus — Scanner di Porte

Un'applicazione desktop moderna in stile iOS 17 per la scansione delle porte, realizzata con **JavaFX 22** e **Java 21**.

---

## Funzionalità

### Scansione
- Scansione di qualsiasi hostname o indirizzo IP alla ricerca di porte aperte
- Intervallo di porte configurabile (es. `1-1024`)
- Numero di thread regolabile (10–500, predefinito 100)
- Misurazione della **latenza** per ogni porta (ms)
- Interruzione della scansione in modo sicuro

### Estrazione delle Informazioni
- **Rilevamento automatico del servizio** per oltre 50 porte note (HTTP, SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Kubernetes API, ecc.)
- **Acquisizione banner** — le porte HTTP ricevono header completi tramite richiesta `HEAD`
- **Estrazione della versione software** dai banner (OpenSSH, Apache, nginx, ProFTPD, Postfix, ecc.)
- Rilevamento di protocollo e **cifratura** (TLS, STARTTLS, HTTPS, SMTPS, LDAPS, ecc.)

### Interfaccia e Flusso di Lavoro
- **Pannello informazioni host** — IP, hostname, tempo di scansione, porte analizzate, porte aperte, latenza media (aggiornamento in tempo reale)
- **Tabella risultati con 7 colonne** — Porta, Stato, Servizio, Versione, Protocollo, Latenza, Banner
- **Esportazione in CSV** con tutte le colonne
- **Cancellazione** dei risultati con un clic
- **Copia riga** o **copia tutti** tramite menu contestuale
- Risoluzione DNS automatica alla perdita del focus
- Design in stile iOS 17: barra di navigazione effetto vetro, pulsanti con gradiente, barre di scorrimento sottili, schede arrotondate, colonna stato colorata

---

## Struttura del Progetto

```
src/
└── main/
    ├── java/
    │   ├── module-info.java
    │   └── it/r2u/anibus/
    │       ├── AnibusApplication.java     # Punto di ingresso JavaFX
    │       ├── AnibusController.java      # Controller UI (FXML)
    │       ├── PortScannerService.java    # Scansione, banner, estrazione versioni
    │       └── PortScanResult.java        # Modello dati (7 campi)
    └── resources/
        └── it/r2u/anibus/
            ├── hello-view.fxml            # Layout dell'interfaccia
            └── ios-style.css              # Stili iOS 17
```

---

## Requisiti

| Strumento | Versione |
|-----------|----------|
| Java      | 21+      |
| JavaFX    | 22.0.1   |
| Maven     | 3.8+     |

---

## Compilazione e Avvio

```bash
# Clonare il repository
git clone https://github.com/your-username/anibus.git
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
8. Usare **Export** per salvare in CSV, oppure **Clear** per azzerare
9. Fare clic destro per copiare una riga o tutti i risultati

---

## Stack Tecnologico

- **Java 21** — linguaggio di programmazione
- **JavaFX 22** — framework UI
- **Maven** — strumento di build
- **FXML** — layout dichiarativo dell'interfaccia
- **CSS** — tema in stile iOS 17

---

## Licenza

Licenza MIT. Vedere il file `LICENSE` per i dettagli.
