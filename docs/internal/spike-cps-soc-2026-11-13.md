# Prova `cps-soc` — 2026-11-13

Branch `spike/cps-soc`. Documento di lavoro, non documentazione della piattaforma.

## Domanda

Si può dare al blue team le due dashboard di un SOC reale, entrambe open source,
dentro il lab e con ogni servizio su un nodo suo come nei deployment ufficiali?

- **SIEM**: Wazuh indexer + Wazuh dashboard 4.14.10, la versione del manager già
  nel lab. Il manager spedisce gli alert all'indexer con Filebeat, come fa un
  server Wazuh.
- **Gestione dei casi**: DFIR-IRIS v2.4.29 (LGPL-3.0) a cinque servizi: web,
  app, worker, Postgres, RabbitMQ. Il SOC deposita ogni contromisura che
  propone come task del caso del run; l'analista lo chiude (approva) o lo
  annulla (rifiuta).

Esclusi: TheHive 5, che non è più open source (licenza proprietaria freemium);
Shuffle, il cui orchestratore vuole il socket Docker dentro il container.

## Risposte

| # | domanda | risultato | soglia |
|---|---|---|---|
| 1 | Le immagini ufficiali girano come nodi Kathará? | Sì. Postgres e RabbitMQ senza modifiche; gli altri con uno strato sottile (vedi sotto) | ✓ |
| 2 | "Task chiuso = approvato, annullato = rifiutato" via API? | Sì, giro completo provato dal vivo e nei test | ✓ |
| 3 | Quanto pesa? | **≈ 3,0 GB** di RAM per i sette nodi nuovi, +0,26 GB sul nodo SOC (Filebeat); entrambe le interfacce rispondono **≈ 20 s** dopo il deploy | ≤ 6 GB, ≤ 4 min ✓ |
| 4 | Il giro completo funziona nel lab? | Sì: finding → alert in Wazuh → task in IRIS → chiuso dall'analista → contromisura eseguita → ledger e punteggio | ✓ |
| 5 | Si smonta pulito e riparte da zero? | Sì: nessun container né volume residuo; il run successivo riparte da un IRIS vuoto | ✓ |

**Proposta: proseguire.** Le cinque soglie sono rispettate, con margine sulla
memoria e sui tempi. I punti da sistemare prima di farne uno scenario stabile
sono nei "Limiti noti" in fondo.

### Memoria, a regime durante una partita

| nodo | servizio | RAM |
|---|---|---|
| indexer | Wazuh indexer (heap 1 GB) | 1,43 GB |
| wazuhui | Wazuh dashboard | 0,19 GB |
| irisworker | worker Celery di IRIS | 0,97 GB |
| irisapp | applicazione IRIS | 0,18 GB |
| irismq | RabbitMQ | 0,13 GB |
| irisdb | Postgres | 0,05 GB |
| irisweb | nginx di IRIS | 0,01 GB |
| **totale nuovi nodi** | | **≈ 2,97 GB** |

Host: 46 GB, arm64, `vm.max_map_count` già a 1048576 (OpenSearch non richiede
modifiche al sistema).

## Cosa ha richiesto uno strato nostro

Immagini in `docker/`: `wazuh-pki`, `soc-siem`, `wazuh-indexer`,
`wazuh-dashboard`, `iris-app`, `iris-web`. Ogni strato è sottile e ha una ragione
precisa:

- **Root nel container.** Kathará esegue i comandi d'avvio del nodo con l'utente
  dell'immagine; le immagini Wazuh e nginx girano non root e non potrebbero
  darsi un indirizzo. Il servizio torna comunque al suo utente: l'entrypoint
  dell'indexer lo fa da sé, per la dashboard (che rifiuta root) lo script
  d'avvio usa `chroot --userspec=1000:1000`, perché `runuser` e `su` mancano.
- **`ip`, `iptables`, `tar`.** Kathará copia i file del nodo spacchettando un
  tar *dentro* il container: senza `tar` il nodo parte senza i suoi file, script
  d'avvio compreso. È il difetto che ha fatto fallire la prima partita (vedi
  sotto).
- **`WORKDIR /`.** La piattaforma cerca il log di console di un servizio nella
  radice; le immagini ufficiali lavorano altrove (`/iriswebapp`, …).
- **Una sola autorità di certificazione.** `kathara/wazuh-pki` genera la CA del
  lab e i certificati di indexer, dashboard, Filebeat e IRIS; le altre immagini li
  copiano da lì. Generati immagine per immagine, verrebbero da CA diverse e
  nessun servizio si fiderebbe degli altri.
- **Il nodo resta in attesa su una shell** (`entrypoint` nuovo nel `Node` del
  core, scritto solo se valorizzato: gli snapshot degli altri scenari non
  cambiano). L'entrypoint di un'immagine di servizio partirebbe subito, prima
  che il lab l'abbia configurata (Postgres esce senza password); lo avvia un
  componente, come per gli altri nodi.

Altri accorgimenti di Kathará: i nomi dei nodi non ammettono il trattino
(`irisdb`, `wazuhui`, …).

## Con quale utente gira ogni processo

Come nei deployment ufficiali, dove ogni servizio ha il suo utente:

| processo | utente | note |
|---|---|---|
| Wazuh indexer, dashboard | `wazuh-indexer`, `wazuh-dashboard` (uid 1000) | il container è root solo per Kathará |
| Wazuh manager | `wazuh` | dal pacchetto |
| Filebeat | root, come nel pacchetto Wazuh; **nell'indexer scrive come `filebeat`**, ruolo `wazuh_shipper`: template, pipeline e scrittura degli alert, nient'altro (verificato: elencare gli indici o leggere la sicurezza → 403) | |
| nginx di IRIS | `www-data` (uid 33), come nell'immagine IRIS | il log di console va dato a `www-data`, altrimenti nginx non parte |
| Postgres, RabbitMQ | `postgres`, `rabbitmq` | dagli entrypoint ufficiali |
| app e worker IRIS | root | come nell'immagine IRIS |

Utenti dell'indexer, tutti con password per run: `admin` (non consegnato a
nessuno), `filebeat`, `kibanaserver` (la connessione della dashboard), `blue`
(il login del blue team).

## Il ponte SOC → IRIS

`nodes/soc/iris_desk.py`, software di nodo con la sola libreria standard, offre
al SOC la stessa interfaccia del banco di oggi (`open`, `close`, `take`,
`take_orders`, `publish`). Il resto del SOC non cambia, e il ledger riceve gli
stessi eventi `approval`: la dashboard di controllo mostra i suggerimenti come
prima.

Verificato dal vivo su IRIS 2.4.29:

- stati dei task: 1 To do, 2 In progress, 3 On hold, 4 Done, 5 Canceled;
- un analista deve stare nel gruppo Administrators, oppure avere accesso al
  singolo caso; lo scenario crea l'account `blue` negli Administrators;
- **attribuzione**: il cambio di stato dal menu rapido della lista task non
  registra chi l'ha fatto, mentre la modifica del task sì. L'approvazione
  funziona in entrambi i casi; il verdetto è attribuito all'account della
  squadra (`blue`);
- **IRIS è lento nelle prime richieste.** Nella prima partita un task è stato
  creato sul server mentre il client andava in timeout, ed è stato depositato tre
  volte. Corretto: deposito idempotente (si adotta il task già depositato con lo
  stesso id di richiesta) e timeout a 20 s, con un test che riproduce il caso.

## Le azioni a mano, dai menu di IRIS

Le leve della console di oggi (applicare o revocare una contromisura, far agire
il SOC da solo o farlo consigliare) sono voci dei menu di IRIS, aggiunte da un
modulo IRIS nostro (`nodes/soar/iris_soc_response/`), come fanno i moduli
ufficiali di IRIS (VirusTotal, MISP, …):

- il SOC deposita nel caso il **catalogo** delle contromisure del lab, un task
  ciascuna, in stato *On hold*, con macchina, comandi di applicazione e revoca,
  D3FEND;
- sul menu di un task, "SOC: apply / revert this countermeasure"; sul menu del
  caso, "SOC: act alone (automatic)" e "SOC: advise (wait for approval)";
- la voce deposita un **task d'ordine**; il banco del SOC lo prende, lo esegue
  per la stessa strada della console di oggi e lo chiude (*Done*, o *Canceled*
  con il motivo se la contromisura non è del lab). IRIS è l'unico canale: il
  worker di IRIS non raggiunge il SOC.

Il formato degli ordini sta in un solo file (`orders.py`), copiato nel modulo e
sul SOC (`/iris_orders.py`), così le due parti non possono divergere.

Due scoperte, verificate sul sorgente e dal vivo:

- **In IRIS 2.4.29 le voci asincrone non funzionano**: il worker non carica la
  chiave con cui verifica i dati accodati (`SECRET_KEY` assente con
  `IRIS_WORKER`), e ogni voce eseguita lì fallisce. Le nostre sono registrate
  *sincrone*: le esegue l'app, dentro la richiesta dell'analista.
- **Proprio per questo l'ordine porta il nome dell'analista** (`by:<login>`), a
  differenza delle approvazioni dal menu rapido dello stato.

Vincolo del repo rispettato: `nodes/` non contiene pacchetti Python
(`test_nodes_is_not_a_package`). Il file radice del pacchetto sta sull'host come
`iris_module_init.py` ed è copiato nel container come `__init__.py`: il nome
sull'host è libero, quello nel container è il contratto.

Verifica dal vivo (`output/cps-soc/spike-5`, lab senza attacco): catalogo di 4
contromisure, voci nei menu, "apply" su `block_flow` e "act alone" sul caso;
il SOC è passato in automatico ed ha eseguito `block_flow` (ok), entrambe sul
ledger con l'utente che le ha chieste.

## Gli alert di Wazuh nel triage di IRIS

Gli alert che meritano l'occhio di un analista arrivano nella pagina **Alerts**
di IRIS, come fanno le integrazioni ufficiali di Wazuh (Shuffle, Slack): un
integratore personalizzato, `custom-iris` (`nodes/wazuh/manager/iris_forward.py`),
lanciato dal manager con il lanciatore Python di Wazuh, solo libreria standard.

- **Cosa passa** (scelta con l'utente): gli alert del sensore OT quando si aprono
  (regola 100101, stato `raised`: uno per episodio) e ogni finding del sensore IT
  sull'HMI (regola 100100, detector `it`). I singoli finding OT restano nella
  dashboard Wazuh.
- **Cosa porta**: titolo con l'host, gravità (High per IT o confidenza ≥ 0,9,
  altrimenti Medium), l'evento Wazuh grezzo, l'host come **asset** e l'IP
  sorgente come **IOC**; gli id di gravità, stato e tipi li ricava per nome da IRIS.
- **Triage** (scelta con l'utente): è l'analista a unire l'alert al caso del run,
  scalarlo o chiuderlo. Verificato: l'unione porta l'alert in stato *Merged*,
  collegato al caso.
- **Aggregazione**, come in un SIEM: stesso host, regola, classe e sorgente entro
  120 s aggiornano la nota dell'alert aperto ("Seen N times") invece di aprirne
  un altro. Non è fatta nelle regole Wazuh, perché l'analytics del SOC deve
  continuare a leggere ogni finding.

Dal vivo, con il sensore IT acceso: senza aggregazione 14 alert, di cui otto
"unexpected_modbus_client" uguali (una per connessione Modbus dell'attaccante);
con l'aggregazione **6**, tra cui uno "seen 8 times". Restano due
"unsafe_command" distinti, ed è giusto: uno dall'HMI (l'attaccante), uno dal PLC
(la sua scrittura correttiva), che l'analista dovrebbe chiudere come effetto
collaterale. È un caso di triage realistico.

## Partita completa

`make cps-soc CPS_SOC_OUT=output/cps-soc/spike-2 SEED=1 CPS_ADVISOR_POST=150`:
attacco predefinito (`setpoint-overvoltage`), policy `solver`, suggerimenti in
attesa per 120 s. Durante il run ho fatto l'analista via API di IRIS.

- **Avvio**: 14 nodi, deploy in 5 s. IRIS e la dashboard Wazuh rispondono
  ~20 s dopo il deploy, ben dentro la fase normale (60 s). La fase `services` non
  aspetta gli strumenti, quindi la sua durata pianificata e l'ETA della dashboard
  di controllo restano corrette.
- **SIEM**: il blue team entra nella dashboard Wazuh con le credenziali del run
  (`blue`, HTTP 200). Nell'indexer 39 alert, tra cui le regole del lab: 100100
  (finding), 100101 (alert), 100110 (scritture della risposta), 100120 (esiti
  delle contromisure).
- **Casi**: il SOC ha creato il caso del run e l'account `blue`, poi ha
  depositato due task, uno per contromisura, con motivazione, nodi coperti e
  comandi. Il riepilogo del caso si aggiorna ogni 10 s con la credenza sull'albero.
- **Approvazione**: chiusi i due task, il SOC li ha registrati come approvati da
  `blue` dopo ~3 s ed eseguito `block_flow` e `force_auto` (entrambe ok).
- **Ledger e punteggio**: 4 eventi `approval` (2 richieste, 2 approvate), 2
  `action`; nel punteggio `suggestions_approved 2/2`, latenza mediana
  dell'operatore 2,8 s. La card "Operator suggestions" della dashboard di
  controllo li mostra come per `cps-advisor`.

**La prima partita (`spike-1`) era fallita a metà**, e i due difetti trovati sono
corretti nel branch:

1. indexer e dashboard Wazuh partiti senza i loro file: alle immagini Amazon
   Linux mancava `tar` (vedi sopra);
2. un task depositato tre volte per i timeout di IRIS nelle prime richieste.

Nella stessa partita la scadenza ha funzionato: senza risposta, dopo 120 s i
task sono stati annullati con la nota "Expired".

Non provato dal vivo: la partita a squadre (`make cps-soc-teams`), che resta su
fino a Ctrl-C.

## Limiti noti della prova

- Le porte pubblicate (8770, 8771) sono protette solo dalle credenziali del run,
  come le console di oggi dai token.
- Il punteggio di risposta segna `over_response: force_auto` anche qui: è la
  metrica di `cps`, non un effetto della prova.

## Cosa c'è nel branch

| dove | cosa |
|---|---|
| `cyberrange/core/topology.py` | `Node.entrypoint`, opzionale |
| `cyberrange/planes/defense/components.py` | `WazuhIndexer`, `WazuhDashboard`, `AlertShipper`, `IrisService`; `SocAnalytics(iris=…)` |
| `cyberrange/scenarios/cps_soc/` | lo scenario (eredita da `cps-advisor`), manifest, CLI, pannello |
| `nodes/soc/iris_desk.py`, `nodes/soc/soc_analytics.py` | il banco su IRIS (suggerimenti, catalogo, ordini) e l'opzione `--desk iris` |
| `nodes/soar/iris_soc_response/` | il modulo IRIS con le voci di menu del SOC |
| `nodes/wazuh/manager/iris_forward.py`, `wazuh-iris-integration.sh` | l'integrazione Wazuh → alert IRIS e la sua installazione |
| `nodes/wazuh/{indexer,dashboard,manager}/`, `nodes/soar/iris-start.sh` | configurazioni e script d'avvio |
| `docker/{wazuh-pki,soc-siem,wazuh-indexer,wazuh-dashboard,iris-app,iris-web}/` | le immagini; `make cps-soc-image` |
| `make/cps-soc.mk` | `cps-soc-image`, `cps-soc`, `cps-soc-lab`, `cps-soc-teams`, `cps-soc-dashboard` |
| `tests/` | `test_iris_desk.py` (13), `test_iris_module.py` (5), `test_iris_forward.py` (14), `tests/scenarios/cps_soc/` (11), entrypoint nel core, versioni Wazuh allineate anche per indexer e dashboard, `lab-cps-soc.json` |

Suite: 514 test verdi; snapshot degli altri lab invariati.

Verifica dopo le correzioni sugli utenti (`output/cps-soc/spike-4`): tre
suggerimenti approvati in IRIS, tre contromisure eseguite (`block_flow`,
`force_auto`, `restore_breaker`), Filebeat collegato come `filebeat` senza
rifiuti, nginx interamente `www-data`, smontaggio pulito.
