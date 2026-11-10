# Scenario cyber-fisico (OT/Modbus): descrizione ad alto livello

## 1. Obiettivo

Lo scenario cyber-fisico (CPS) emula un piccolo impianto industriale di
distribuzione elettrica e riproduce, in un ambiente isolato e ripetibile, una
catena di attacco completa che parte dalla rete IT e arriva a produrre un effetto
fisico sull'impianto:

> intrusione IT → pivot verso la rete OT → scrittura Modbus non autorizzata →
> effetto fisico sul processo → rilevamento

Lo scenario serve a valutare se e con quale tempestività un sensore difensivo
passivo riesce a riconoscere l'attacco, idealmente prima che l'effetto fisico si
manifesti, e a misurare l'impatto sul processo quando l'attacco va a segno.

È indipendente dallo scenario MQTT/MTD già presente nel repository. Usa una
propria immagine dei nodi (`kathara/cps`) e un proprio lab Kathará (`cps`), e i
due scenari non interferiscono.

## 2. Architettura in sintesi

L'ambiente è diviso in tre zone di rete, separate da un firewall di confine
IT/OT:

```
        ZONA IT                 FIREWALL               ZONA OT
     10.10.0.0/24              IT/OT                10.20.0.0/24
  ┌──────────────────┐     ┌─────────────┐     ┌──────────────────────┐
  │ attaccante       │     │ FORWARD:    │     │ PLC                  │
  │ HMI / SCADA      │────▶│ DROP salvo  │────▶│ motore fisico        │
  │  (+ app web      │     │ HMI→motore  │     │  (gemello digitale   │
  │   vulnerabile)   │     │ Modbus/TCP  │     │   + server Modbus)   │
  └──────────────────┘     └─────────────┘     └──────────┬───────────┘
                                                          │ copia passiva
                                                          ▼ del traffico
                                               ┌──────────────────────┐
                                               │ sensore DPI Modbus   │
                                               │ (ZONA DIFESA,        │
                                               │  10.30.0.0/24)       │
                                               └──────────────────────┘
```

- **Zona IT**: ospita la postazione HMI/SCADA dell'operatore e l'attaccante.
- **Zona OT**: ospita il PLC e il "motore fisico", cioè il gemello digitale
  dell'impianto esposto in Modbus/TCP.
- **Zona difesa**: ospita il sensore. Il sensore ha un'interfaccia passiva sulla
  rete OT, da cui osserva il traffico senza trasmettere, e un'interfaccia di
  gestione separata su cui pubblica i risultati. Dalla rete OT l'interfaccia di
  gestione non è raggiungibile.
- **Firewall di confine**: blocca tutto il traffico IT→OT tranne un solo flusso
  autorizzato, quello dall'HMI al motore fisico su Modbus. L'attaccante quindi
  non può raggiungere direttamente l'impianto: deve prima compromettere l'HMI e
  usarla come trampolino. Le sue scritture arrivano così da un host legittimo.

## 3. Il processo fisico

Il processo controllato è una linea di distribuzione in bassa tensione (0,4 kV),
modellata con **pandapower** come un vero calcolo di flusso di potenza. Valori
come tensioni e carichi non sono sceneggiati: risultano dal calcolo.

```
rete esterna ──linea feeder (interruttore)── bus carico ──linea── bus generatore
  (slack)                                    (~50 kW)              (DG, 60 kW nominali)
```

- Un **carico** di circa 50 kW, con una variazione casuale riproducibile tramite
  seed.
- Un **generatore distribuito (DG)** con potenza nominale di 60 kW, che in
  condizioni normali eroga circa 20 kW.
- Due **attuatori**: il setpoint di potenza del DG e l'interruttore della linea.
  A questi si aggiunge un registro di **modalità di controllo** (AUTO/MANUALE).
- Uno **stato normale** definito da tensioni comprese tra 0,95 e 1,05 pu e da un
  carico di linea non superiore al 100%.

La linea è dimensionata in modo che anche un comando *lecito*, cioè il DG al
100% della potenza nominale, provochi una sovratensione. Questo è il punto che
rende interessante lo scenario: un comando può essere formalmente valido e
comunque pericoloso.

## 4. I componenti

| Componente | Ruolo | Dove |
|---|---|---|
| **Motore fisico** | Gemello digitale pandapower dietro un server Modbus/TCP. Le misure (tensioni, carichi, potenze, flag di anomalia) sono *input register*, gli attuatori sono *holding register*. | OT |
| **PLC** | Master Modbus e unico regolatore legittimo. In AUTO legge le misure, tiene la tensione nella banda di regolazione, rifiuta setpoint fuori dall'inviluppo e riporta il DG al valore nominale di 20 kW. In MANUALE cede il controllo all'operatore. | OT |
| **HMI / SCADA** | Client IT legittimo. Interroga periodicamente l'impianto e circa ogni 12 s esegue un dispacciamento operatore sicuro: passa in MANUALE, imposta 15–35 kW per qualche secondo e torna in AUTO. È il comportamento "normale" che il sensore deve distinguere dall'attacco. | IT |
| **App diagnostica vulnerabile** | Piccola web app sull'host HMI con una reale command injection, che offre all'attaccante l'esecuzione di codice da remoto. È volutamente insicura e confinata nel lab. | IT |
| **Attaccante** | Sfrutta l'app, ottiene RCE sull'HMI e da lì invia scritture Modbus verso il motore fisico. | IT |
| **Sensore DPI Modbus** | Analizza passivamente richieste e risposte Modbus, ricostruisce lo stato dell'impianto e produce *finding* e *alert*. | Difesa |

Tutti i nodi condividono un unico **contratto d'impianto**
(`defense_plane/ot_registers.py`), che definisce la mappa dei registri, le
scale, gli inviluppi validi dei comandi, la policy di accesso per ruolo (chi può
leggere e scrivere cosa) e le bande operative.

## 5. Gli scenari di attacco

La fase iniziale è la stessa per tutti gli scenari: exploit dell'app
diagnostica, esecuzione di codice sull'HMI e pivot attraverso il firewall
usando l'indirizzo dell'HMI. Cambia invece l'azione eseguita sull'impianto:

| Modalità | Azione | Effetto fisico | Difficoltà di rilevamento |
|---|---|---|---|
| `setpoint-overvoltage` | Imposta il setpoint del DG a un valore fuori dall'inviluppo (200 kW). | Sovratensione al bus del DG e sovraccarico di linea. Il PLC rifiuta il valore e l'impianto rientra. | Bassa: il comando è palesemente fuori range. |
| `breaker-open` | Apre l'interruttore della linea, che per policy nessuno deve comandare da remoto. | La sezione a valle resta senza alimentazione e l'impatto persiste. | Bassa: è una violazione della policy di ruolo. |
| `manual-hijack` | Prende l'autorità MANUALE e dispaccia 60 kW, entro i limiti del DG. | Sovratensione persistente: il PLC si è fatto da parte e l'effetto resta anche dopo che l'attaccante se ne va. | Alta: ogni valore è lecito e la sorgente è l'HMI, quindi le regole basate su sorgente e range non bastano. |

Ogni scrittura dell'attaccante viene registrata con il suo istante di emissione
(*ground truth*). Su questa base si calcolano le metriche di rilevamento.

## 6. Il rilevamento

Il sensore usa solo librerie standard e numpy. Decodifica a mano i frame
Ethernet/IP/TCP/Modbus e accoppia ogni richiesta alla sua risposta, così da
conoscere sia i comandi inviati sia lo stato osservato dell'impianto. Lavorano in
parallelo due rilevatori, e ogni finding indica quale dei due l'ha prodotto.

**Regole (rules):**
- comando fuori range;
- client sconosciuto, in lettura o in scrittura;
- violazione della policy di ruolo, per esempio una scrittura sull'interruttore;
- *unsafe command*: una scrittura sensibile seguita dall'uscita della tensione
  osservata dalla banda normale;
- *manual mode excursion*: impianto in MANUALE mentre è fuori banda.

**Modello comportamentale (model):**
- calcola feature al secondo, tra cui ricambio delle sessioni, ampiezza dei salti
  di setpoint, tempo in MANUALE e tensioni osservate;
- assegna un punteggio con un modello robusto (mediana/MAD) calibrato online sui
  primi secondi della fase normale;
- valuta la finestra corrente subito a ogni scrittura, così da poter segnalare
  un'anomalia prima che l'effetto fisico si manifesti.

Gli alert vengono sollevati una sola volta e chiusi quando la condizione cessa.
Finding e alert viaggiano sul bus di telemetria e sulla dashboard già usati
dallo scenario MTD.

## 7. Svolgimento di un esperimento

Ogni esecuzione segue sempre la stessa sequenza di fasi:

1. **deploy**: avvio del lab Kathará a tre zone e configurazione del firewall.
2. **services**: avvio del motore fisico, del PLC, dell'HMI, dell'app
   vulnerabile e del sensore.
3. **normal**: esercizio normale, di default 60 s. Nei primi 45 s il modello
   comportamentale si calibra.
4. **attack**: esecuzione della catena d'attacco nella modalità scelta. Questa
   fase manca nelle esecuzioni di sola operatività normale.
5. **post_attack**: osservazione del comportamento dell'impianto dopo l'attacco,
   di default 30 s.
6. **download / undeploy**: raccolta dei log (frame, finding, ground truth) e
   smantellamento del lab.

Un'esecuzione dura circa 1 minuto in modalità normale e circa 1 minuto e mezzo
con attacco. Le **campagne** ripetono la griglia *modalità × seed* in modo
riproducibile. Sono riprendibili e producono un riepilogo aggregato. Una
**dashboard di avanzamento** locale mostra fasi, tempo stimato, tensioni dei bus
in tempo reale, finding e risultati.

## 8. Cosa si misura

**Sul rilevamento**, per ciascun rilevatore (regole, modello, combinato):
- tasso di rilevamento;
- latenza misurata dall'inizio dell'attacco e dalla prima scrittura malevola;
- se il rilevamento è avvenuto prima dell'impatto fisico;
- falsi allarmi, e quanti di questi cadono durante i dispacciamenti legittimi
  dell'operatore.

**Sull'impianto:**
- tempo all'impatto e durata dell'impatto;
- massima deviazione di tensione;
- se l'impatto persiste dopo l'attacco o se l'impianto rientra;
- tempo trascorso in MANUALE;
- energia.

Le prime esecuzioni di verifica, singole e con seed fisso, danno risultati
indicativi:

- gli attacchi rumorosi vengono rilevati in pochi centesimi di secondo dalla
  prima scrittura;
- nel `manual-hijack` il modello comportamentale segnala l'attacco prima
  dell'impatto, mentre le regole se ne accorgono solo a impatto avvenuto;
- in operatività normale non si sono registrati falsi allarmi.

Una valutazione statistica su più seed è affidata alle campagne.

## 9. Perimetro e sviluppi futuri

Lo scenario copre le fasi **1–4** del prototipo: fondamenta, emulazione OT,
confine IT/OT e rilevamento.

Sopra queste fasi c'è ora un **primo prototipo di risposta**
(`defense_plane/soar/`, attivabile con `CPS_RESPOND=rules|solver`; dettagli nel
README, sezione "Response (SOAR prototype)"). Comprende:

- un knowledge graph del lab;
- l'albero di attacco della catena;
- il mapping dai finding ai nodi dell'albero;
- le contromisure eseguibili nel lab;
- due policy: un playbook a regole fisse e un primo risolutore a costo
  atteso;
- un'approvazione dell'operatore simulata.
- una **telemetria IT sull'HMI** (`CPS_IT=1`): un sensore lato host
  (`defense_plane/agents/it_sensor.py`) che rende osservabili i primi passi
  dell'attacco — accesso all'app web, esecuzione di comandi, pivot — che il
  sensore OT può solo inferire. Impara il normale (traffico diagnostico
  legittimo) nella fase iniziale. Con questa telemetria la difesa ferma
  l'attacco **prima** che l'impianto venga toccato; senza, può reagire solo
  alla scrittura.
- un **attaccante guidato dall'albero** (`CPS_ATTACK_DRIVER=planner`): invece di una sequenza
  fissa, un pianificatore cammina sull'albero d'attacco e sceglie il passo successivo in base
  allo stato, componendo le stesse primitive del lab (nessuna nuova capacità offensiva, solo
  per il lab). Reagisce agli esiti: se una contromisura gli chiude una strada, ne prova
  un'altra o si ferma. È anche l'avversario baseline del gioco di WP3.

È un prototipo in piccolo, pensato per fissare le interfacce di WP2 e WP3
(vedi [piano-wp2-wp3.md](piano-wp2-wp3.md)). Restano da fare:

- la generazione automatica degli alberi;
- il modello a gioco stocastico;
- la misura energetica reale delle contromisure;
- un nodo SOAR dentro il lab al posto del risponditore lato host.

## 10. Riferimenti rapidi

| Cosa | Dove |
|---|---|
| Contratto d'impianto (registri, policy, bande) | `defense_plane/ot_registers.py` |
| Gemello digitale e server Modbus | `traffic_generator/agents/grid_sim.py`, `modbus_engine.py` |
| PLC e HMI | `traffic_generator/agents/plc_controller.py`, `hmi_client.py` |
| Catena d'attacco | `attack_plane/agents/`, `attack_plane/active_attack.py` |
| Sensore e modello | `defense_plane/agents/ot_sensor.py`, `ot_model.py` |
| Lab e orchestrazione | `network_scenario/cps_experiment.py`, `cps_campaign.py` |
| Metriche e dashboard | `monitor/cps_metrics.py`, `cps_dashboard.py` |
| Comandi | `make cps-selftest`, `cps-image`, `cps-lab`, `cps-attack`, `cps-campaign`, `cps-dashboard`, `cps-metrics` (dettagli nel README) |
