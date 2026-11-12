# Playground red team contro blue team

Guida per chi gioca e per chi arbitra. Spiega lo scenario, cosa ha in mano
ciascuna squadra e cosa può fare. I dettagli tecnici di come è costruito sono in
[scenario-cps-advisor.md](scenario-cps-advisor.md) e [scenario-cps.md](scenario-cps.md).

## 1. Lo scenario in breve

Un piccolo impianto di distribuzione elettrica in bassa tensione, emulato: una
linea con un generatore distribuito (DG) e un interruttore, regolata da un PLC.
L'impianto è un gemello digitale: tensioni e carichi sono calcolati, non recitati,
quindi un comando sbagliato produce davvero una sovratensione o un distacco.

- Il **red team** parte da una macchina sulla rete degli uffici (IT) e vuole
  produrre un effetto fisico sull'impianto.
- Il **blue team** siede nel SOC: vede ciò che i sensori rilevano, riceve i
  suggerimenti del sistema di risposta e decide cosa applicare.
- L'**arbitro** osserva entrambe le squadre da una dashboard in sola lettura.

Il SOC qui **non agisce da solo**: propone ogni contromisura con la sua
spiegazione e aspetta che una persona la approvi. Un suggerimento senza risposta
scade e non viene applicato.

## 2. La mappa

```
      RETE IT 10.10.0.0/24          FIREWALL            RETE OT 10.20.0.0/24
   ┌────────────────────────┐   10.10.0.1 | 10.20.0.1   ┌───────────────────────┐
   │ attacker   10.10.0.10  │   ┌──────────────────┐    │ plc      10.20.0.10   │
   │ hmi        10.10.0.20  │──▶│ passa solo        │──▶│ engine   10.20.0.20   │
   │  (postazione operatore │   │ HMI → engine      │    │  (impianto, Modbus    │
   │   + app diagnostica)   │   │ Modbus tcp/5020   │    │   tcp/5020)           │
   └───────────┬────────────┘   └────────┬─────────┘    └──────────┬────────────┘
               │                          │                         │ ascolto passivo
   ────────────┴──────────────────────────┴─────────────────────────┴────────────
      RETE DI GESTIONE (MGMT) 10.30.0.0/24
      hmi 10.30.0.30    firewall 10.30.0.1    sensor 10.30.0.10    soc 10.30.0.20
```

Tre fatti da tenere a mente:

1. **L'attaccante non raggiunge l'impianto direttamente.** Il firewall lascia
   passare verso la rete OT un solo flusso: dall'HMI all'engine, in Modbus.
2. **L'HMI è l'unica porta.** È la postazione dell'operatore, ha un'applicazione
   web di diagnostica vulnerabile ed è collegata a tutte e due le reti che
   contano: IT e gestione.
3. **Il sensore ascolta senza parlare.** Vede tutto il traffico Modbus della rete
   OT e manda ciò che rileva al SOC sulla rete di gestione.

### I comandi dell'impianto

L'impianto si comanda scrivendo tre registri Modbus sull'engine:

| Registro | Nome | Significato | Valori |
|---|---|---|---|
| 0 | `dg_setpoint` | potenza richiesta al generatore | kW × 10; normale 200 (= 20 kW), massimo ammesso 600 (= 60 kW) |
| 1 | `switch_cmd` | interruttore della linea | 0 = chiuso, 1 = aperto |
| 2 | `ctrl_mode` | chi regola | 0 = AUTO (il PLC), 1 = MANUAL (l'operatore) |

In AUTO il PLC corregge da solo un setpoint sbagliato. In MANUAL si fa da parte:
ciò che viene scritto resta.

## 3. Come si svolge una partita

1. L'arbitro avvia la dashboard di controllo e il laboratorio:
   ```sh
   make dashboard      # http://127.0.0.1:8765
   make cps-teams
   ```
2. Il laboratorio sale e per circa un minuto l'impianto lavora normalmente: il
   sensore impara com'è il traffico normale. **Il blue team entra subito**, il
   red team no.
3. Finita la calibrazione **entra il red team** e la partita comincia.
4. La partita dura finché l'arbitro non chiude con Ctrl-C. Alla chiusura tutto
   ciò che è successo viene salvato nella cartella del run.

A ogni squadra l'arbitro consegna **due link**, e nient'altro: la console e il
terminale. Sono stampati sul terminale da cui è partito il laboratorio (quelli
del red team solo a calibrazione finita) e scritti in
`output/cps-advisor/run-1/teams.json`. Ogni link contiene il segreto della
squadra: chi ha il link entra.

| | Console | Terminale |
|---|---|---|
| Blue team | `http://127.0.0.1:8766/#token=…` | `http://blue:…@127.0.0.1:8767/` |
| Red team | `http://127.0.0.1:8768/#token=…` | `http://red:…@127.0.0.1:8769/` |

## 4. Red team

### Obiettivo

Arrivare a un effetto fisico sull'impianto. Ce ne sono tre, diversi per rumore e
per durata:

| Effetto | Come | Quanto si nota | Cosa succede |
|---|---|---|---|
| Setpoint fuori scala | potenza del DG oltre il massimo | molto | il PLC lo rifiuta e recupera: va ripetuto per avere effetto |
| Apertura dell'interruttore | `switch_cmd = 1` | molto | la linea si stacca finché qualcuno non richiude |
| Presa del controllo manuale | `ctrl_mode = 1`, poi un setpoint alto ma lecito | poco | ogni valore è nella norma e arriva dall'HMI; il PLC non corregge, l'effetto resta |

### La strada

L'impianto si raggiunge solo passando dall'HMI, in quest'ordine:

1. **Accesso iniziale**: sfruttare l'applicazione di diagnostica dell'HMI.
2. **Esecuzione di comandi** sull'HMI.
3. **Pivot**: dall'HMI, raggiungere l'engine sulla porta Modbus.
4. **Azione sull'impianto**: una delle tre scritture sopra.

### La console

Elenca questi passi, ciascuno con la tecnica ATT&CK, quanto è rumoroso e il
comando esatto che esegue. **Run** lo lancia e mostra ciò che ha stampato.

- Un passo marcato *not ready* ha un prerequisito non ancora riuscito. Si può
  provare lo stesso: fallirà, e lo vedrete.
- Si esegue un passo alla volta.
- Lo storico in basso conserva l'esito di ogni tentativo.

### Il terminale

Una shell di root sulla macchina `attacker`, per tutto ciò che la console non
prevede: guardarsi intorno sulla rete IT, provare a mano i comandi che i passi
automatizzano, scrivere i registri Modbus con parametri propri. Gli strumenti
sono già sulla macchina (`exploit_client.py`, `ot_write.py`, `curl`, `python3`).

Attenzione: **ogni comando digitato è registrato**, e una scrittura Modbus fatta
a mano dalla shell, invece che da un passo della console, finisce nel registro
dei comandi ma non tra gli effetti valutati. Per farsi riconoscere il merito di
un effetto, conviene passare per i passi della console.

## 5. Blue team

### Obiettivo

Accorgersi dell'attacco, idealmente **prima** che l'impianto ne risenta, e
fermarlo con il minimo danno — senza, per esempio, staccare l'operatore legittimo
se basta un blocco al confine.

### La console

Mostra, aggiornata in continuo:

- **Suggerimenti**: ciò che il SOC propone di fare. Ogni suggerimento dice cosa
  ha visto il sensore, cosa l'azione previene o ripristina, quanto è sicuro il
  SOC, quanto costa, i comandi esatti che eseguirà e le alternative scartate. Si
  **Approva** o si **Rifiuta**, con un conto alla rovescia: senza risposta, scade.
- **Contromisure**: le si può applicare o revocare di propria iniziativa, senza
  aspettare un suggerimento.
- **Albero dell'attacco**: cosa il SOC crede che l'attaccante abbia fatto, passo
  per passo, con il livello di certezza.
- **Rilevamenti** e **risposte**: cosa i sensori hanno segnalato e cosa è stato
  eseguito, su quale host e per volontà di chi.

In alto si sceglie la **modalità del SOC**:

- **Advise** (predefinita): niente parte senza approvazione.
- **Automatic**: il SOC esegue da solo ciò che la sua policy decide. Utile per
  lasciargli le contromisure ovvie e concentrarsi sulle decisioni difficili.

### Le contromisure

| Contromisura | Dove | Effetto | Si revoca |
|---|---|---|---|
| `notify` | nessuno | solo avvisa, non esegue nulla | — |
| `block_flow` | firewall | blocca il flusso Modbus HMI → impianto al confine | sì |
| `isolate_hmi` | hmi | stacca l'HMI dalla rete (anche l'operatore legittimo) | sì |
| `force_auto` | firewall | riporta il controllo al PLC e il setpoint al valore nominale | — |
| `restore_breaker` | firewall | richiude l'interruttore | — |

Se la partita è avviata con il sensore lato IT (`CPS_IT=1`) il SOC vede anche i
primi passi dell'attacco sull'HMI, e si aggiungono due contromisure: `kill_proc_tree`
(termina i processi avviati dall'attaccante sull'HMI) e `block_web_src` (blocca
l'indirizzo da cui arriva l'attacco all'applicazione di diagnostica).

`block_flow` taglia la strada all'attaccante lasciando in piedi l'HMI;
`isolate_hmi` è più drastica (l'operatore perde la postazione) e per questo è
quella che il SOC segnala come più delicata.

### Il terminale

Una shell sul SOC, che è anche il ponte verso gli altri host della difesa: da qui
`ssh firewall`, `ssh sensor`, `ssh hmi` funzionano sulla rete di gestione. Serve
per guardare lo stato di un host, le regole del firewall, i log — tutto ciò che
la console non mostra. Anche qui ogni comando è registrato.

## 6. Arbitro (control dashboard)

`make dashboard`, in sola lettura: non può agire sul laboratorio. Vede tutto ciò
che le due console tengono separato, su un'unica linea del tempo:

- le fasi del run e lo stato dell'impianto;
- i **suggerimenti** del SOC con il loro esito (approvato, rifiutato, scaduto),
  come storico;
- una scheda **Teams** con, in ordine di tempo, i passi del red team, le azioni
  del blue team e **ogni comando digitato da entrambi**, con l'host e la squadra.

Su un host della difesa la squadra di un comando si legge da come la shell è
arrivata lì:

- **blue** — via SSH dal SOC;
- **red** — una shell ottenuta attraverso l'applicazione vulnerabile dell'HMI (o
  lasciata in esecuzione da un servizio), oppure SSH da un host che non è il
  SOC: è il segno che l'attaccante ha preso quell'host;
- **control** — tutto il resto, cioè la shell dell'arbitro
  (`kathara connect`). Compare nella scheda Teams ma non nel `ground_truth`:
  l'arbitro può guardare dentro un nodo senza che conti come attacco.

## 7. Cosa separa le due squadre

- Ogni console e ogni terminale richiede il **token** della propria squadra. I
  token sono diversi, generati a ogni partita, e non finiscono mai sul registro
  che l'arbitro legge.
- Sulle reti del laboratorio le porte delle console sono chiuse: dall'HMI non si
  raggiunge la console del blue team, né viceversa.
- Resta una via tecnica: un nodo con una porta pubblicata può raggiungere
  l'host e da lì la porta dell'altra squadra. A fermarlo c'è solo il token —
  quindi **non condividete i link fuori dalla vostra squadra**.

## 8. Cosa resta dopo la partita

Nella cartella del run (`output/cps-advisor/run-1/`):

- `ground_truth.jsonl` — cosa è successo davvero (passi del red team, scritture
  Modbus, comandi);
- `progress.jsonl` — la linea del tempo che l'arbitro ha visto;
- `response.jsonl` — suggerimenti, verdetti e azioni del SOC;
- `<host>.commands.jsonl` e `<host>.terminal.typescript` — i comandi e la
  trascrizione di ogni terminale;
- `teams.json` — i link consegnati alle squadre.

Il punteggio si calcola come per lo scenario `cps`:
`make cps-metrics CPS_OUT=output/cps-advisor/run-1`. Tenete presente che qui i
tempi includono quello degli operatori, e che un effetto ottenuto con una
scrittura a mano dalla shell (invece che da un passo) si vede nell'impianto ma
non tra gli effetti valutati.
