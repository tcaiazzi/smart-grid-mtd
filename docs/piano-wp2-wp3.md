# GreenShieldX: piano a lungo termine per WP2 e WP3

Bozza v0.1, 2026-11-10. I mesi sono relativi all'avvio del progetto (M1), la
cui data è ancora da fissare.

## 1. Contesto e perimetro

GreenShieldX è il progetto STEP di Mashfrog Group: 24 mesi, 7 Work Package, da
TRL3 a TRL7. Roma Tre partecipa come ricerca contrattuale e ha la
responsabilità di due WP:

| WP | Titolo | Periodo | TRL a fine WP | Contributi Roma Tre indicati nella proposta (§4.10) |
|---|---|---|---|---|
| WP2 | Cognitive Threat Detection Engine | M1–M15 | 5 | Knowledge Graph Foundation, Attack Tree Generation, Alert-to-Tree Semantic Mapping |
| WP3 | Autonomous Defense Orchestration | M4–M18 | 5 | Defense Tree Formalisation, Stochastic Game Modelling, Energy-Aware Policy Solver |

Il filo conduttore dei due WP è la catena **dati → rilevamento → risposta**,
costruita su un unico *knowledge graph* di sicurezza. Gli alberi di attacco
(WP2) e gli alberi di difesa (WP3) sono le strutture che collegano gli alert
alle contromisure. Lo stesso grafo alimenta anche il knowledge layer di WP4,
curato da UNIMORE.

**Punti da chiarire con Mashfrog prima di M1:**

1. **Divisione del lavoro dentro WP2.** L'ingestion e la normalizzazione
   energy-efficient sono un output di WP2. Vanno attribuite a Mashfrog, in
   continuità con Phalanx, oppure a noi?
2. **Metamodello e formato dei dati di WP1.** Il nostro knowledge graph deve
   essere allineato al metamodello UML/OWL fin dall'inizio.
3. **Accesso all'infrastruttura GPU/HPC** (voce A.3) per le misure energetiche
   e per gli stress test.
4. **Quota di budget** (voce B.3), con il dettaglio in persone-mese per task.
5. **Diritti di pubblicazione** e regime di proprietà dei prototipi, dei
   dataset e degli strumenti di testbed.

## 2. Architettura concettuale

```
  telemetrie, log, flussi, alert
              │
              ▼
  normalizzazione (metamodello WP1)
              │
              ▼
  ┌────────────────────┐  alert   ┌──────────────────────┐  stato/belief  ┌─────────────────────┐ azione ┌──────────────────────┐
  │ T2.3 detector      │ ───────▶ │ T2.4 alert→albero    │ ─────────────▶ │ T3.2–T3.3 policy    │ ─────▶ │ T3.4 orchestrazione  │
  │ frugali in cascata │          │ correlazione, stato  │                │ (gioco stocastico,  │        │ approvazione umana,  │
  └────────────────────┘          │ della campagna       │                │ multi-obiettivo)    │        │ esecuzione, verifica │
            ▲                     └──────────────────────┘                └─────────────────────┘        └──────────────────────┘
            │                               ▲                                       ▲
            └────────────── T2.1 Knowledge graph: asset, topologia, vulnerabilità, ATT&CK, D3FEND ──────────┐
                                            │                                       │                        │
                              T2.2 alberi di attacco               T3.1 alberi di difesa e contromisure      ▼
                                                                                                  WP4 (UNIMORE): retrieval, spiegazioni
```

Le scelte di fondo sono tre:

- **Ontologie di riferimento pubbliche.** Le tecniche d'attacco sono
  descritte con MITRE ATT&CK, incluso ATT&CK for ICS per gli scenari OT, e le
  contromisure con MITRE D3FEND. Le vulnerabilità sono identificate con
  CVE/CWE. Questo rende gli alberi confrontabili e riusabili, e permette di
  spiegare le decisioni nei termini che usano gli analisti.
- **Gli alberi sono il ponte tra rilevamento e risposta.** Un alert viene
  mappato su uno o più nodi dell'albero di attacco. Lo stato stimato della
  campagna diventa l'ingresso del risolutore della policy. Ogni decisione è
  giustificata da un cammino nell'albero, ed è questo cammino che misura la
  copertura esplicativa (KPI di WP3).
- **Efficienza energetica come vincolo esplicito.** Il rilevamento usa
  modelli in cascata: un detector economico decide e passa al modello più
  costoso solo quando è incerto. Nella risposta, il costo energetico è uno
  degli obiettivi della policy.

## 3. Banco di prova (testbed)

La validazione a TRL5 richiede un "ambiente rilevante" che sia riproducibile e
dotato di verità di riferimento (*ground truth*). Come base proponiamo di usare
la piattaforma di emulazione già sviluppata in questo repository, costruita su
Kathará. Offre già:

- lab riproducibili con seed fisso, un runner di campagne riprendibili e il
  calcolo automatico delle metriche;
- registrazione della ground truth per ogni azione d'attacco (istante e tipo),
  che è la base per misurare MTTD e MTM;
- due scenari funzionanti:
  - una smart grid su MQTT, con *moving target defense* e un coordinatore
    basato su reinforcement learning, distillato in numpy per l'esecuzione nel
    lab;
  - un impianto cyber-fisico OT/Modbus con intrusione IT → pivot → effetto
    fisico, e un sensore con regole più un modello comportamentale (vedi
    [scenario-cps.md](scenario-cps.md)).

Mancano invece, e vanno sviluppati:

1. **Uno scenario IT "da SOC".** GreenShieldX riguarda il perimetro IT, quindi
   serve un segmento aziendale con web server, postazioni, database, un
   servizio di directory/autenticazione e una pipeline di log (syslog/auditd,
   log applicativi, flussi di rete). Su questo segmento vanno eseguiti attacchi
   multi-passo mappati su ATT&CK, come accesso iniziale, escalation, movimento
   laterale ed esfiltrazione, insieme a traffico e attività legittime
   realistiche.
2. **Esportazione verso il formato di WP1.** La stessa telemetria deve poter
   essere inviata alla piattaforma Mashfrog, così i nostri moduli e i loro si
   provano sugli stessi dati.
3. **Misura energetica.** Serve una misura per processo/container (contatori
   RAPL, dove disponibili, e stime basate sul tempo CPU/GPU), eseguita sull'hardware
   dedicato del progetto. Le misure in WSL o su laptop non sono attendibili.
4. **Dataset pubblici** di intrusione, come termine di confronto con lo stato
   dell'arte. Il testbed resta lo strumento principale, perché i dataset
   pubblici non hanno le catene d'attacco complete né la possibilità di
   provare le contromisure.

## 4. WP2: Cognitive Threat Detection Engine (M1–M15)

**Obiettivo.** Trasformare segnali eterogenei in alert affidabili, collocati
nel contesto della campagna d'attacco in corso, con il minimo costo
computazionale per una qualità di rilevamento data.

### KPI e definizioni operative

I target vengono dalla proposta (§4.9). Le definizioni vanno concordate con
Mashfrog entro M6, insieme alla baseline.

| KPI | Target | Definizione operativa proposta | Dove si misura |
|---|---|---|---|
| MTTD p95 | ≤ 5 s | Tempo dal primo evento malevolo (ground truth) al primo alert corretto; 95° percentile sulle campagne | Testbed |
| Performance-per-watt | ≥ +25% vs baseline | Eventi classificati al secondo a F1 fissata, diviso la potenza media assorbita | Hardware dedicato |
| Frugal compression ratio | ≥ 40% con ΔF1 ≤ 5% | Riduzione di parametri e FLOP del modello compresso rispetto al riferimento; ΔF1 in punti assoluti | Testbed e dataset pubblici |
| Energia per operazione | −40/−60% vs baseline (stima da validare) | Joule per evento classificato | Hardware dedicato |

**Baseline.** È il miglior detector non compresso e senza cascata, misurato
sugli stessi dati e sullo stesso hardware. Va congelata a M6, altrimenti i
miglioramenti in percentuale non sono verificabili.

### Task

**T2.1 Knowledge Graph Foundation (M1–M6)**
- Schema del grafo allineato al metamodello di WP1, con queste entità: asset,
  servizi, account, vulnerabilità, tecniche ATT&CK, contromisure D3FEND,
  alert, osservabili.
- Popolamento automatico dalla topologia del testbed, che Kathará espone già
  tramite API, e da fonti pubbliche (CVE, ATT&CK, D3FEND).
- Accordo di interfaccia con UNIMORE entro M4: uno schema condiviso e una
  sola istanza del grafo.
- **Output:** schema v1, popolatore, grafo dello scenario IT e degli scenari
  esistenti.

**T2.2 Attack Tree Generation (M3–M10)**
- Generazione automatica di alberi o grafi di attacco a partire dal knowledge
  graph: raggiungibilità di rete, vulnerabilità presenti, precondizioni e
  postcondizioni delle tecniche ATT&CK.
- Annotazione dei nodi con probabilità di successo e tempo atteso,
  calibrati sulle campagne del testbed.
- Validazione: le catene eseguite nel testbed devono comparire tra i cammini
  generati. Si misurano copertura e numero di cammini spuri.
- **Output:** generatore v1 (M9), libreria di alberi per gli scenari, report.

**T2.3 Detector frugali (M4–M13)**
- Famiglia di detector a costo crescente:
  - regole;
  - modelli statistici robusti (come il median/MAD già usato nel sensore OT);
  - modelli ML leggeri;
  - modelli più grandi, usati come riferimento.
- Compressione tramite pruning, quantizzazione e distillazione (abbiamo già
  esperienza con la distillazione di policy RL in numpy).
- *Routing* adattivo: un modello economico filtra e passa i casi incerti a uno
  più costoso. La soglia di passaggio va tarata sul compromesso tra qualità ed
  energia.
- Misura sistematica del compromesso: curve di F1 rispetto ai joule per
  evento.
- **Output:** prototipo del motore di rilevamento (v1 a M12), benchmark
  prestazionale ed energetico.

**T2.4 Alert-to-Tree Semantic Mapping (M6–M13)**
- Classificazione degli alert in tecniche ATT&CK e mapping sui nodi degli
  alberi di attacco.
- Correlazione: raggruppare gli alert che appartengono alla stessa campagna
  (questo riduce il rumore e alimenta il KPI di WP4/WP7 sui falsi positivi).
- Stima dello stato della campagna: quali passi sono probabilmente compiuti e
  quali sono i prossimi probabili. Il risultato è un *belief* sull'albero, che
  costituisce l'interfaccia verso WP3.
- **Output:** modulo di mapping e correlazione, formato del belief concordato
  con WP3.

**T2.5 Integrazione e validazione TRL5 (M12–M15)**
- Campagne sul testbed: tutti gli scenari, più seed, attacchi noti e varianti.
- Confronto su dataset pubblici.
- Misura dei KPI rispetto alla baseline congelata.
- Consegna dei moduli a WP7 per l'integrazione.
- **Output:** report di validazione WP2 (TRL5), dataset di test, pacchetto
  software documentato.

## 5. WP3: Autonomous Defense Orchestration (M4–M18)

**Obiettivo.** Scegliere ed eseguire contromisure coerenti con lo stato
stimato della campagna, bilanciando efficacia, tempo di mitigazione e costo
energetico. Ogni decisione deve essere spiegabile, e le azioni ad alto impatto
richiedono l'approvazione dell'operatore (*human-in-the-loop*).

### KPI e definizioni operative

| KPI | Target | Definizione operativa proposta | Dove si misura |
|---|---|---|---|
| Response accuracy | ≥ 90% | Percentuale di decisioni in cui la contromisura scelta interrompe la catena d'attacco nel testbed. Dove il testbed non basta, si usano contromisure etichettate da esperti | Testbed |
| MTM (mean time to mitigate) | −25% vs baseline | Tempo dal primo alert alla catena interrotta o all'impatto contenuto. La baseline è un playbook statico con regole fisse alert → azione | Testbed |
| Explainable decision coverage | ≥ 90% | Percentuale di decisioni con una giustificazione completa: nodi dell'albero di attacco coinvolti, contromisura nell'albero di difesa, compromesso atteso tra efficacia, tempo ed energia | Log del motore |
| Costo energetico della risposta (metrica secondaria) | Da definire | Energia della contromisura più energia del risolutore, per incidente | Hardware dedicato |

### Task

**T3.1 Libreria di contromisure e formalizzazione degli alberi di difesa (M4–M9)**
- Alberi attacco-difesa ricavati dagli alberi di T2.2.
- Contromisure mappate su D3FEND e annotate con: efficacia per passo d'attacco,
  tempo di effetto, impatto operativo (disponibilità, utenti coinvolti), costo
  energetico, reversibilità.
- Contromisure di partenza già disponibili nel testbed: blocco al firewall,
  isolamento di un host, *moving target defense* (rimescolamento degli
  indirizzi), modalità sicura del PLC. Da aggiungere: revoca delle
  credenziali, limitazione del traffico, quarantena di un servizio.
- **Output:** libreria annotata v1 (M9), alberi di difesa per gli scenari.

**T3.2 Modello a gioco stocastico (M7–M14)**
- Gioco stocastico a osservabilità parziale tra attaccante e difensore,
  definito sullo stato dell'albero di attacco. Il difensore osserva solo il
  belief prodotto da T2.4.
- Tipi di attaccante: opportunista, mirato, furtivo. Quest'ultimo corrisponde
  al caso `manual-hijack` dello scenario CPS.
- Soluzioni esatte su alberi piccoli, da usare come riferimento per le
  approssimazioni di T3.3.
- **Output:** modello formale, solver di riferimento, analisi.

**T3.3 Risolutore della policy energy-aware (M9–M16)**
- Ottimizzazione multi-obiettivo su efficacia, tempo di mitigazione ed
  energia: fronte di Pareto, più scalarizzazione o vincoli di budget
  energetico, a seconda del profilo operativo del cliente.
- Metodi approssimati scalabili: reinforcement learning (riusa la pipeline PPO
  già sviluppata), o pianificazione sul belief. Le policy vengono poi
  distillate in forma leggera per l'esecuzione in tempo reale.
- Ogni azione viene emessa con la sua giustificazione: cammino nell'albero e
  compromesso atteso.
- **Output:** policy multi-obiettivo, report comparativo tra strategie
  tradizionali e strategie energy-aware.

**T3.4 Motore di orchestrazione (M10–M16)**
- Esecuzione delle contromisure nel testbed e verifica dell'effetto, a ciclo
  chiuso.
- Approvazione dell'operatore per le azioni ad alto impatto, con soglie
  configurabili.
- Il motore copre anche i passi 5–6 lasciati fuori dal prototipo CPS:
  orchestrazione, approvazione dell'operatore e risposta automatica al
  confine.
- **Output:** prototipo del motore di orchestrazione/risposta, con interfaccia
  verso WP7.

**T3.5 Validazione TRL5 (M15–M18)**
- Confronto tra il playbook statico e le policy energy-aware, su tutti gli
  scenari e tipi di attaccante, con più seed.
- Misura dei KPI e consegna a WP7.
- **Output:** report di validazione WP3 (TRL5).

## 6. Cronoprogramma

```
                            M1        M6          M12         M18         M24
WP2  Threat detection       ##############################
 T2.1 Knowledge graph       ============
 T2.2 Attack tree gen.          ================
 T2.3 Detection frugal            ====================
 T2.4 Alert-to-tree                   ================
 T2.5 Validazione TRL5                            ========
WP3  Defense orchestration        ##############################
 T3.1 Defense tree + lib.         ============
 T3.2 Stochastic game                   ================
 T3.3 Policy solver                         ================
 T3.4 Orchestrazione                          ==============
 T3.5 Validazione TRL5                                  ========
Supporto WP4/WP6/WP7                                          ..................
Milestone                             ^     ^     ^     ^     ^
                                     MS1   MS2   MS3   MS4   MS5
```

Dopo la chiusura formale (M15 per WP2, M18 per WP3) resta un supporto fino a
M24:
- a **WP6**, per la robustezza avversariale dei nostri detector e delle policy;
- a **WP7**, per l'integrazione end-to-end e la dimostrazione TRL7;
- a **WP4**, per la manutenzione del knowledge graph condiviso.

## 7. Milestone e deliverable

| ID | Mese | Contenuto | Verifica |
|---|---|---|---|
| MS1 | M6 | Schema del knowledge graph v1 allineato a WP1; testbed IT-SOC v1; baseline e definizioni dei KPI congelate | Documento firmato con Mashfrog; campagna di prova eseguita |
| MS2 | M9 | Generatore di alberi di attacco v1; libreria di contromisure v1 | Le catene del testbed sono coperte dai cammini generati |
| MS3 | M12 | Motore di rilevamento v1 (frugale, in cascata) e mapping alert→albero; primi KPI di WP2 | Report KPI intermedio rispetto alla baseline |
| MS4 | M15 | **Chiusura WP2 a TRL5**: motore di rilevamento e correlazione validato; dataset di test | Report di validazione WP2 |
| MS5 | M18 | **Chiusura WP3 a TRL5**: motore di orchestrazione e policy multi-obiettivo validati | Report di validazione WP3 |

I deliverable corrispondono agli output previsti nella proposta (§4.9):
- **WP2:** prototipo del motore di rilevamento e correlazione; ingestion e
  normalizzazione (da attribuire, vedi §1); knowledge graph di sicurezza;
  modelli frugali con benchmark; report tecnici e dataset di test.
- **WP3:** prototipo del motore di orchestrazione; libreria di contromisure
  annotata; policy multi-obiettivo; report comparativi.

## 8. Interfacce con gli altri WP

| WP | Cosa riceviamo | Cosa forniamo | Quando |
|---|---|---|---|
| WP1 (Mashfrog) | Metamodello, inventario dei dati, protocolli di validazione | Requisiti del knowledge graph e del formato degli alert | M1–M6 |
| WP4 (UNIMORE) | Requisiti di retrieval e spiegazione | Knowledge graph condiviso, alberi, giustificazioni delle decisioni | Schema a M4; aggiornamenti continui |
| WP5 (Mashfrog) | Metodologia di misura energetica, accesso all'hardware | Profili energetici dei detector e delle contromisure | Da M10 |
| WP6 | Modello delle minacce avversariali | Detector e policy da sottoporre ad attacco; contributo alle difese | Da M13 |
| WP7 (Mashfrog) | Ambiente di integrazione | Moduli WP2 e WP3 documentati, scenari di test, ground truth | M15 / M18, poi supporto |

## 9. Rischi e mitigazioni

| Rischio | Impatto | Mitigazione |
|---|---|---|
| Baseline e definizioni dei KPI non concordate, quindi percentuali non verificabili | Alto | Congelamento a MS1 (M6), con un documento condiviso con Mashfrog |
| Misure energetiche non affidabili in container o ambienti virtualizzati | Alto | Misure solo sull'hardware dedicato; RAPL dove disponibile; stima da tempo CPU/GPU come riserva, dichiarata come tale |
| Metamodello di WP1 in ritardo | Medio | Schema provvisorio basato su ATT&CK e D3FEND, con mapping successivo |
| Nessun accesso a dati SOC reali | Medio | Testbed IT-SOC con ground truth, più dataset pubblici; eventuali dati Mashfrog/Phalanx pseudonimizzati |
| Sovrapposizione con UNIMORE sul knowledge graph | Medio | Accordo di interfaccia a M4: una sola istanza, responsabilità separate (struttura e popolamento noi, retrieval e spiegazione loro) |
| Esplosione dello spazio di stato del gioco stocastico | Medio | Astrazione sui nodi dell'albero; soluzioni esatte solo su istanze piccole; policy approssimate e distillate |
| Divario tra scenari di laboratorio e un SOC reale | Medio | Scenario IT con traffico legittimo realistico; varianti d'attacco non viste in calibrazione; validazione finale in WP7 |
| Mancata trasferibilità dei prototipi di ricerca a Mashfrog | Medio | Codice documentato, interfacce stabili, consegne intermedie a M12 e M15, non solo a fine WP |

## 10. Output scientifici

Gli output scientifici previsti sono:
- pubblicazioni su generazione di alberi di attacco da knowledge graph,
  mapping alert→albero, giochi stocastici per la risposta e detection
  frugale;
- il testbed come strumento riproducibile;
- eventuali dataset di campagne con ground truth.

Il regime di proprietà e di pubblicazione va definito nel contratto di ricerca
(vedi §1, punto 5).

## 11. Prossimi passi (primi 90 giorni)

1. Kick-off con Mashfrog per chiudere i punti aperti della §1, in
   particolare la divisione del lavoro in WP2 e il calendario reale (data
   di M1).
2. Rassegna dello stato dell'arte su: generazione di alberi di attacco,
   alberi attacco-difesa, giochi di sicurezza stocastici, IDS frugali e
   misura energetica del ML. Serve anche a sostenere il criterio di
   valutazione A.1.
3. Bozza dello schema del knowledge graph e incontro con UNIMORE.
4. Progetto dello scenario IT-SOC: topologia, servizi, catene ATT&CK da
   emulare, profilo del traffico legittimo.
5. Proposta scritta delle definizioni dei KPI e della baseline, da
   concordare entro M6.
6. Piano di gestione dei dati: minimizzazione, pseudonimizzazione e
   segregazione degli ambienti, come previsto nella proposta.
