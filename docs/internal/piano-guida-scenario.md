# Guida interattiva per creare uno scenario: piano di miglioramento

Bozza v0.1, 2026-11-20. Riguarda `docs/scenario-guide.html`, il suo test
`tests/core/test_scenario_guide.py` e la pagina `docs/new-scenario.md`.

## 1. Punto di partenza

La guida accompagna in 11 passi la creazione di uno scenario con un laboratorio
proprio e ne scrive lo scheletro. Oggi ha questi limiti:

- lo scheletro è provato solo sul laboratorio finto, mai su Kathará;
- le modifiche ai file esistenti (7-8) si applicano a mano;
- il blocco `guide-contract` della pagina si corregge a mano quando il
  repository cambia;
- copre solo il percorso "laboratorio nuovo", non le varianti CPS;
- nell'episodio offre solo un agente segnaposto;
- le risposte restano nel browser, e dell'interfaccia si controlla solo la
  sintassi.

**Stato al 2026-11-20.** Tutte e sei le fasi fatte. Nella fase 6 il catalogo
comprende tutti i 31 componenti dei plane, derivato dal codice; gli stub di
campagna e pannello sono solo per il laboratorio proprio.
Nota sulla fase 5: genera tre hook
di `Feature` (opzioni, file su un host, servizi); `nodes`, `attacker`,
`lab_spec` e `plant_spec` sono spiegati nella guida ma non generati. Nella fase 4 il file delle
risposte non è finito nello zip: scompattato alla radice sarebbe rimasto un
file senza un posto nel repository. Si esporta con il suo pulsante. La fase 1 ha portato una correzione
alla guida: in `loc-totals.json` cresce di 1 anche `platform`, per la riga del
registry.

Il piano è in sei fasi. Ogni fase è un commit a sé e si chiude con `make check`
verde. L'ordine conta: le prime tre rendono affidabile la guida che c'è, le
altre la allargano.

| Fase | Cosa | Dipende da | Peso |
|---|---|---|---|
| 1 | Prova su un laboratorio vero | — | piccolo |
| 2 | Modifiche ai file esistenti applicate da uno script | 1 | medio |
| 3 | `guide-contract` rigenerato con un comando | — | piccolo |
| 4 | Interfaccia testabile, esportazione delle risposte, anteprima di `lab.conf` | — | medio |
| 5 | Percorso "variante CPS" | 2, 4 | grande |
| 6 | Componenti veri nell'episodio, stub di campagna e pannello | 4 | grande |

## 2. Fase 1: prova su un laboratorio vero

**Perché.** La suite non deploya mai un laboratorio. Finché lo scheletro non
gira su Kathará, la guida promette una cosa che nessuno ha visto.

**Come.**

1. Creare un worktree git usa e getta, così il repository di lavoro non viene
   toccato.
2. Generare lo zip dell'esempio `substation` con node, come fa il test, e
   scompattarlo alla radice del worktree.
3. Applicare a mano le modifiche che la guida elenca, seguendo solo il testo
   della guida. Ogni punto in cui il testo non basta è un difetto da annotare.
4. Eseguire, nell'ordine:
   - `make lab-conf SCENARIO=substation`;
   - i test dello scenario;
   - l'aggiornamento deliberato dei due snapshot, leggendo il diff;
   - `make check`;
   - `make substation SEED=1`, poi `make substation-lab` per guardare dentro i
     nodi.
5. Verificare il risultato del run: `progress.jsonl` chiuso con `run_end` e
   stato `ok`, `topology.json`, `probe.probe_agent.log` non vuoto,
   `run_metrics` sul ledger, laboratorio rimosso alla fine.
6. Ripetere con la variante "immagine nuova" (`make substation-image`), che
   esercita il Dockerfile generato.
7. Riportare nella guida le correzioni emerse, poi eliminare il worktree. Lo
   scenario `substation` non entra nel repository.

**Rischi noti da guardare.** La NIC passiva del nodo `probe`, la porta
pubblicata insieme alla route `replace`, il percorso del log di console
dell'agente, i nomi dei file scaricati.

**Fatto quando.** I due run reali passano senza interventi fuori dal testo
della guida, e le correzioni sono nei template e nel test.

Docker è attivo su questa macchina e `kathara/cps` è già costruita, quindi la
fase si può fare subito.

## 3. Fase 2: modifiche ai file esistenti applicate da uno script

**Perché.** È il punto in cui chi segue la guida sbaglia più facilmente: sette
file, ciascuno con il suo punto di inserimento.

**Come.**

- Il generatore produce le modifiche anche come dati, non solo come testo:
  file, riga-àncora, modo (dopo l'àncora, in coda a una riga, sostituzione di
  un blocco), testo. Lo zip le contiene in `scenario-edits.json`.
- Nuovo script nel repository, `tools/apply_scenario_edits.py`, solo stdlib:
  - legge `scenario-edits.json`;
  - con `--check` (predefinito) mostra il diff senza scrivere;
  - con `--write` applica;
  - è idempotente: una modifica già presente viene saltata;
  - se un'àncora manca si ferma senza scrivere nulla, e dice quale.
- Restano manuali, per scelta, i due aggiornamenti degli snapshot e
  `MIN_TESTS`: lo script li ricorda a fine esecuzione, con i comandi.
- La guida mostra ancora ogni modifica, ma come spiegazione di ciò che lo
  script farà. Il passo finale diventa: scompattare, `--check`, `--write`.

**Test.** In `test_scenario_guide.py`: copiare in una cartella temporanea i
file toccati, applicare le modifiche dell'esempio e verificare che

- il registry copiato contenga la nuova riga e resti Python valido;
- `make -n substation` si espanda con il `Makefile` copiato;
- una seconda applicazione non cambi nulla;
- un'àncora rimossa faccia fallire lo script senza scritture parziali.

Le àncore del `guide-contract` diventano le stesse che lo script usa, così il
controllo esistente le copre.

**Da decidere.** `tools/` è fuori dal conteggio del codice (`OUT_OF_SCOPE` in
`test_loc_coverage.py`), quindi lo script non richiede voci in `SOURCES`. Va
bene lì, oppure lo vuoi come sottocomando di `python -m cyberrange.core`?
Propongo `tools/`: è uno strumento per chi sviluppa, non parte della
piattaforma.

## 4. Fase 3: `guide-contract` rigenerato con un comando

**Perché.** Ogni nuovo scenario, target make, modulo guest o pacchetto di
un'immagine rende rosso il test, e oggi la correzione è un JSON scritto a mano
dentro una pagina HTML.

**Come.**

- Dividere il blocco in due parti:
  - **derivata** dal repository: scenari e lab, fasi riservate, plane,
    immagini e pacchetti, pin, nomi d'import, target make, moduli guest;
  - **scritta a mano**: percorsi citati, simboli, àncore.
- Spostare il calcolo della parte derivata in `tests/helpers/guide_contract.py`.
  Il test la confronta con la pagina, come oggi.
- Con `UPDATE_GUIDE_CONTRACT=1` il test riscrive la sola parte derivata nella
  pagina, sullo stesso modello di `UPDATE_SNAPSHOTS=1`. Il messaggio di errore
  del test dice il comando da lanciare.
- Documentare in `cyberrange-guardrails` (skill) e in `docs/new-scenario.md`
  quando è lecito rigenerare: quando il repository è cambiato e la guida deve
  seguirlo, mai per far passare uno scheletro che non funziona.

**Fatto quando.** Aggiungere uno scenario finto al registry in un test e
rigenerare produce un diff della pagina limitato alla parte derivata.

## 5. Fase 4: interfaccia testabile, esportazione, anteprima di `lab.conf`

**Interfaccia testabile.**

- Oggi il corpo di ogni passo è una funzione che restituisce HTML, ma legge lo
  stato globale della pagina. Va resa pura: `renderStep(id, state, contract)`,
  esposta accanto al generatore.
- Il test la esegue con node per ogni passo, su esempio e scenario vuoto, e
  verifica che non sollevi errori, che ogni file generato compaia nel suo passo
  e che ogni errore di validazione sia mostrato nel passo giusto.
- Nessuna dipendenza nuova: niente browser nella suite. Il controllo in browser
  reale resta manuale, dopo modifiche al layout.

**Esportazione e importazione.**

- Due pulsanti: "Export answers" salva `<nome>.scenario.json`, "Import" lo
  ricarica. Il file contiene la sola specifica, con un numero di versione.
- Lo zip include lo stesso file, così lo scheletro porta con sé la specifica
  da cui è nato.
- Un file importato passa dalla validazione prima di sostituire lo stato.

**Anteprima di `lab.conf`.**

- Nel passo della topologia, una scheda mostra `lab.conf` e i file `.startup`
  come li renderebbe `make lab-conf`.
- Il rischio è duplicare in JavaScript la logica di `core/topology.py`. Il test
  lo chiude: per la specifica d'esempio confronta l'anteprima della pagina con
  l'uscita di `export_lab_conf` sulla topologia generata. Se le due divergono,
  il test è rosso.

## 6. Fase 5: percorso "variante CPS"

**Perché.** Tre scenari su cinque sono varianti di `cps`. È il caso più
frequente e oggi la guida rimanda altrove.

**Come.**

- Un bivio al passo 2: laboratorio nuovo oppure variante di `cps`. I passi
  comuni restano, quelli specifici cambiano.
- Passi propri della variante:
  1. cosa aggiunge: opzioni, file o immagine su un host esistente, nodi nuovi,
     servizi, un attaccante diverso. Ogni scelta corrisponde a un hook di
     `Feature` (`add_arguments`, `extras`, `nodes`, `services`, `engage`,
     `attacker`);
  2. un laboratorio diverso: `lab_spec(args)` che restituisce un `LabSpec`,
     con i vincoli di `LabSpec.check()` controllati nella pagina.
- File generati, sul modello di `cps_recon`:
  - `feature.py` con i soli hook scelti;
  - `scenario.py`, sottoclasse di `CpsScenario` con `features = (...)` e i
    `DEFAULT_*` propri;
  - `cli.py`, `guest_files.py`, `__init__.py`;
  - `panel.js` che delega al pannello di `cps`;
  - `make/<nome>.mk` che riusa le variabili `CPS_*`;
  - un test di opzioni e topologia, come `test_cps_recon_scenario.py`.
- Lo script della fase 2 applica le stesse modifiche ai file esistenti.

**Test.** Lo scheletro della variante viene montato come quello attuale e si
verifica che: importi, costruisca la topologia di `cps` con le aggiunte,
passi ruff, superi il contratto dei pannelli di `test_panels.py`. Un run
completo sul laboratorio finto richiede pandapower: va tra i test lenti.

**Prova reale.** Come nella fase 1, su un worktree usa e getta, con una
variante minima (un file in più su un host e un'opzione).

**Rischio.** L'API di `Feature` è recente e ancora in movimento. Il
`guide-contract` deve elencare gli hook e le loro firme, verificate con
`inspect.signature`, così un hook rinominato rende rosso il test.

## 7. Fase 6: componenti veri nell'episodio, stub di campagna e pannello

**Componenti.**

- Un catalogo, nel `guide-contract`, dei componenti generici dei plane: quelli
  che non presuppongono il laboratorio CPS o MQTT. Candidati: `Capture`,
  `TelemetryMirror`, `WebTerminal`, `RecordedShell`, `JumpHost`,
  `BackgroundReplay`, `VulnApp`, oltre a `GuestAgent`. La lista va decisa
  leggendo ogni costruttore: un componente entra solo se si può configurare
  con nodi, porte e percorsi.
- Nel passo dell'episodio, per ogni fase si scelgono i componenti e si
  compilano i loro argomenti; i nodi si scelgono tra quelli del laboratorio.
- Il generatore scrive le chiamate `ctx.start(...)`, gli import e, per i
  componenti che lanciano un file guest, le righe del manifest.
- La firma di ogni componente del catalogo è verificata nel test con
  `inspect.signature`. La parte derivabile del catalogo rientra nella
  rigenerazione della fase 3.
- Lo scheletro con componenti scelti viene eseguito sul laboratorio finto,
  come oggi.

**Stub opzionali.**

- `campaign.py`: semi × una opzione, con `Step`, `Unit`, `Campaign` e
  `run_cli`, più il target `<nome>-campaign`. Test: la campagna si costruisce
  e i suoi passi a secco si espandono.
- `panel.js`: registra `window.CyberRangePanels["<nome>"]` con una vista
  minima delle metriche. Test: il contratto di `test_panels.py`, eseguito
  sullo stub generato. Va aggiunta la categoria in `SOURCES`.

## 8. Cosa resta fuori

- Una copia locale delle librerie per l'uso senza rete: hai detto che non
  serve.
- Un test in browser reale dentro la suite: richiederebbe Playwright e
  Chromium tra le dipendenze.
- Tenere `substation` nel repository come scenario d'esempio: aumenterebbe il
  conteggio del codice e gli snapshot per uno scenario che non misura nulla.

## 9. Decisioni che servono da te

1. Lo script delle modifiche va in `tools/` (proposta) o come sottocomando del
   core?
2. La fase 5 parte dopo le prime quattro, o ha la precedenza perché è il caso
   più frequente?
3. Quali componenti entrano nel catalogo della fase 6: solo i generici
   elencati sopra, o anche quelli CPS quando il percorso è "variante"?
