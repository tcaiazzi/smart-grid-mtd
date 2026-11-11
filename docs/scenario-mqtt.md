# Scenario MQTT smart grid (MTD vs fingerprinting): descrizione ad alto livello

## 1. Obiettivo

Misurare se una **moving target defense** sul canale MQTT di una smart grid
riesce a sottrarre una nanogrid al riconoscimento di un attaccante passivo, e
a che prezzo in disponibilità del servizio.

L'attaccante non entra in nessun host: ascolta soltanto. Da una cattura di
traffico cifrato estrae caratteristiche di flusso, le dà in pasto a una CNN 1D
addestrata in precedenza, e decide **quale indirizzo IP è la nanogrid**. Poi la
isola con un blackhole sul router. La difesa non lo può impedire: può solo fare
in modo che il traffico osservato non sia più riconoscibile.

È lo scenario dei risultati del paper (Fig. 2 e Fig. 3).

## 2. Architettura in sintesi

```
scmc 10.0.0.2 ──── A ──── router ──── B ──── semp 10.1.0.2
(+ pool IP sorgente)   10.0.0.1   10.1.0.1    (+ pool IP del broker)
                                             └─ attacker 10.1.0.3 (sniffa B)
```

| Nodo | Ruolo |
|---|---|
| `scmc` | La nanogrid: pubblica telemetria (fisica simulata con pymgrid) sul broker, in mutual TLS |
| `semp` | Il broker MQTT dell'operatore, e il coordinatore MTD |
| `router` | Instrada A↔B e riproduce una **traccia reale** di traffico di fondo su B, perché l'attaccante non abbia una cattura artificialmente pulita |
| `attacker` | Sniffa passivamente il link B; dopo la decisione, applica il blackhole |

I certificati per il TLS mutuo sono distribuiti all'avvio su un canale che
simula una consegna QKD (`QkdCertBootstrap`).

## 3. La difesa: che cosa muove la MTD

Il coordinatore sul `semp` cambia nel tempo le caratteristiche osservabili del
traffico, ognuna con un costo di disponibilità diverso:

| Manovra | Effetto osservabile |
|---|---|
| **hop** dell'IP del broker | cambia il punto di destinazione dei flussi |
| **source hop** dell'IP della nanogrid | cambia il punto di origine |
| **port hop** | cambia la porta TLS del broker |
| **padding** | altera la distribuzione delle dimensioni dei pacchetti |
| **frequency hop** | altera la cadenza delle pubblicazioni |

Due famiglie di politiche, confrontate nel paper:

- **timer fissi** — ogni manovra ha il suo intervallo (`MTD_HOP_INTERVAL`, …);
- **RL** — una politica PPO addestrata offline (`training/train_rl_coordinator.py`)
  e distillata in una rete numpy (`policy.npz`) che gira nel container, decide a
  ogni tick quale manovra vale il suo costo. Due varianti: `cost` (equilibrio
  sicurezza/disponibilità) ed `entropy` (massima diffusione).

## 4. I componenti

| Piano | Componenti |
|---|---|
| traffic | `BackgroundReplay` (tcpreplay della traccia), `ScmcPublisher` (publisher di base o esecutore MTD) |
| defense | `QkdCertBootstrap`, `MtdCoordinator` (timer fissi o politica RL) |
| attack | `PassiveFingerprinter` (sniff → CNN → scelta dell'IP), `DeliveryAttack` (blackhole + guasti benigni) |
| monitor | `Capture` su `router` e `scmc`, `TelemetryMirror` |

## 5. Svolgimento di un esperimento

Una esecuzione è in uno di tre modi:

| Modo | Che cosa fa |
|---|---|
| `--generate-dataset N` | Cattura N secondi di traffico misto su B: sono i dati di addestramento e di test della CNN |
| `--attack N` | Sniffa N s, impronta la nanogrid, blocca l'IP scelto, osserva l'effetto per `--post-attack` s |
| nessuno dei due | Avvia e smonta il sistema (prova di sanità) |

Le fasi di un'esecuzione di attacco sono `services → sniff → score →
post_attack`, registrate sul ledger di avanzamento e seguibili dal vivo con
`make dashboard`.

La pipeline completa, per una configurazione:

```sh
make datasets      # cattura train + test (due deploy del lab)
make train         # addestra la CNN 1D sul dataset di train
make evaluate      # la valuta sul test
make attack        # esegue l'attacco guidato dal modello nel lab
make plots         # figure della configurazione
```

`NO_MTD=1` esegue la variante di riferimento senza difesa; `MODEL_SRC=baseline`
usa il modello addestrato sul traffico non difeso contro il traffico difeso —
che è il confronto interessante, perché misura quanto la MTD degrada un
classificatore già addestrato.

**L'intera valutazione del paper** (quattro configurazioni + figure) si esegue
con un comando solo:

```sh
.venv/bin/python main.py            # --dry-run per vedere i comandi senza eseguirli
```

## 6. Cosa si misura

Per singola esecuzione (`cyberrange/scenarios/mqtt_mtd/metrics.py`):

| Metrica | Significato |
|---|---|
| `nanogrid_detect` | Quanto in alto la nanogrid compare nel ranking dell'attaccante: è la misura di efficacia della difesa |
| `blocked_is_nanogrid` | Se l'IP effettivamente bloccato era davvero la nanogrid |
| `publishes` | Pubblicazioni riuscite: la disponibilità del servizio |
| `availability_cost` | Costo cumulato delle manovre MTD (riconnessioni indotte) |
| `data_gaps`, `max_data_gap_s` | Interruzioni nel flusso di telemetria |
| `mtd_actions`, `mtd_outcomes` | Che cosa ha fatto il coordinatore, e con quale esito |

Le campagne aggregano queste metriche su più semi con media e intervallo di
confidenza al 95%.

Figure del paper (`analysis/compare_coordinators.py`):

| Figura | File |
|---|---|
| Fig. 2a — disponibilità nel tempo | `availability_comparison.pdf` |
| Fig. 2b — confidenza dell'attaccante per configurazione | `detection_comparison.pdf` |
| Fig. 2c — costo cumulato di disponibilità | `availability_cost_comparison.pdf` |
| Fig. 3 — entropia di Shannon per campo | `entropy_comparison.pdf` |

## 7. Riferimenti rapidi

| Cosa | Dove |
|---|---|
| Topologia ed episodio | `cyberrange/scenarios/mqtt_mtd/{topology,scenario}.py` |
| Riga di comando di una esecuzione | `cyberrange/scenarios/mqtt_mtd/cli.py` |
| Campagna del paper | `cyberrange/scenarios/mqtt_mtd/campaign.py`, `main.py` |
| Manifest di deploy | `cyberrange/scenarios/mqtt_mtd/guest_files.py` |
| Metriche | `cyberrange/scenarios/mqtt_mtd/metrics.py` |
| Figure e analisi | `cyberrange/scenarios/mqtt_mtd/analysis/` |
| Addestramento offline (RL, rilevatore) | `cyberrange/scenarios/mqtt_mtd/training/` |
| Coordinatori ed esecutori MTD | `cyberrange/planes/defense/agents/` |
| Classificatore CNN | `cyberrange/planes/attack/classify.py` |
| Piattaforma e contratto di scenario | [platform.md](platform.md), [structure.md](structure.md) |
