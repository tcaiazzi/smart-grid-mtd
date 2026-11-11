# The MQTT smart-grid scenario (MTD vs traffic fingerprinting)

## 1. What it is for

Measure whether a **moving target defence** on a smart grid's MQTT channel can
keep a nanogrid from being recognised by a passive attacker — and what that
costs in service availability.

The attacker never breaks into a host; it only listens. From a capture of
encrypted traffic it extracts flow features, feeds them to a 1D CNN trained
beforehand, and decides **which IP address is the nanogrid**. Then it isolates
that address with a blackhole on the router. The defence cannot prevent any of
this. All it can do is make the observed traffic stop being recognisable.

This is the scenario behind the paper's results (Fig. 2 and Fig. 3).

## 2. Architecture

```
scmc 10.0.0.2 ──── A ──── router ──── B ──── semp 10.1.0.2
(+ source IP pool)     10.0.0.1   10.1.0.1    (+ broker IP pool)
                                             └─ attacker 10.1.0.3 (sniffs B)
```

| Node | Role |
|---|---|
| `scmc` | The nanogrid: publishes telemetry (physics simulated with pymgrid) to the broker over mutual TLS |
| `semp` | The operator's MQTT broker, and the MTD coordinator |
| `router` | Routes A↔B and replays a **real background trace** onto link B, so the attacker does not get an artificially clean capture |
| `attacker` | Sniffs link B passively; after deciding, applies the blackhole |

The mutual-TLS certificates are distributed at startup over a channel that
simulates QKD delivery (`QkdCertBootstrap`).

## 3. What the defence moves

The coordinator on `semp` changes the observable properties of the traffic over
time, each at a different availability cost:

| Manoeuvre | Observable effect |
|---|---|
| broker IP **hop** | the destination of the flows changes |
| source IP **hop** | the origin changes |
| **port hop** | the broker's TLS port changes |
| **padding** | the packet size distribution changes |
| **frequency hop** | the publishing cadence changes |

Two families of policy, compared in the paper:

- **fixed timers** — each manoeuvre has its own interval (`MTD_HOP_INTERVAL`, …);
- **RL** — a PPO policy trained offline
  (`scenarios/mqtt_mtd/training/train_rl_coordinator.py`) and distilled into a
  numpy network (`policy.npz`) that runs inside the container, deciding at every
  tick which manoeuvre is worth its cost. Two variants: `cost` (security against
  availability) and `entropy` (maximum diffusion).

## 4. The components

| Plane | Components |
|---|---|
| traffic | `BackgroundReplay` (tcpreplay of the trace), `ScmcPublisher` (baseline publisher or MTD executor) |
| defense | `QkdCertBootstrap`, `MtdCoordinator` (fixed timers or an RL policy) |
| attack | `PassiveFingerprinter` (sniff → CNN → pick the IP), `DeliveryAttack` (blackhole + benign faults) |
| monitor | `Capture` on `router` and `scmc`, `TelemetryMirror` |

## 5. Running an experiment

A run is in one of three modes:

| Mode | What it does |
|---|---|
| `--generate-dataset N` | Captures N seconds of mixed traffic on link B: the CNN's training and test data |
| `--attack N` | Sniffs for N s, fingerprints the nanogrid, blocks the chosen IP, observes the effect for `--post-attack` s |
| neither | Brings the system up and tears it down (a sanity check) |

The phases of an attack run are `services → sniff → score → post_attack`,
recorded on the progress ledger and followable live with `make dashboard`.

The full pipeline for one configuration:

```bash
make datasets      # capture train + test (two lab deployments)
make train         # train the 1D CNN on the train dataset
make evaluate      # score it on the test dataset
make attack        # run the model-driven attack in the lab
make plots         # figures for this configuration
```

`NO_MTD=1` runs the undefended reference variant. `MODEL_SRC=baseline` uses the
model trained on undefended traffic against defended traffic — the interesting
comparison, because it measures how much the MTD degrades a classifier that was
already trained.

**The paper's whole evaluation** is one command:

```bash
.venv/bin/python main.py            # --dry-run to see the commands without running them
```

It runs the four configurations (baseline, fixed-timer, RL-cost, RL-entropy),
training the RL policies first if their `.npz` files are missing, and finishes
with the figures. `--runs N` repeats the evaluation under `output/run-<i>/` with
a seed per run; `--resume` skips attacks that already have metrics.

### Key variables

| Variable | Default | Meaning |
|---|---|---|
| `NO_MTD` | `0` | `1` switches to the baseline (no-MTD) variant |
| `MODEL_SRC` | same as the variant | Which variant's model attacks (`baseline` or `mtd`) |
| `BG_TRACE` | `assets/pcap/traccia.pcap` | Background trace to split |
| `SPLIT_RATIO` | `0.7` | Fraction of packets in the train split |
| `DATASET_DURATION` | `120` | Capture duration per dataset, seconds |
| `ATTACK_DURATION` | `40` | Attacker sniff duration, seconds |
| `POST_ATTACK` | `40` | Observation after the block, seconds |
| `BG_REPLAY_MBPS` | `2` | Background replay rate |
| `MTD_HOP_INTERVAL` | `2` | Seconds between address hops (broker and source share the timer) |
| `MTD_PORT_POOL` | `8883–8887` | Broker port pool |
| `MTD_PAD_BUCKETS` | `128,256,…,1024` | Padding bucket sizes, bytes |
| `MTD_PAD_INTERVAL` | `3` | Seconds between padding rotations |
| `MTD_FREQ_INTERVAL` | `30` | Seconds between frequency mutations |
| `SEED` | — | Seeds the run; each role derives its own seed from it |
| `DASHBOARD_PORT` | `8080` | Host port of the live MTD dashboard (`0` disables it) |

`make help` prints the complete catalogue with what each target writes where.
Any variable can be overridden on the command line:

```bash
make experiment DATASET_DURATION=60 MTD_HOP_INTERVAL=1
```

### Output layout

Everything for one parameter configuration goes into a single self-contained
directory `output/<exp-slug>/`. The slug is `baseline-mbps<M>` for the baseline
variant, and for an MTD configuration it spells out every parameter:

```
mtd-hop<H>-padint<PI>-ips<NI>-ports<NP>-pads<NB>-srcips<NS>-mbps<M>-freqint<FI>-freqs<NF>
```

with the prefix `mtdrl-` (or `mtdrl-<tag>-`) when an RL policy drives it.

```
output/
  baseline-mbps2/
    datasets/   train.pcap test.pcap  train.client.log train.mosquitto.log  test.*.log
    model/      model.pt scaler.pkl
    eval/       model-baseline/   predictions.csv roc_curve.pdf confusion_matrix.png
    attack/     model-baseline/   attacker_capture.pcap router_capture.pcap
                                  nanogrid_ranking.csv mosquitto.log client.log
    summary.csv detection.pdf availability.pdf            # from `make plots`
  mtd-hop2-padint3-ips4-ports5-pads7-srcips4-mbps2-freqint30-freqs6/
    datasets/  model/
    eval/  attack/    model-mtd/...  model-baseline/...   # cross-model results too
    summary.csv ...
  sweep/        e1_*.pdf e2_*.pdf e3_*.pdf e4_*.pdf sweep_results.csv   # from `make sweep`
  sweep_manifest.csv
  campaigns/<name>/   campaign.json progress.jsonl summary.md ci.csv
```

Results are keyed by the scoring model (`model-mtd` / `model-baseline`); the
cross-model run reads the baseline model from `output/baseline-mbps<M>/model/`.

## 6. The parameter ablation

`make sweep` walks a grid instead of the paper's four fixed configurations, and
answers which mechanism actually does the hiding:

| Group | Varies |
|---|---|
| E0 | nothing — the reference point |
| E1 | one mechanism at a time (the other pools collapsed to a single value) |
| E2 | how often the address hops: 1, 5, 10, 30 s |
| E3 | how much background noise there is: 1, 5, 10 Mbit/s |
| E4 | how often the publish frequency mutates: 1, 5, 10 s |

```bash
make sweep GROUPS=e1,e2 DRY=1    # look at the grid first
make sweep                       # all five groups, resumable
```

It is a campaign like any other: one ledger that `make dashboard` follows,
`--resume` skipping configurations already scored, retries on failed lab steps.
Each configuration writes a row into `output/sweep_manifest.csv`, and the final
step draws `output/sweep/e1..e4_*.pdf` from those rows plus each
configuration's `summary.csv`.

## 7. What is measured

Per run (`cyberrange/scenarios/mqtt_mtd/metrics.py`):

| Metric | Meaning |
|---|---|
| `nanogrid_detect` | How high the nanogrid ranks in the attacker's ranking — the defence's effectiveness |
| `blocked_is_nanogrid` | Whether the address actually blocked was the nanogrid |
| `publishes` | Successful publishes: service availability |
| `availability_cost` | Cumulative cost of the MTD manoeuvres (induced reconnections) |
| `data_gaps`, `max_data_gap_s` | Interruptions in the telemetry stream |
| `mtd_actions`, `mtd_outcomes` | What the coordinator did, and how each attempt ended |

Campaigns aggregate these across seeds with mean and 95% confidence interval.

The paper's figures (`analysis/compare_coordinators.py`):

| Figure | File |
|---|---|
| Fig. 2a — availability over time | `availability_comparison.pdf` |
| Fig. 2b — attacker confidence per configuration | `detection_comparison.pdf` |
| Fig. 2c — cumulative availability cost | `availability_cost_comparison.pdf` |
| Fig. 3 — per-field Shannon entropy | `entropy_comparison.pdf` |

## 8. The live MTD dashboard

During every MTD run the coordinator on `semp` serves a dashboard at
`http://localhost:8080/` (`DASHBOARD_PORT=9090` moves it, `0` turns it off). It
shows the MTD actions taken and how each one ended (applied, failed and rolled
back, timed out, client lost), the cumulative availability cost (the same
per-knob weights as the RL reward and `compare_coordinators`), how often updates
are sent and skipped, ACK/DONE latencies, delivery problems, executor health,
the currently exposed attack surface, the nanogrid messages actually reaching the
broker with their gaps, and — for the RL coordinator — every policy decision.

The page is reached through a Kathará bridged interface and port forward on
`semp`, **never over link B**, so the attacker's capture contains no dashboard
traffic; the data-plane observer subscribes over a loopback-only mosquitto
listener. Every event is also written to `telemetry.jsonl`, downloaded next to
`coordinator.log`: open `cyberrange/planes/defense/agents/mtd_dashboard.html`
directly in a browser and load that file to replay a finished run. The data-plane
observer (the `data` / `data_gap` events the delivery detector needs) runs on
every MTD run, with or without the dashboard.

This is a different thing from `make dashboard`, which follows the host-side
progress ledger of every scenario's runs and campaigns.

## 9. The delivery-attack detector

The attacker's active phase blackholes an address on the router, so nanogrid data
stops reaching the SEMP. `cyberrange/planes/defense/delivery_detector.py` scores
every SCMC once a second from the SEMP's telemetry alone — data silence, MTD
actions left unanswered, control-channel state, ACK latency — and tells a
blackhole apart from MTD-induced gaps and benign faults. It is a small MLP,
trained on the host and replayed with numpy on `semp`.

```bash
make detector-runs DET_SEEDS="1 2 3 4 5 6 7 8 9 10"   # labelled lab runs -> output/detector/runs/
make detector-train          # dev seeds (DET_DEV_SEEDS=1-3) only: ablation -> output/detector/ablation.md
make detector-final DET_FEATURES=v2h DET_HIDDEN=16,16 DET_SMOOTHING=2of3
                             # fit the chosen config on dev, score the test seeds (4-10) ONCE
                             # -> output/detector/kpi.md + detector.npz
make attack DETECTOR_MODEL=output/detector/detector.npz   # run it live in the dashboard
```

Everything that is tuned — feature set, network size, smoothing, threshold — is
chosen on the dev seeds; the test seeds are scored only by `detector-final`.

Each detector run uses the paper's MTD configuration, sniffs, then spends
`DET_POST_ATTACK` seconds with `DET_BLOCK_EPISODES` blackholes (the CNN
attacker's pick, or an oracle attacker blocking the address in use) and seeded
benign faults (netem loss / delay / burst loss on the router, executor restarts).
What really happened is written host-side to `ground_truth.jsonl`; labels come
from the captures and the broker log — a blackhole is "in effect" from the block
on the address the SCMC uses, or tries to use, until the broker receives nanogrid
data again — never from what the detector itself sees. KPIs are cross-validated
by run and reported for the MLP and for a plain threshold rule. Load
`telemetry.jsonl` and `ground_truth.jsonl` together in the dashboard to compare
alerts with the truth.

## 10. Quick reference

| What | Where |
|---|---|
| Topology and episode | `cyberrange/scenarios/mqtt_mtd/{topology,scenario}.py` |
| Command line of one run | `cyberrange/scenarios/mqtt_mtd/cli.py` |
| Paper campaign | `cyberrange/scenarios/mqtt_mtd/campaign.py`, `main.py` |
| Parameter ablation | `cyberrange/scenarios/mqtt_mtd/ablation.py` (`make sweep`) |
| Deploy manifest | `cyberrange/scenarios/mqtt_mtd/guest_files.py` |
| Metrics | `cyberrange/scenarios/mqtt_mtd/metrics.py` |
| Figures and analysis | `cyberrange/scenarios/mqtt_mtd/analysis/` |
| Offline training (RL, detector) | `cyberrange/scenarios/mqtt_mtd/training/` |
| MTD coordinators and executors | `cyberrange/planes/defense/agents/` |
| CNN fingerprinter | `cyberrange/planes/attack/classify.py` |
| The platform underneath | [platform.md](platform.md), [structure.md](structure.md) |
