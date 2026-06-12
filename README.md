# Smart Grid AI-MTD

AI-driven Moving Target Defense (MTD) for MQTT communications in a smart grid, emulated with [Kathará](https://github.com/KatharaFramework/Kathara).

The system models a microgrid SCMC publishing telemetry (power, frequency, voltage) over MQTT/TLS to a central SEMP broker, while a passive attacker on the backbone sniffs traffic. A simulated QKD exchange bootstraps mutual TLS; the attacker then captures traffic, identifies the SCMC by IP fingerprinting, and blocks it at the router — demonstrating the threat that MTD must counter.

---

## Architecture

```
  Network A (10.0.0.0/24)          Network B (10.1.0.0/24)
  ┌──────────────────────┐         ┌──────────────────────────┐
  │  SCMC  10.0.0.2      │         │  SEMP (broker)  10.1.0.2 │
  │  pymgrid + paho-mqtt │         │  mosquitto TLS  :8883    │
  └────────┬─────────────┘         └──────────┬───────────────┘
           │                                   │
           └──────────── ROUTER ───────────────┘
                     10.0.0.1 / 10.1.0.1
                     (routes + pcap replay)
                                   │
                         ┌─────────┴──────────┐
                         │  Attacker 10.1.0.3  │
                         │  tcpdump + analysis │
                         └────────────────────┘
```

**Security bootstrap (QKD simulation):** a 256-bit key is generated on the host and injected into both SEMP and SCMC as a stand-in for a Quantum Key Distribution channel. SEMP runs `cert_authority.py` — it self-signs a CA, signs the broker certificate, then listens for clients. SCMC runs `cert_client.py` — it sends its CN encrypted with the shared key, receives the signed cert bundle back encrypted. Mosquitto starts with mutual TLS (`require_certificate true`).

**Fingerprinting attack:** the attacker captures traffic on `eth0` with `tcpdump`. A packet-level 1D-CNN (`classify.py`) is trained offline to recognise the SCMC↔broker MQTT/TLS fingerprint; at attack time `run_experiment.py --attack` scores the live capture, ranks source IPs by their nanogrid probability, and the router drops all forwarded traffic from the top-ranked IP.

---

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.10+ | use the project venv |
| [Kathará](https://github.com/KatharaFramework/Kathara) | ≥ 3.7 | system binary + Python API |
| Docker | 24+ | Kathará backend |
| `smartgrid/node:latest` | — | custom image (see below) |

---

## Setup

### 1. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install kathara
```

### 2. Build the custom Docker image

All lab nodes use a single image that bakes in mosquitto, paho-mqtt, scapy, tcpreplay, and editcap — avoiding slow/unreliable `apt` runs at container start.

```bash
docker build -t smartgrid/node:latest docker/mqtt/
```

### 3. Background traffic trace

The experiment replays a real PCAP onto the backbone so the attacker sees realistic noise. Place a `traccia.pcap` in `assets/pcap/` (gitignored due to size). Without it, the router step will fail — comment out the relevant lines in `run_experiment.py` to skip replay.

A single source trace is split by packet count into independent train/test background traces (default 70/30) under `assets/pcap/datasets/`, either via `make split` or directly:

```bash
python split_trace.py assets/pcap/traccia.pcap --train-ratio 0.7 \
  --train-out assets/pcap/datasets/traccia_train.pcap \
  --test-out  assets/pcap/datasets/traccia_test.pcap
```

`split_trace.py` uses dpkt (raw packet records, no layer dissection), so splitting a ~1 GB trace takes seconds.

---

## Makefile pipeline

The whole workflow (split → datasets → train → attack) is driven by `make`:

```bash
make split               # split BG_TRACE into train/test background traces (SPLIT_RATIO)
make datasets            # generate train+test dataset PCAPs (deploys the Kathará lab twice)
make train               # train the 1D-CNN on the train dataset
make evaluate            # train + evaluate on the test dataset (plots + report)
make attack              # run the model-driven attack in the lab
make experiment          # full pipeline: datasets -> train -> attack
make baseline            # run the attack with MTD disabled (-> output/baseline/)
make experiment-baseline # full pipeline without MTD
make demo                # legacy demo, no model needed (hardcoded IP block)
make clean               # remove generated outputs (both variants)
```

Each target writes to a per-variant output tree: `output/mtd/` by default, `output/baseline/`
when MTD is disabled. Pass `NO_MTD=1` to any target to switch tree, or use the `baseline` /
`experiment-baseline` convenience targets (which recurse with `NO_MTD=1`). The two trees are
independent, so MTD and baseline runs keep separate datasets, models, and captures.

Steps whose output already exists are skipped, regardless of timestamps: `dataset-train`/`dataset-test` skip when `output/<variant>/datasets/{train,test}.pcap` are present, `train` skips when `output/<variant>/ml_results/model.pt` is present, and the split runs automatically only when the train/test background traces are missing. Delete the artifact (or `make clean`) to force regeneration.

| Variable | Default | Meaning |
|---|---|---|
| `BG_TRACE` | `assets/pcap/traccia.pcap` | Source background trace to split |
| `SPLIT_RATIO` | `0.7` | Fraction of packets in the train split |
| `TRAIN_TRACE` / `TEST_TRACE` | `assets/pcap/datasets/<stem>_{train,test}.pcap` | Background traces replayed during the train/test captures |
| `DATASET_DURATION` | `120` | Capture duration (seconds) per dataset |
| `ATTACK_DURATION` | `30` | Attacker sniff duration (seconds) |

Override on the command line, e.g.:

```bash
make experiment BG_TRACE=assets/pcap/capture.pcap SPLIT_RATIO=0.8 DATASET_DURATION=60
```

---

## `run_experiment.py` — Kathará orchestrator

Always activate the venv first: `source .venv/bin/activate`. Every run wipes existing Kathará
state, deploys the four-node lab, bootstraps mutual TLS via the simulated QKD exchange, and
starts the mosquitto broker. The flags select what happens next.

### 1. Generate a labelled dataset

Captures one mixed PCAP (background replay + SCMC telemetry together) for `DURATION` seconds.
Run it **twice on independent background traces** to get train/test sets — `make datasets`
automates both runs on the two splits of the source trace.

```bash
# training set (background: train split of the source trace)
python run_experiment.py --generate-dataset 120 --name train --trace assets/pcap/datasets/traccia_train.pcap
# test set (background: test split → independent noise, avoids overfitting)
python run_experiment.py --generate-dataset 120 --name test  --trace assets/pcap/datasets/traccia_test.pcap
```

| Flag | Default | Meaning |
|---|---|---|
| `--generate-dataset DURATION` | — | Capture seconds; triggers dataset mode |
| `--name NAME` | `dataset` | Output → `output/<variant>/datasets/NAME.pcap` (`mtd`/`baseline`) |
| `--trace PATH` | `assets/pcap/traccia_2b.pcap` | Background PCAP replayed by tcpreplay |
| `--split TRAIN_RATIO` | — | Split `--trace` by packet count into `assets/pcap/datasets/<stem>_{train,test}.pcap` and replay the part matching `--name` (test split when `--name test`, train split otherwise) |

### 2. Run the model-driven attack

The attacker sniffs for `DURATION` seconds, the host scores that capture with the trained model,
ranks source IPs by nanogrid probability, and the router blocks the top-ranked IP.

```bash
python run_experiment.py --attack 30
```

| Flag | Default | Meaning |
|---|---|---|
| `--attack DURATION` | — | Attacker sniff seconds; triggers attack mode |
| `--post-attack SECONDS` | `15` | Keep capturing after the block to record its effect |
| `--model PATH` | `output/ml_results/model.pt` | Trained model |
| `--scaler PATH` | `output/ml_results/scaler.pkl` | Fitted scaler |

#### Baseline (no MTD)

Add `--no-mtd` (or run `make baseline`) to repeat the attack with the defense turned off — the
comparison point for the MTD experiment. In baseline mode the broker uses a dedicated config
(`assets/mosquitto/mosquitto_nomtd.conf`) that listens directly on `8883`, so the MTD
coordinator and its iptables NAT are not needed: no coordinator/executor is started and the
SCMC runs the plain publisher (`simple_client.py`) with a fixed packet fingerprint. The
classifier then identifies the SCMC's real IP and the router block takes it down, whereas with
MTD the padding defeats the fingerprint and the wrong IP is blocked. The flag also applies to
`--generate-dataset` (capture an un-defended dataset).

All baseline artifacts (datasets and captures) land under `output/baseline/`, keeping them
separate from the MTD run in `output/mtd/`. `make baseline` builds the baseline dataset and
model on demand, then runs the attack.

```bash
python run_experiment.py --attack 30 --no-mtd
make baseline
```

### 3. Default demo (no model)

With no flag, `run_experiment.py` runs the legacy demo: it blocks a hardcoded SCMC IP after a
fixed 10 s sniff. Useful for a quick end-to-end smoke test without a trained model.

```bash
python run_experiment.py
```

**Outputs** are written to a per-variant tree — `output/mtd/` with MTD enabled,
`output/baseline/` with `--no-mtd` — so the two runs never overwrite each other (`<v>` below
is `mtd` or `baseline`):

| File | Contents |
|---|---|
| `output/<v>/datasets/<name>.pcap` | Labelled dataset (dataset mode) |
| `output/<v>/attacker_capture.pcap` | Packets seen by the attacker on the backbone |
| `output/<v>/router_capture.pcap` | Router traffic spanning before + after the block |
| `output/<v>/mosquitto.log` | Mosquitto broker log (connections, publishes) |

---

## `classify.py` — packet-level traffic classifier

A 1D-CNN that labels each packet as `nanogrid` (SCMC↔broker MQTT/TLS) or `background`, using a
context window of the preceding packets in its flow. Three modes; ground-truth labels are
derived from the SCMC/SEMP IPs and broker port (defaults match the lab: `10.0.0.2`, `10.1.0.2`,
`8883`).

### Train

```bash
python classify.py --mode train --train-pcap output/mtd/datasets/train.pcap --out-dir output/mtd/ml_results
```
Saves `model.pt` + `scaler.pkl` to `--out-dir` (default `output/ml_results/`; the Makefile
passes `output/<variant>/ml_results`).

### Evaluate (train + test in one run)

```bash
python classify.py --mode evaluate \
  --train-pcap output/mtd/datasets/train.pcap \
  --test-pcap  output/mtd/datasets/test.pcap \
  --out-dir    output/mtd/ml_results
```
Prints the packet-level classification report, ROC-AUC and confusion matrix, and saves
`roc_curve.png`, `confusion_matrix.png` and per-packet `predictions.csv` to `--out-dir`.

### Infer (detect the nanogrid IP in a capture)

```bash
python classify.py --mode infer --test-pcap output/mtd/attacker_capture.pcap
```
Loads `--model`/`--scaler`, scores the PCAP, and prints the most likely nanogrid source IP.

**Common options:** `--scmc-ip`, `--semp-ip`, `--broker-port` (labelling); `--window-size` (32),
`--epochs` (50), `--batch-size` (64), `--lr` (1e-3) (training); `--threshold` (0.5),
`--model`, `--scaler`, `--out-dir`.

---

## Project structure

```
smart-grid-mtd/
├── Makefile                   # Pipeline driver: split -> datasets -> train -> attack
├── run_experiment.py          # Kathará orchestrator — main entry point
├── classify.py                # Packet-level 1D-CNN traffic classifier
├── split_trace.py             # Train/test split of a background pcap (dpkt, fast)
├── requirements.txt
├── assets/
│   ├── qkd/
│   │   ├── cert_authority.py  # CA server (SEMP): issues certs over QKD-keyed channel
│   │   └── cert_client.py     # Cert client (SCMC): receives signed cert bundle
│   ├── mosquitto/
│   │   └── mosquitto.conf     # TLS broker config (mutual auth, port 8883)
│   ├── simple_client.py       # SCMC: pymgrid simulator + paho-mqtt publisher
│   ├── traffic_generator.py   # Alternative traffic generator
│   ├── replay_background.sh   # tcpreplay wrapper for background noise
│   └── pcap/                  # Real traffic traces (gitignored if large)
│       └── datasets/          # Train/test background splits (make split)
├── docker/
│   └── mqtt/Dockerfile        # Custom node image (kathara/core + mosquitto + tooling)
└── output/                    # Experiment outputs (gitignored)
```

---

## Research context

This prototype is the emulation layer for a paper targeting IEEE SmartGridComm / ACM CPS-SPC. The full system will extend this baseline with:

- Three SCMCs publishing concurrently
- LSTM anomaly detection on traffic features
- DQN agent (stable-baselines3) selecting from 8 MTD actions (IP hop, port randomisation, payload padding, …)
- QKD key rotation every 30 s driving cert re-issuance
- Attacker using a RandomForest on 7 traffic features for fingerprinting
- Experiments E1–E7 measuring attacker accuracy under each MTD configuration
