# Smart Grid AI-MTD

AI-driven Moving Target Defense (MTD) for MQTT communications in a smart grid, emulated with [Kathará](https://github.com/KatharaFramework/Kathara).

---

## Installation

### 1. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install kathara
```

### 2. Docker image

```bash
docker build -t smartgrid/node:latest docker/mqtt/
```

### 3. Background traffic trace

Place a `traccia.pcap` in `assets/pcap/`. Then split it into train/test sets:

```bash
make split
```

---

## Makefile

### Experiment commands

| Goal | Command |
|---|---|
| Full pipeline — MTD (datasets → train → attack) | `make experiment` |
| Full pipeline — baseline, no MTD | `make experiment-baseline` |
| Full pipeline — all three scenarios + plots | `make all` |
| Generate train + test datasets (MTD) | `make datasets` |
| Generate train + test datasets (baseline) | `make datasets NO_MTD=1` |
| Train classifier (MTD) | `make train` |
| Train classifier (baseline) | `make train NO_MTD=1` |
| Evaluate model on test set (MTD model on MTD data) | `make evaluate` |
| Evaluate model on test set (baseline model on baseline data) | `make evaluate NO_MTD=1` |
| Evaluate baseline model on MTD data (cross-model) | `make evaluate MODEL_SRC=baseline` |
| Run all three evaluations | `make all-evaluate` |
| Attack — MTD scenario, MTD-trained model | `make attack` |
| Attack — baseline scenario (no MTD) | `make baseline` |
| Attack — MTD scenario, baseline-trained model (cross-model) | `make attack MODEL_SRC=baseline` |
| Run all three attack scenarios | `make all-attack` |
| Plot results (detection + availability charts) | `make plots` |
| Remove all generated outputs | `make clean` |

### Key variables

| Variable | Default | Meaning |
|---|---|---|
| `NO_MTD` | `0` | Set to `1` to switch to the baseline (no-MTD) variant |
| `MODEL_SRC` | same as variant | Source variant for the attack model (`baseline` or `mtd`) |
| `BG_TRACE` | `assets/pcap/traccia.pcap` | Source background trace to split |
| `SPLIT_RATIO` | `0.7` | Fraction of packets in the train split |
| `DATASET_DURATION` | `120` | Capture duration (seconds) per dataset |
| `ATTACK_DURATION` | `30` | Attacker sniff duration (seconds) |
| `MTD_HOP_INTERVAL` | `2` | Seconds between broker port hops |
| `MTD_PORT_POOL` | `8883–8887` | Broker port pool for MTD |
| `MTD_PAD_BUCKETS` | `128,256,…,1024` | Payload padding bucket sizes (bytes) |
| `MTD_PAD_INTERVAL` | `3` | Seconds between padding rotations |

Variables can be overridden on the command line:

```bash
make experiment DATASET_DURATION=60 MTD_HOP_INTERVAL=1
```
