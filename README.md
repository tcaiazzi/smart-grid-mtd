# Smart Grid AI-MTD

AI-driven Moving Target Defense (MTD) for MQTT communications in a smart grid, emulated with [Kathará](https://github.com/KatharaFramework/Kathara).

The source is organized into the platform's four functional planes plus the
network scenario they surround (see the paper, Fig. 1):

| Package | Plane |
|---|---|
| `network_scenario/` | Kathará lab (topology, machines, deploy/exec lifecycle) |
| `defense_plane/` | MTD coordinators (fixed-timer + RL), the QKD-simulated cert bootstrap |
| `attack_plane/` | The 1D-CNN fingerprinting classifier + attack actuation |
| `traffic_generator/` | Background trace replay + the nanogrid MQTT publishers |
| `monitor/` | Run-artifact collection, defender/attacker analysis, all figures |

Files under a plane's `agents/` (and `defense_plane/qkd/`) are deployment data:
they are copied flat into the Kathará containers and run there directly, so
they cannot use package-relative imports — see the module docstring in
`network_scenario/guest_files.py`. Everything else is a normal importable
package. The nine Python entrypoints the `Makefile` invokes by path
(`run_experiment.py`, `classify.py`, `entropy.py`, `plot_results.py`,
`compare_coordinators.py`, `train_rl_coordinator.py`, `plot_tradeoff.py`,
`plot_sweep.py`, `split_trace.py`) stay at the repo root as thin shims into
their package, so the `Makefile` and the `run_*.sh` scripts below work
unchanged.

**To reproduce the paper's evaluation (Fig. 2/3) end to end in one command:**

```bash
.venv/bin/python main.py              # all four configs + the paper figures
.venv/bin/python main.py --dry-run    # print every command without running it
.venv/bin/python main.py --mbps 5     # same, at a different replay rate
```

`main.py` runs the four configurations compared in §VI-G — baseline, fixed-timer
MTD, RL-cost, RL-entropy (training both RL policies first if missing) — at the
replay rate (`MBPS=2`) the paper's reported numbers were generated at, then
runs `compare_coordinators.py` to produce `availability_comparison.pdf` (Fig. 2a),
`detection_comparison.pdf` (Fig. 2b), `availability_cost_comparison.pdf` (Fig. 2c)
and `entropy_comparison.pdf` (Fig. 3) under `output/compare-<slug>/`. It shells
out to the same `make` targets `run_single.sh` does, so the two stay in
lockstep — see `tests/` for the checks that enforce that.

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

### Output layout

Everything for one parameter configuration is written to a single self-contained
directory `output/<exp-slug>/`, where the slug is `baseline-mbps<M>` for the
baseline variant and `mtd-hop<H>-padint<PI>-ips<NI>-ports<NP>-pads<NB>-mbps<M>`
for an MTD configuration:

```
output/
  baseline-mbps2/
    datasets/   train.pcap test.pcap  train.client.log train.mosquitto.log  test.*.log
    model/      model.pt scaler.pkl
    eval/       model-baseline/   predictions.csv roc_curve.pdf confusion_matrix.png
    attack/     model-baseline/   attacker_capture.pcap router_capture.pcap nanogrid_ranking.csv mosquitto.log client.log
    summary.csv detection.pdf availability.pdf            # from `make plots`
  mtd-hop2-padint3-ips3-ports5-pads7-mbps2/
    datasets/  model/
    eval/  attack/    model-mtd/...  model-baseline/...   # cross-model results too
    summary.csv ...
  sweep/        e1_*.pdf e2_*.pdf e3_*.pdf sweep_results.csv   # aggregate (run_sweep.sh)
  sweep_manifest.csv
```

Results are keyed by the scoring model (`model-mtd` / `model-baseline`); the
cross-model run reads the baseline model from `output/baseline-mbps<M>/model/`.
