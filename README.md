# Smart Grid AI-MTD

AI-driven Moving Target Defense (MTD) for MQTT communications in a smart grid,
emulated with [Kathará](https://github.com/KatharaFramework/Kathara).

The repository is a **platform** for testing attacks and defences on emulated
cyber-physical systems safely, reproducibly and observably, with two
**scenarios** running on it:

| Scenario | What it studies | Read |
|---|---|---|
| `mqtt-mtd` | The workshop paper's: MTD against ML traffic fingerprinting | [docs/scenario-mqtt.md](docs/scenario-mqtt.md) |
| `cps` | A cyber-physical OT/Modbus plant: active IT→OT attack, DPI and IT sensors, SOAR response | [docs/scenario-cps.md](docs/scenario-cps.md) |

How the platform is built and how to add a scenario:
**[docs/platform.md](docs/platform.md)**. Every reusable component of the four
planes: **[docs/components.md](docs/components.md)**. Where a file goes and why:
**[docs/structure.md](docs/structure.md)**.

## Layout

Everything lives in one package, `cyberrange/`, laid out as the three layers of
the architecture:

```
core  <-  planes  <-  scenarios        imports point left; nothing points back
```

| Directory | What it holds |
|---|---|
| `cyberrange/core/` | The platform: declarative topology, run lifecycle, the three event streams, campaigns (95% CI aggregate), scenario registry, progress ledger and dashboard |
| `cyberrange/planes/traffic/` | Background trace replay, the nanogrid MQTT publishers, the plant and PLC |
| `cyberrange/planes/attack/` | The 1D-CNN fingerprinting classifier, the attack chain and the tree-guided planner |
| `cyberrange/planes/defense/` | MTD coordinators (fixed-timer + RL), OT/IT sensors, SOAR, the QKD-simulated cert bootstrap |
| `cyberrange/planes/monitor/` | Capture and the telemetry/plant mirrors |
| `cyberrange/scenarios/<name>/` | One scenario, whole: topology, episode, CLI, campaign, deploy manifest, metrics, `analysis/`, `training/` |
| `tests/`, `make/`, `scripts/`, `tools/`, `docs/` | Tests by area, the makefiles, the manual single-run script, cross-scenario tooling, documentation |

Each plane exposes its reusable building blocks in `components.py`; a scenario
composes them. One directory holds one scenario — which is what makes
`make platform-loc` a true measure of what a new scenario costs.

Files under a plane's `agents/` (and `cyberrange/planes/defense/qkd/`) are
deployment data: they are copied flat into the Kathará containers and run there
directly, so they cannot use package-relative imports. Each scenario lists what
it stages in its own `guest_files.py`; the contract is documented in
`cyberrange/core/topology.py`. Everything else is a normal importable module,
invoked with `-m` rather than by path.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install kathara
```

Node images, one per scenario:

```bash
docker build -t smartgrid/node:latest docker/mqtt/   # MQTT scenario
make cps-image                                       # CPS scenario (pandapower + pymodbus)
```

The MQTT scenario needs a background traffic trace. Place a `traccia.pcap` in
`assets/pcap/`, then split it into train/test sets:

```bash
make split
```

## The five commands

```bash
make help                 # every target, with what it writes where
make selftest             # the whole test suite — no Kathará, no Docker
.venv/bin/python main.py  # the paper's evaluation end to end (--dry-run to look first)
make cps-attack CPS_OUT=output/cps/hijack CPS_ATTACK_MODE=manual-hijack SEED=1
make dashboard            # follow any run or campaign live, any scenario
```

`main.py` runs the four configurations compared in §VI-G — baseline,
fixed-timer MTD, RL-cost, RL-entropy, training both RL policies first if they are
missing — at the replay rate (`MBPS=2`) the paper's numbers were generated at,
and ends with the figures: `availability_comparison.pdf` (Fig. 2a),
`detection_comparison.pdf` (Fig. 2b), `availability_cost_comparison.pdf`
(Fig. 2c), `entropy_comparison.pdf` (Fig. 3).

It runs as a campaign on the platform's runner: lab steps are retried, a failed
configuration does not stop the others, every attack run is scored, and
`output/campaigns/paper-mbps<M>/summary.md` holds the per-configuration
mean [95% CI] across `--runs`. `make dashboard` follows it live.

For anything beyond these five — the experiment pipeline step by step, the
variables that shape a run, the output layout, the parameter ablation, the SOAR
response loop — the two scenario documents are the reference.

## Working in this repository

`make help` is the authoritative catalogue of targets: it prints every one with
its defaults and where it writes. Beyond that:

```bash
make fmt                  # ruff format: layout only, never logic
make lint                 # what fmt cannot fix: dead imports, long lines
make selftest-fast        # the suite without the heavy tests
make platform-loc         # how much code is platform and how much is scenario
```

Conventions, the rules that are not negotiable, and the gate to pass before
calling a change done are in [CLAUDE.md](CLAUDE.md) and
[docs/structure.md](docs/structure.md).
