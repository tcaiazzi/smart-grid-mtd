# Smart Grid AI-MTD

A cyber range for smart-grid security, emulated with
[Kathará](https://github.com/KatharaFramework/Kathara). It began as AI-driven
Moving Target Defense (MTD) for MQTT communications in a smart grid, which is
still its first scenario.

The repository is a **platform** for testing attacks and defences on emulated
cyber-physical systems safely, reproducibly and observably, with three
**scenarios** running on it:

| Scenario | What it studies | Read |
|---|---|---|
| `mqtt-mtd` | The workshop paper's: MTD against ML traffic fingerprinting | [docs/scenario-mqtt.md](docs/scenario-mqtt.md) |
| `cps` | A cyber-physical OT/Modbus plant: active IT→OT attack, DPI and IT sensors, a SOC (Wazuh + analytics) that decides and responds inside the lab | [docs/scenario-cps.md](docs/scenario-cps.md) |
| `cps-advisor` | The `cps` lab with people in it: the SOC advises an operator instead of acting, and a red team can attack by hand against a blue team | [docs/scenario-cps-advisor.md](docs/scenario-cps-advisor.md), and for the players [docs/playground-red-vs-blue.md](docs/playground-red-vs-blue.md) |

How the platform is built and how to add a scenario:
**[docs/platform.md](docs/platform.md)**. Every reusable component of the four
planes: **[docs/components.md](docs/components.md)**. Where a file goes and why:
**[docs/structure.md](docs/structure.md)**.

## Layout

The platform lives in one package, `cyberrange/`, laid out as the three layers
of the architecture; the software the lab's nodes run that is not the
platform's lives beside it, in `nodes/`:

```
core  <-  planes  <-  scenarios        imports point left; nothing points back
nodes/                                 imports none of them, and none imports it
```

| Directory | What it holds |
|---|---|
| `cyberrange/core/` | The platform: declarative topology, run lifecycle, the three event streams, campaigns (95% CI aggregate), scenario registry, progress ledger and dashboard |
| `cyberrange/planes/traffic/` | Background trace replay, the nanogrid MQTT publishers, the plant and PLC |
| `cyberrange/planes/attack/` | The 1D-CNN fingerprinting classifier, the attack chain, the launchers of the in-lab tree-guided attacker and of the red team's console |
| `cyberrange/planes/defense/` | MTD coordinators (fixed-timer + RL), OT/IT sensors, the launchers of Wazuh and of the SOC's analytics, the QKD-simulated cert bootstrap |
| `cyberrange/planes/monitor/` | Capture, the telemetry/plant mirrors, the web terminals and the record of what people type in them |
| `cyberrange/scenarios/<name>/` | One scenario, whole: topology, episode, CLI, campaign, deploy manifest, metrics, `analysis/`, `training/` |
| `nodes/` | Node software: the Wazuh configuration and active response (`wazuh/`), the SOC's analytics, SOAR reasoning and operator console (`soc/`), the autonomous tree-guided attacker with its planner and the red team's console (`redteam/`), shell access and command recording (`common/`) |
| `tests/`, `make/`, `scripts/`, `tools/`, `docs/` | Tests by area, the makefiles, the manual single-run script, cross-scenario tooling, documentation |

Each plane exposes its reusable building blocks in `components.py`; a scenario
composes them. One directory holds one scenario — which is what makes
`make platform-loc` a true measure of what a new scenario costs.

Files under a plane's `agents/` (and `cyberrange/planes/defense/qkd/`), and
everything under `nodes/`, are deployment data: they are copied flat into the
Kathará containers and run there directly, so they cannot use package-relative
imports. Each scenario lists what
it stages in its own `guest_files.py`; the contract is documented in
`cyberrange/core/topology.py`. Everything else is a normal importable module,
invoked with `-m` rather than by path.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Node images:

```bash
docker build -t kathara/mqtt docker/mqtt/   # MQTT scenario
make cps-image                              # cps and cps-advisor: kathara/cps (plant nodes, Wazuh agent,
                                            # ttyd) and kathara/soc (Wazuh manager, ttyd)
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
response loop — the scenario documents are the reference.

Two more are for people rather than experiments. `PLAYGROUND=1` on a single-run
target keeps its lab up after the episode, until Ctrl-C. `make cps-teams` is a
red team against a blue team on the CPS lab: each team gets a console and a web
terminal on its own node, and `make dashboard` is the referee's read-only view
([docs/playground-red-vs-blue.md](docs/playground-red-vs-blue.md)).

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
