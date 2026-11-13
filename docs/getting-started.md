# Set-up and first run

This page takes you from a fresh clone to a scenario running and scored. For what
the targets and variables mean once you are past the first run, see
[Running and measuring](running-and-metrics.md).

## Prerequisites

- **Python 3.12** and `python3-venv`.
- **Docker** — the lab nodes are containers.
- **[Kathará](https://github.com/KatharaFramework/Kathara)** — the network
  emulator that deploys the labs. Install it and make sure `kathara` is on your
  `PATH`.

The platform runs from the repository root; it is never installed as a package.
Every command below is run from the repository root, using the project's
virtualenv at `.venv`.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` pins everything the platform, the tests and the tooling need
(including the documentation site). Guest agents inside the containers do **not**
use this virtualenv — they only have what their node image installs.

## Build the node images

Each scenario runs on container images you build once:

```bash
docker build -t kathara/mqtt docker/mqtt/   # mqtt-mtd
make cps-image                              # cps and cps-advisor: kathara/cps + kathara/soc
make cps-recon-image                        # cps-recon: the attacker's box (nmap); needs cps-image too
```

## Verify the checkout without Docker

The whole test suite runs with no Kathará and no Docker — run it first to confirm
the checkout is sound:

```bash
make selftest        # the whole suite
make selftest-fast   # the same, without the heavy tests (torch/pandapower/subprocesses)
```

## Your first run

### CPS (OT/Modbus) — the most illustrative

Deploy the lab, drive an attack chain, and score it:

```bash
make cps-attack CPS_OUT=output/cps/hijack CPS_ATTACK_MODE=manual-hijack SEED=1
make cps-metrics CPS_OUT=output/cps/hijack
```

Follow it live in a second terminal:

```bash
make dashboard       # http://127.0.0.1:8765  — every scenario's runs and campaigns
```

### MQTT MTD — the paper's scenario

The MQTT scenario needs a background traffic trace. Place a `traccia.pcap` in
`assets/pcap/`, then split it into train/test sets:

```bash
make split
```

The whole paper evaluation — baseline, fixed-timer MTD, RL-cost, RL-entropy, with
the figures at the end — runs as one campaign:

```bash
.venv/bin/python main.py             # add --dry-run to see the plan first
```

### Put a human in the loop

```bash
make cps-advisor     # attack the lab; the SOC suggests, you approve/reject at its console (:8766)
make cps-teams       # red team vs blue team, each from its own console — see the playground guide
```

The [red vs blue playground guide](playground-red-vs-blue.md) explains the
team-vs-team mode end to end.

## The handful of commands to know

```bash
make help            # the authoritative catalogue: every target, its defaults, where it writes
make dashboard       # follow any run or campaign live, any scenario
make selftest        # the whole test suite — no Kathará, no Docker
make fmt             # ruff format: layout only, never logic
make lint            # what fmt cannot fix: dead imports, long lines
make clean           # remove everything under output/
```

`make help` is always the source of truth for targets and the variables that shape
a run (`SEED`, `CPS_OUT`, `CPS_ATTACK_MODE`, `RL=1`, …).

## Troubleshooting

- **A run produces nothing / the lab will not come up.** Check Docker is running
  and the scenario's images are built (see above). `make clean` clears stale
  `output/` state between runs.
- **`kathara: command not found`.** Kathará is not installed or not on `PATH`; the
  test suite still passes without it, but no lab will deploy.
- **A heavy test fails on import (torch, pandapower).** Use `make selftest-fast`
  while iterating; the heavy dependencies are only needed for the full suite and
  for actually running the relevant scenarios.
