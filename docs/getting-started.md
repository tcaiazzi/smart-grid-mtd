# Set-up and first run

This page takes you from a fresh clone to a scenario running and scored. For what
the targets and variables mean once you are past the first run, see
[Running and measuring](running-and-metrics.md).

## Prerequisites

| What | Why |
|---|---|
| **Linux**, or Windows with WSL2 | The labs are Linux containers on Docker networks. |
| **Python 3.12** and `python3-venv` | The platform, the tests and the tooling. |
| **Docker**, usable by your user without `sudo` | The lab nodes are containers. |
| **[Kathará](https://www.kathara.org/)** with `kathara` on your `PATH` | The network emulator that deploys the labs. `requirements.txt` pins its Python API to 3.8.3; install the same release. |
| **Node.js** (optional) | Only the tests of the dashboard panels and of the scenario guide need it. Without `node` they skip themselves. |
| **Internet access** while building images | The image builds download packages, and `make cps-soc-image` pulls DFIR-IRIS's images. |
| **Memory** | The `cps-soc` lab needs about 3 GB more than the other CPS labs. |

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
make cps-recon-image                        # cps-recon: the attacker's box (nmap, networkx); needs cps-image too
make cps-soc-image                          # cps-soc: the lab CA, Wazuh indexer/dashboard, DFIR-IRIS; needs cps-image too
make cps-players-image                      # only to seat a harness as a player (make cps-agents, cps-bench)
```

You only need the images of the scenarios you run: `make cps-image` is enough for
the first run below.

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
make cps-attack CPS_ATTACK_MODE=manual-hijack SEED=1
make cps-metrics
```

Follow it live in a second terminal:

```bash
make dashboard       # http://127.0.0.1:8765  — every scenario's runs and campaigns
```

**What you should see.** The run takes about a minute and a half. The terminal
logs each phase as it is entered — deploy, services, normal operation, the
attack, the watch after it, download, undeploy — and the lab is torn down at
the end, also when the run fails or is interrupted. The run writes a directory
of its own, `output/cps/runs/<date-time>/`, and `output/cps/latest` points at
it, which is why `make cps-metrics` needs no argument. In it:

| File | What it is |
|---|---|
| `run.json` | The run's card: commit, lab, options, how it ended |
| `progress.jsonl` | The timeline the dashboard shows |
| `ground_truth.jsonl` | What the attack really did |
| `sensor.telemetry.jsonl`, `response.jsonl` | What the sensor reported and what the SOC made of it |
| `topology.json`, `kg.json`, `tree.json` | The lab, its knowledge graph and its attack tree |
| `<node>.<name>.log` | Each node's logs |
| `metrics.json`, `metrics.md` | The score, as data and as a page to read |

Every file a run can leave is listed in the [reference](reference.md#artifacts).
On the dashboard the run appears as soon as it starts: the plant's voltage
leaves its band when the attack takes the controller, and the sensor's
findings and the SOC's response follow. [The dashboard](dashboard.md) explains
what each part shows.

Every run gets a new directory, so the same command can be repeated. To name
the directory yourself use `CPS_OUT=output/cps/mine`; one that already holds a
run is refused unless you add `OVERWRITE=1`
([Running and measuring](running-and-metrics.md)).

### MQTT MTD

The MQTT scenario needs a background traffic trace: a capture the router
replays with `tcpreplay`, at the rate the run asks for, as the traffic the
nanogrids' MQTT messages hide in. The trace used for the paper is not
distributed with the repository, and any pcap of ordinary network traffic
does the job. Place yours at `assets/pcap/traccia.pcap` (or name another with
`BG_TRACE=…`), then split it into the part the attacker trains on and the part
it is tested on:

```bash
make split           # -> assets/pcap/datasets/traccia_train.pcap, traccia_test.pcap
```

Results obtained on another trace are comparable with each other, not with the
paper's numbers.

The whole evaluation — baseline, fixed-timer MTD, RL-cost, RL-entropy, with
the figures at the end — runs as one campaign:

```bash
.venv/bin/python main.py             # add --dry-run to see the plan first
```

It takes hours: it trains the two RL policies first if they are missing, then
runs every configuration. [MQTT MTD](scenario-mqtt.md) has the pipeline step by
step, for running one part of it.

### Put a human in the loop

```bash
make cps-advisor     # attack the lab; the SOC suggests, you approve/reject at its console (:8766)
make cps-teams       # red team vs blue team, each from its own console — see the playground guide
make cps-soc         # the same with the blue team on Wazuh (:8770) and DFIR-IRIS (:8771); ~3 GB more memory
```

The [red vs blue playground guide](playground-red-vs-blue.md) explains the
team-vs-team mode end to end.

## Stopping and cleaning up

A run undeploys its own lab when it ends. Ctrl-C does the same: the run stops,
collects what there is and tears the lab down, so press it once and wait. A lab
kept up on purpose (`PLAYGROUND=1`, `make cps-teams`) stays until Ctrl-C. The
dashboard is a separate process: stop it with Ctrl-C in its own terminal.

If a lab is left behind — the process was killed, the machine went down — see
[Troubleshooting](troubleshooting.md#a-lab-is-still-up-after-a-crash). `make clean`
removes everything under `output/`, **every run included**: it is not a way to
reset a lab.

## The handful of commands to know

```bash
make help            # every target, with what it writes where
make runs            # the runs kept under output/, one line each
make dashboard       # follow any run or campaign live, any scenario
make selftest        # the whole test suite — no Kathará, no Docker
make check           # lint + the suite + a dry run of every target: before calling a change done
make fmt             # ruff format: layout only, never logic
make lint            # what fmt cannot fix: dead imports, long lines
make clean           # remove everything under output/, every run included
```

`make help` lists the targets. The variables that shape a run (`SEED`,
`CPS_OUT`, `CPS_ATTACK_MODE`, `RL=1`, …) are in the
[reference](reference.md), with their defaults.

## When something goes wrong

[Troubleshooting](troubleshooting.md) covers the usual cases: a lab that will not
come up or was left running, a port already in use, a run that produced nothing,
tests that fail on a heavy import.
