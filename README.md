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
package, invoked as a module rather than by path — e.g.
`.venv/bin/python -m network_scenario.run_experiment`, `-m attack_plane.classify`,
`-m monitor.plot_results` — which is how the `Makefile` and the `run_*.sh`
scripts below run every host-side stage.

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
| `DASHBOARD_PORT` | `8080` | Host port of the live MTD dashboard (`0` disables it) |

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

### Live MTD dashboard

During every MTD run (fixed-timer or RL) the coordinator on `semp` serves a live
dashboard at `http://localhost:8080/` (`make attack DASHBOARD_PORT=9090` to move
it, `DASHBOARD_PORT=0` to turn it off). It shows the MTD actions taken and how
each one ended (applied, failed and rolled back, timed out, client lost), the
cumulative availability cost (same per-knob weights as the RL reward and
`compare_coordinators`), how often updates are sent and skipped, ACK/DONE
latencies, delivery problems, executor health, the currently exposed attack
surface, the nanogrid messages actually reaching the broker (with gaps), and —
for the RL coordinator — every policy decision.

The page is reached through a Kathará bridged interface + port forward on `semp`,
never over link B, so the attacker's capture contains no dashboard traffic; the
data-plane observer subscribes over a loopback-only mosquitto listener. Every
event is also written to `telemetry.jsonl`, downloaded next to `coordinator.log`;
open `defense_plane/agents/mtd_dashboard.html` directly in a browser and load
that file to replay a finished run.

### Delivery-attack detector (blackhole seen from the SEMP)

The attacker's active phase blackholes an address on the router, so nanogrid data
stops reaching the SEMP. `defense_plane/delivery_detector.py` scores every SCMC each
second from the SEMP's telemetry alone (data silence, MTD actions left unanswered,
control-channel state, ACK latency) and tells a blackhole apart from MTD-induced
gaps and benign faults. It is a small MLP, trained on the host and replayed with
numpy on `semp`.

```bash
make detector-runs DET_SEEDS="1 2 3 4 5 6 7 8 9 10"   # labelled lab runs -> output/detector/runs/
make detector-train          # dev seeds (DET_DEV_SEEDS=1-3) only: ablation -> output/detector/ablation.md
make detector-final DET_FEATURES=v2h DET_HIDDEN=16,16 DET_SMOOTHING=2of3
                             # fit the chosen config on dev, score the test seeds (4-10) ONCE
                             # -> output/detector/kpi.md + detector.npz
make attack DETECTOR_MODEL=output/detector/detector.npz   # run it live in the dashboard
```

Everything that is tuned (feature set, network size, smoothing, threshold) is chosen
on the dev seeds; the test seeds are only scored by `detector-final`.

Each detector run uses the paper's MTD configuration, sniffs, then spends
`DET_POST_ATTACK` seconds with `DET_BLOCK_EPISODES` blackholes (the CNN attacker's
pick, or an oracle attacker blocking the address in use) and seeded benign faults
(netem loss / delay / burst loss on the router, executor restarts). What really
happened is written on the host to `ground_truth.jsonl`; labels come from the
captures and the broker log (a blackhole is "in effect" from the block on the
address the SCMC uses, or tries to use, until the broker receives nanogrid data
again), never from what the detector itself sees. KPIs are cross-validated by run and
reported for the MLP and for a plain threshold rule. Load `telemetry.jsonl` and
`ground_truth.jsonl` together in the dashboard to compare alerts with the truth.

---

## Cyber-physical (OT/Modbus) scenario

A second scenario emulates a small industrial plant and the full chain *IT
intrusion → pivot to OT → unauthorized Modbus write → physical effect →
detection* (the Mashfrog prototype, doc steps 1–4). It is independent of the
MQTT/MTD pipeline above and runs on its own node image.

Three zones joined by an IT/OT boundary firewall that forwards **only HMI → engine
Modbus**: the attacker cannot reach the plant directly, it has to compromise the HMI
and pivot from it, so its writes come from an allowed host.

```
IT 10.10.0.0/24           firewall            OT 10.20.0.0/24         DEF 10.30.0.0/24
  attacker 10.10.0.10   10.10.0.1|10.20.0.1    plc    10.20.0.10        sensor 10.30.0.10
  hmi      10.10.0.20    (FORWARD DROP,        engine 10.20.0.20       (mgmt / findings)
                          HMI->engine Modbus    sensor eth0 (passive sniff)
                          allowed)
```

- **Physical engine** (`traffic_generator/agents/grid_sim.py` + `modbus_engine.py`):
  a pandapower LV-feeder digital twin behind a Modbus/TCP server. Sensors are input
  registers; actuators (DG setpoint, feeder breaker, **control mode** auto/manual)
  are holding registers — the register map, access policy per role and control
  constants are the plant contract in `defense_plane/ot_registers.py`. The feeder is
  sized so a full-rated 60 kW DG — an *in-range* command — overvolts the DG bus.
- **PLC** (`traffic_generator/agents/plc_controller.py`): the Modbus master. In AUTO
  it regulates the worst bus voltage, rejects out-of-envelope setpoints in force and
  relaxes back to the 20 kW nominal; in MANUAL (operator authority) it hands off.
- **HMI** (`traffic_generator/agents/hmi_client.py`): the legitimate IT client — one
  persistent session polling sensors/actuators, and every ~12 s a safe operator
  dispatch (MANUAL, 15–35 kW for 5 s, back to AUTO). This is the normal behaviour
  the sensor must tell the attack apart from.
- **Active attacker** (`attack_plane/agents/vuln_app.py` on the HMI host,
  `exploit_client.py`, `ot_write.py`; driver `attack_plane/active_attack.py`):
  exploits the vulnerable diagnostics app (real OS command injection → RCE), pivots
  across the boundary from the HMI's IP, then (`CPS_ATTACK_MODE`):
  - `setpoint-overvoltage` — DG setpoint out of range (loud; the PLC rejects it and
    the plant recovers),
  - `breaker-open` — opens the feeder breaker (loss of supply; a policy violation),
  - `manual-hijack` — takes MANUAL authority and dispatches 60 kW: every value is
    legal and the source is the HMI, so source/range rules cannot see it, and the
    overvoltage **persists** after the attacker leaves because the PLC stands down.

  Every write is recorded in `ground_truth.jsonl` with the time it was issued.
  **The app is intentionally insecure and lab-only.**
- **DPI sensor** (`defense_plane/agents/ot_sensor.py` + `ot_model.py`, stdlib + numpy):
  passively parses Modbus requests *and* responses on the OT link, reconstructing
  the plant state from the read responses. Two detectors, each finding tagged with
  `detector`:
  - **rules** — out-of-range command, unknown client (write/read), role policy
    violation, `unsafe_command` (a sensitive write followed by the observed voltage
    leaving the band), `manual_mode_excursion` (MANUAL while out of band);
  - **model** — per-second behavioural features (session churn, setpoint jump size,
    time in MANUAL, observed voltages, …) scored by a robust median/MAD model
    calibrated online on the first `CPS_LEARN` seconds of the normal phase.

  Alerts are raised once and cleared when the condition ends. Findings ride the
  reused telemetry/dashboard bus.

### Commands

```bash
make cps-selftest      # physics, Modbus, PLC, sensor rules+model, attack chain — NO Kathará
make cps-image         # build the kathara/cps node image (pandapower + pymodbus)
make cps-lab    CPS_OUT=output/cps/normal SEED=1                        # normal operation only
make cps-attack CPS_OUT=output/cps/hijack CPS_ATTACK_MODE=manual-hijack SEED=1
make cps-metrics CPS_OUT=output/cps/hijack  # per-detector detection, impact, energy
```

`make cps-selftest` needs no Docker: it runs the pandapower twin, a real Modbus
round-trip, the PLC decision logic, both detectors off-wire, and the
exploit→pivot→write chain end to end against a live engine + PLC on the host.
Knobs: `CPS_NORMAL` (normal phase, default 60 s), `CPS_LEARN` (model calibration,
default 45 s — must end ≥ 5 s before the attack), `CPS_POST` (post-attack observation,
30 s), `CPS_DETECTORS` (`rules,model`). `cps-metrics` reports, per detector
(rules / model / combined), detection, latency from the attack start and from the
first malicious write, whether it fired before the physical impact, and false alarms
(and how many fell inside legitimate operator windows); and, on the plant,
time-to-impact, impact duration, whether it persists after the attack / recovered,
and time spent in MANUAL. `DASHBOARD_PORT=8090` serves the live findings dashboard
off the sensor's mgmt NIC.

### Campaigns and the progress dashboard

```bash
make cps-campaign CPS_CAMPAIGN=c1 CPS_SEEDS=1-5      # 4 modes x 5 seeds = 20 runs (~30 min)
make cps-campaign CPS_CAMPAIGN=c1 CPS_SEEDS=1-5 DRY=1   # print the grid and the planned time
make cps-dashboard                                    # http://127.0.0.1:8765 (CPS_DASH_PORT)
```

`cps-campaign` (`network_scenario/cps_campaign.py`) runs `CPS_MODES` (default
`normal,setpoint-overvoltage,breaker-open,manual-hijack`) x `CPS_SEEDS`, seed-major, one
lab at a time, under `output/cps/campaigns/<name>/`: each run in `runs/<mode>-s<seed>/`
is scored as it finishes (`metrics.json`/`metrics.md`) and the aggregate is refreshed
(`summary.md`, `summary.csv` per mode x detector, `impact.csv` per mode). Re-running the
same `CPS_CAMPAIGN` resumes it (scored runs are skipped); a failed run is retried once,
then recorded and skipped; Ctrl-C undeploys the lab and marks the campaign interrupted.

Everything is written to a progress ledger, `progress.jsonl` (`monitor/progress.py`; a
standalone `make cps-lab`/`cps-attack` writes one in its `CPS_OUT` too): phases, the
live plant state and the sensor's findings pulled from the containers every ~2 s, the
attacker's writes, each run's metrics and the aggregate. `cps-dashboard`
(`monitor/cps_dashboard.py`, stdlib, read-only, 127.0.0.1) follows every ledger under
`output/cps`: campaign progress and ETA, the queue with per-run detection latencies and
impact, the current run's phase timeline, live bus voltages with the attack and the
first finding of each detector marked, findings by class, and the aggregated results.
It can be started before, during or after a campaign.

For the selected run, a **Topology · knowledge graph · attack tree** card draws three
views in SVG with no libraries (`monitor/cps_graph.js`). It reads the run's `kg.json` /
`tree.json` via `GET /api/structure?id=&run=`; every run writes both files. For runs that
predate them, the structure is rebuilt from today's lab model and the card says so.
- **Topology:** zones as columns, with the firewall and the sensor on their zone
  boundaries; the sensor's passive tap is dashed. It also shows addresses, services and
  the boundary allow rule.
- **Knowledge graph:** all typed nodes in layers, with edges coloured by relation.
  Hovering a node shows its attributes.
- **Attack tree:** the state of each node (suspected / confirmed / inferred), with the
  countermeasures that prevent (⊘) or restore (↺) it.

With the responder on, the response state is overlaid on all three views:
- implicated hosts;
- blocked flow and attacker-write count;
- restored / isolated hosts;
- active impacts;
- applied countermeasures.

A time slider replays the state event by event, and the decisions are listed with their
justification. `?view=topology|kg|tree&run=<run_id>` opens a view directly.

### Response (SOAR prototype)

A first end-to-end data → detection → response loop on top of the sensor
(`defense_plane/soar/`, host-side; runtime in `network_scenario/cps_responder.py`).
It is off by default (`CPS_RESPOND=off`), which leaves the scenario unchanged.

- **Knowledge graph** (`soar/kg.py`, networkx). It is built from the Kathará Lab model:
  hosts, zones and the `addresses` meta that `build_lab` sets on each machine, plus
  services, the plant's registers and role permissions (`ot_registers.ROLE_POLICY`) and
  the boundary FORWARD rules. `reachable(g, src, dst, port)` decides whether a host can
  reach a port on another from zones, addresses and rules.
- **Attack tree** (`soar/trees.py`). A template of the CPS chain, grounded on the graph:
  - steps: access to the HMI's web app (T1190) → execution on the HMI (T1059) → the
    sanctioned HMI→plant flow → one of three impacts: setpoint out of range (T0855),
    breaker open (T0855) or MANUAL hijack (T0831);
  - preconditions are checked on the graph, so removing the allow rule makes the
    branch infeasible;
  - the ATT&CK mapping still has open review notes.
- **Countermeasures**, the defense tree. Each one *prevents* or *restores* tree nodes:
  - `block_flow`: an iptables DROP inserted at the top of FORWARD on the firewall;
  - `isolate_hmi`: link down on the HMI; needs operator approval;
  - `force_auto`: back to AUTO plus the nominal setpoint;
  - `restore_breaker`: re-close the breaker;
  - `force_auto` and `restore_breaker` are local Modbus writes on 127.0.0.1 inside the
    engine container, so the sensor does not see them and the plant contract is
    unchanged.
- **Mapping** (`soar/mapping.py`). Findings become weighted evidence on tree nodes:
  - command-level evidence (a wrong write) is kept apart from consequence evidence
    (the voltage left the band);
  - once a leaf is confirmed by a wrong write, voltage-derived evidence for the other
    leaves is discounted. An open breaker also makes the operator's routine dispatch
    "unsafe", and that is not a hijack;
  - the unobservable IT steps are *inferred* from an observed OT step;
  - `CampaignState.snapshot()` is the belief handed to the policy.
- **Policies** (`soar/policy.py`):
  - `rules` is the static playbook and the baseline: confirmed leaf → fixed
    countermeasures, each fired once;
  - `solver` picks the countermeasure subset that minimises expected loss plus weighted
    operational, time and energy cost, by exhaustive enumeration over at most 32
    subsets, and also returns the Pareto front;
  - every decision carries its justification: the covered tree nodes and the cost terms.

```bash
make cps-attack CPS_OUT=output/cps/resp CPS_ATTACK_MODE=manual-hijack CPS_RESPOND=rules SEED=1
make cps-metrics CPS_OUT=output/cps/resp                 # adds a "Response" section
make cps-replay CPS_OUT=output/cps/v2b-manual-hijack CPS_RESPOND=solver   # offline, no lab
make cps-campaign CPS_CAMPAIGN=c-solver CPS_RESPOND=solver   # one policy per campaign
```

`CPS_APPROVAL` controls countermeasures that need an operator: `auto`, `deny` (never
proposed) or `delay:<s>` (simulated operator latency).

The responder writes these files to the run directory:
- `response.jsonl`, with kinds `response_up`, `tree_state`, `decision`, `approval` and
  `action` (with per-command return codes);
- `kg.json` and `tree.json`.

`cps-metrics` then reports:
- MTM: first malicious write → plant back in band for good;
- decision latency;
- accuracy against the countermeasures each mode needs, plus over-response;
- attacker writes that still succeeded after the block;
- false responses;
- explained-decision coverage;
- seconds the operator HMI was cut off.
