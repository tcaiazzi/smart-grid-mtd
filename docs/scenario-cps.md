# The cyber-physical scenario (OT/Modbus)

## 1. What it is for

This scenario emulates a small electrical distribution plant and reproduces, in
an isolated and repeatable environment, a complete attack chain that starts on
the IT network and ends in a physical effect:

> IT intrusion → pivot into OT → unauthorized Modbus write → physical effect →
> detection

The question it is built to answer: can a passive defensive sensor recognise the
attack, ideally **before** the physical effect appears, and what does the plant
suffer when it does not?

It is independent of the MQTT/MTD scenario. It has its own node images
(`kathara/cps` for the nodes, `kathara/soc` for the SOC) and its own Kathará
lab (`cps`), and the two never interfere.

## 2. Architecture

Two process zones separated by an IT/OT boundary firewall, plus a management
network for the security tooling:

```
        IT ZONE                  FIREWALL                OT ZONE
     10.10.0.0/24             10.10.0.1 |            10.20.0.0/24
  ┌──────────────────┐        10.20.0.1       ┌──────────────────────┐
  │ attacker  .0.10  │     ┌─────────────┐    │ plc        10.20.0.10│
  │ hmi       .0.20  │────▶│ FORWARD:    │───▶│ engine     10.20.0.20│
  │  (+ vulnerable   │     │ DROP except │    │  (digital twin +     │
  │   diagnostics)   │     │ HMI→engine  │    │   Modbus server)     │
  └────────┬─────────┘     │ Modbus/TCP  │    └──────────┬───────────┘
           │ eth1          └──────┬──────┘               │ passive tap
           │ 10.30.0.30           │ eth2 10.30.0.1       ▼ sensor eth1 10.30.0.10
  ─────────┴──────────────────────┴──────────────────────┴──────────────
        MGMT 10.30.0.0/24                       soc 10.30.0.20
```

- **IT zone**: the operator's HMI/SCADA workstation and the attacker.
- **OT zone**: the PLC and the physical engine — the plant's digital twin,
  exposed over Modbus/TCP. The sensor listens here on a passive interface with
  no address, without transmitting.
- **Management network (MGMT)**: the in-band network of the security tooling.
  On it sit the hosts that report findings or enforce countermeasures (sensor,
  HMI, firewall) and the SOC node. The firewall forwards nothing to or from it.
  The **HMI is dual-homed**, so it is the one way in: an attacker who
  compromises the HMI is on the management network. The engine and the PLC are
  not on it — a host sharing a network with the engine could write to it
  without crossing the boundary.
- **Boundary firewall**: drops all IT→OT traffic except one authorised flow,
  HMI to engine over Modbus. The attacker therefore cannot reach the plant
  directly: it must compromise the HMI first and use it as a springboard, which
  is what makes its writes arrive **from a legitimate host**.

Two channels must not be confused:

| | Management network | Instrumentation |
|---|---|---|
| What it is | a lab network, `10.30.0.0/24` | the container runtime (`docker exec`, file copy-out) and, for the sensor's live page, a bridged NIC |
| Who uses it | scenario nodes | the experiment: ledger, progress dashboard, artifacts, ground truth |
| In the knowledge graph | yes (`zone:MGMT`) | no — it is not a lab interface, so no node can see or reach it |

The sensor's live page is instrumentation: an `INPUT` rule on the sensor drops
it on the MGMT interface, so it is reachable through the bridged NIC only.

What travels on the management network, when a response runs
(`CPS_RESPOND` other than `off`), is **Wazuh** traffic:

- the `soc` node runs the Wazuh **manager** (image `kathara/soc`);
- sensor, HMI and firewall each run a Wazuh **agent**, registered with a
  pre-shared key so that it reports as soon as the manager listens (about 8 s
  after the services start);
- the sensor's agent ships every finding to the manager, which turns it into an
  alert (`soc.alerts.json` in the run directory; median 0.5 s after the finding);
- a countermeasure reaches its host as a Wazuh **active response**: the manager
  asks the agent for it by id, and the agent runs the commands that id maps to
  in an allowlist provisioned on that host — a request never carries a command.

The engine and the PLC run no agent: the plant is watched from the wire and
acted on from the firewall. The configuration and scripts behind all this are
node software, under `nodes/wazuh/` (see [structure.md](structure.md)).

The manager's REST API listens on the management network with the product's
default credentials. An attacker on the HMI can therefore ask the manager for
any allowlisted response on any agent. That is the exposure this network
models; the attack tree does not walk it yet (§11).

The decision runs inside the lab too. The `soc` node runs an **analytics**
service (`nodes/soc/soc_analytics.py`) next to the manager: it reads the
manager's alerts, keeps the attack tree's belief and asks the manager for the
responses — so detection, decision and enforcement are all in the lab, and the
host only starts, observes and scores. The analytics builds its own knowledge
graph from an **inventory** the scenario hands it (what a SOC is configured with
about the network it watches); the host provisions it, it does not decide.

The management plane runs in **every** episode, so a detection-only run carries
the same load and is comparable. `CPS_RESPOND` sets the analytics' policy:
`off` watches and requests nothing, `rules`/`solver` act. Each action in
`response.jsonl` carries, besides the host clock, the manager's `alert_t` and
the `node_started_t`/`node_done_t` the enforcing host recorded, so the latency
of each leg — finding to alert, alert to request, request to effect — is
measurable.

## 3. The physical process

A low-voltage (0.4 kV) distribution feeder, modelled in **pandapower** as a real
power-flow computation. Voltages and loadings are not scripted — they are
computed.

```
external grid ──feeder line (breaker)── load bus ──line── generator bus
   (slack)                               (~50 kW)          (DG, 60 kW rated)
```

- A **load** of about 50 kW, with a seeded random variation.
- A **distributed generator (DG)** rated 60 kW, delivering about 20 kW normally.
- Two **actuators**: the DG power setpoint and the feeder breaker, plus a
  **control mode** register (AUTO/MANUAL).
- A **normal state** defined as bus voltages within 0.95–1.05 pu and line
  loading at or below 100%.

The feeder is deliberately sized so that even a *legal* command — the DG at
100% of its rating — causes an overvoltage. That is what makes the scenario
interesting: a command can be formally valid and still dangerous.

## 4. The components

| Component | Role | Zone |
|---|---|---|
| **Physical engine** (`planes/traffic/agents/grid_sim.py` + `modbus_engine.py`) | pandapower digital twin behind a Modbus/TCP server. Measurements (voltages, loadings, powers, anomaly flags) are input registers; actuators are holding registers. | OT |
| **PLC** (`planes/traffic/agents/plc_controller.py`) | The Modbus master and the only legitimate regulator. In AUTO it holds the worst bus voltage in band, rejects out-of-envelope setpoints and relaxes back to the 20 kW nominal. In MANUAL it hands authority to the operator. | OT |
| **HMI / SCADA** (`planes/traffic/agents/hmi_client.py`) | The legitimate IT client: one persistent session polling the plant, and every ~12 s a safe operator dispatch (MANUAL, 15–35 kW for 5 s, back to AUTO). This is the normal behaviour the sensor must tell the attack apart from. | IT |
| **Vulnerable diagnostics app** (`planes/attack/agents/vuln_app.py`) | A small web app on the HMI host with a real OS command injection, giving the attacker remote code execution. Deliberately insecure, confined to the lab. | IT |
| **Attacker** (`planes/attack/agents/exploit_client.py`, `ot_write.py`; driver `planes/attack/active_attack.py`) | Exploits the app, gains RCE on the HMI, and from there writes Modbus to the engine. | IT |
| **Modbus DPI sensor** (`planes/defense/agents/ot_sensor.py`, `ot_model.py`) | Passively parses Modbus requests and responses, reconstructs the plant state, and emits findings and alerts. | Defence |

Every node shares one **plant contract**
(`cyberrange/planes/defense/ot_registers.py`): the register map, the scales, the
valid command envelopes, the per-role access policy, and the operating bands.

## 5. The attack modes

The opening is the same in every mode: exploit the diagnostics app, execute code
on the HMI, pivot through the firewall using the HMI's address. What differs is
the action on the plant (`CPS_ATTACK_MODE`):

| Mode | Action | Physical effect | Detection difficulty |
|---|---|---|---|
| `setpoint-overvoltage` | DG setpoint outside the envelope (200 kW) | Overvoltage at the DG bus and line overload. The PLC rejects the value and the plant recovers. | Low: the command is plainly out of range |
| `breaker-open` | Opens the feeder breaker, which by policy no one may command remotely | The downstream section loses supply and the impact persists | Low: a role-policy violation |
| `manual-hijack` | Takes MANUAL authority and dispatches 60 kW, within the DG's limits | Persistent overvoltage: the PLC has stood down, so the effect outlives the attacker | **High**: every value is legal and the source is the HMI, so source and range rules cannot see it |

Every attacker write is recorded with the instant it was issued (*ground
truth*), and the detection metrics are computed against it.

## 6. Detection

The sensor uses only the standard library and numpy. It decodes
Ethernet/IP/TCP/Modbus frames by hand and pairs each request with its response,
so it knows both the commands issued and the observed plant state. Two detectors
run in parallel, and every finding says which one produced it.

**Rules:**

- out-of-range command;
- unknown client, reading or writing;
- role-policy violation — a write to the breaker, for instance;
- *unsafe command*: a sensitive write followed by the observed voltage leaving
  the normal band;
- *manual mode excursion*: the plant in MANUAL while out of band.

**Behavioural model:**

- computes per-second features, among them session turnover, setpoint jump
  size, time in MANUAL and observed voltages;
- scores them with a robust model (median/MAD) calibrated online over the first
  seconds of the normal phase;
- evaluates the current window immediately on every write, so it can flag an
  anomaly before the physical effect appears.

Alerts are raised once and closed when the condition ends. Findings and alerts
travel on the same telemetry bus and dashboard the MTD scenario uses.

## 7. Running an experiment

Every run follows the same sequence of phases:

1. **deploy** — bring up the lab and configure the firewall;
2. **services** — start the engine, the PLC, the HMI, the vulnerable app and
   the sensor;
3. **normal** — normal operation, 60 s by default; the behavioural model
   calibrates during the first 45 s;
4. **attack** — run the attack chain in the chosen mode (absent in
   normal-operation runs);
5. **post_attack** — watch the plant after the attack, 30 s by default;
6. **download / undeploy** — collect the logs (frames, findings, ground truth)
   and tear the lab down.

A run takes about a minute in normal mode and about a minute and a half with an
attack.

```bash
make cps-selftest      # physics, Modbus, PLC, both detectors, attack chain — NO Kathará
make cps-image         # build kathara/cps (nodes + Wazuh agent) and kathara/soc (Wazuh manager)
make cps-lab    CPS_OUT=output/cps/normal SEED=1                        # normal operation only
make cps-attack CPS_OUT=output/cps/hijack CPS_ATTACK_MODE=manual-hijack SEED=1
make cps-metrics CPS_OUT=output/cps/hijack   # per-detector detection, impact, energy
```

`make cps-selftest` needs no Docker: it runs the pandapower twin, a real Modbus
round trip, the PLC decision logic, both detectors off-wire, and the
exploit → pivot → write chain end to end against a live engine and PLC on the
host.

| Knob | Default | Meaning |
|---|---|---|
| `CPS_NORMAL` | 60 s | length of the normal phase |
| `CPS_LEARN` | 45 s | model calibration; **must end ≥ 5 s before the attack** |
| `CPS_POST` | 30 s | post-attack observation |
| `CPS_DETECTORS` | `rules,model` | which detectors run |
| `DASHBOARD_PORT` | unset (off) | host port of the live findings dashboard off the sensor's mgmt NIC, e.g. 8090 |

Every option of the run (`python -m cyberrange.scenarios.cps.cli --help`) is also
accepted by a campaign and applies to all of its runs.

## 8. Campaigns and the progress dashboard

```bash
make cps-campaign CPS_CAMPAIGN=c1 CPS_SEEDS=1-5           # 4 modes x 5 seeds = 20 runs (~30 min)
make cps-campaign CPS_CAMPAIGN=c1 CPS_SEEDS=1-5 DRY=1     # print the grid and the planned time
make cps-campaign CPS_CAMPAIGN=p1 CPS_RESPOND=solver CPS_IT=1 CPS_ATTACK_DRIVER=planner
make dashboard                                            # http://127.0.0.1:8765, every scenario
```

`cps-campaign` (`cyberrange/scenarios/cps/campaign.py`) runs `CPS_MODES`
(default `normal,setpoint-overvoltage,breaker-open,manual-hijack`) × `CPS_SEEDS`,
seed-major, one lab at a time, under `output/campaigns/<name>/` — where every
scenario's campaigns live. Each run in
`runs/<mode>-s<seed>/` is scored as it finishes (`metrics.json`, `metrics.md`)
and the aggregate is refreshed (`summary.md`, `summary.csv` per mode × detector,
`impact.csv` per mode, `ci.csv` with every metric's mean [95% CI] per mode).

Re-running the same `CPS_CAMPAIGN` **resumes** it: scored runs are skipped, a
failed run is retried once and then recorded and skipped, and Ctrl-C undeploys
the lab and marks the campaign interrupted.

Everything goes onto a progress ledger, `progress.jsonl` (a standalone
`make cps-lab`/`cps-attack` writes one into its `CPS_OUT` too): phases, the live
plant state and the sensor's findings pulled from the containers every ~2 s, the
attacker's writes, each run's metrics and the aggregate. `make dashboard` reads
every ledger under `output/`; `make cps-dashboard` is the same dashboard with
`--scenario cps`, which filters on what each run recorded rather than on where
it was written. It can be
started before, during or after a campaign.

For the selected run, a **Topology · knowledge graph · attack tree** card draws
three views in SVG with no libraries (`cyberrange/scenarios/cps/panel.js`),
reading the run's `kg.json` / `tree.json` through
`GET /api/structure?id=&run=`. Every run writes both files; for runs that predate
them the structure is rebuilt from today's lab model and the card says so.

- **Topology**: zones as columns, firewall and sensor on the boundary of two
  neighbouring zones, the sensor's passive tap dashed, with addresses, services
  and the boundary allow rule. A host's presence on a zone further away (the
  HMI on MGMT) shows in its address list, not as a link.
- **Knowledge graph**: all typed nodes in layers, edges coloured by relation;
  hovering a node shows its attributes.
- **Attack tree**: each node's state (suspected / confirmed / inferred) with the
  countermeasures that prevent (⊘) or restore (↺) it.

With the responder on, the response state is overlaid on all three: implicated
hosts, blocked flow and attacker-write count, restored or isolated hosts, active
impacts, applied countermeasures. A time slider replays the state event by event
and lists the decisions with their justification.
`?view=topology|kg|tree&run=<run_id>` opens a view directly.

## 9. What is measured

**On detection**, per detector (rules, model, combined):

- detection rate;
- latency from the attack start and from the first malicious write;
- whether it fired before the physical impact;
- false alarms, and how many fell inside legitimate operator windows.

**On the plant:**

- time to impact and impact duration;
- maximum voltage deviation;
- whether the impact persists after the attack or the plant recovers;
- time spent in MANUAL;
- energy.

Single seeded verification runs give indicative results: the loud attacks are
detected within hundredths of a second of the first write; in `manual-hijack`
the behavioural model flags the attack before the impact while the rules only
notice once the impact has happened; and normal operation produced no false
alarms. A statistical evaluation across seeds is what campaigns are for.

## 10. Response (the SOAR prototype)

A full end-to-end data → detection → decision → response loop, all inside the
lab (§2). The reasoning — knowledge graph, attack tree, mapping, policy — is
software of the SOC node (`nodes/soc/`, stdlib + networkx), run by the analytics
service there and, offline, by the host through `soc_tool` (a subprocess, no
import) for the dashboard's structure and for replay. `CPS_RESPOND` sets the
policy; `off` watches without acting. `make cps-replay` shows what a policy
would have decided on a finished run's findings.

How the knowledge graph and the attack tree are built, turned into a belief
and used by both sides is in [kg-and-attack-trees.md](kg-and-attack-trees.md).

- **Knowledge graph** (`soar/kg.py`, networkx), built from the Kathará Lab
  model: hosts, zones and the `addresses` meta that `core.topology.build_lab`
  sets on every machine, plus services, the plant's registers, role permissions
  (`ot_registers.ROLE_POLICY`) and the boundary FORWARD rules.
  `reachable(g, src, dst, port)` decides whether a host can reach a port on
  another from zones, addresses and rules. The CPS binding lives in
  `cyberrange/scenarios/cps/inventory.py` — the node software itself knows no scenario.
- **Attack tree** (`soar/trees.py`), a template of the chain grounded on the
  graph: access to the HMI's web app (T1190) → execution on the HMI (T1059) →
  the sanctioned HMI→plant flow → one of three impacts: setpoint out of range
  (T0855), breaker open (T0855), MANUAL hijack (T0831). Preconditions are
  checked on the graph, so removing the allow rule makes a branch infeasible.
  The ATT&CK mapping still has open review notes.
- **Countermeasures**, the defence tree; each one *prevents* or *restores* tree
  nodes:
  - `block_flow` — an iptables DROP at the top of FORWARD on the firewall;
  - `isolate_hmi` — link down on the HMI; needs operator approval;
  - `force_auto` — back to AUTO plus the nominal setpoint;
  - `restore_breaker` — re-close the breaker.

  `force_auto` and `restore_breaker` are Modbus writes from the firewall to the
  engine over the OT link. The plant contract gives that writer its own role,
  `responder`; the sensor records its writes as `ot_response_write` (when the
  plant actually received the response) and raises no finding for them. The
  role is bound to the firewall's OT address, so a compromised firewall is a
  blind spot of the sensor.
- **Mapping** (`soar/mapping.py`): findings become weighted evidence on tree
  nodes. Command-level evidence (a wrong write) is kept apart from consequence
  evidence (the voltage left the band); once a leaf is confirmed by a wrong
  write, voltage-derived evidence for the other leaves is discounted; an open
  breaker also makes the operator's routine dispatch "unsafe", which is not a
  hijack; the unobservable IT steps are *inferred* from an observed OT step.
  `CampaignState.snapshot()` is the belief handed to the policy.
- **Policies** (`soar/policy.py`): `rules` is the static playbook and the
  baseline — confirmed leaf → fixed countermeasures, each fired once. `solver`
  picks the countermeasure subset minimising expected loss plus weighted
  operational, time and energy cost, by exhaustive enumeration over at most 32
  subsets (128 with the IT countermeasures), and returns the Pareto front too. Every decision carries its
  justification: the tree nodes covered and the cost terms.

```bash
make cps-attack CPS_OUT=output/cps/resp CPS_ATTACK_MODE=manual-hijack CPS_RESPOND=rules SEED=1
make cps-metrics CPS_OUT=output/cps/resp                                  # adds a "Response" section
make cps-replay  CPS_OUT=output/cps/v2b-manual-hijack CPS_RESPOND=solver  # offline, no lab
make cps-campaign CPS_CAMPAIGN=c-solver CPS_RESPOND=solver                # one policy per campaign
```

`CPS_APPROVAL` controls countermeasures that need an operator: `auto`, `deny`
(never proposed) or `delay:<s>` (simulated operator latency).

### Tree-guided attacker

By default the attack is a fixed per-mode chain. `CPS_ATTACK_DRIVER=planner`
runs a **reactive attacker** (`cyberrange/planes/attack/planner/`) that walks the
same attack tree and picks its next step from the current state, composing the
*same* lab primitives the scripted chain uses — no new offensive capability,
lab-only. It learns by outcome: if a step fails because a countermeasure closed
its path, it tries another feasible impact or gives up, so it exercises the
response like a real adversary. It is also the baseline adversary of the WP3
stochastic game.

```bash
make cps-attack CPS_OUT=output/cps/plan CPS_ATTACK_DRIVER=planner \
    CPS_PROFILE=stealthy CPS_DWELL=3 CPS_RESPOND=rules SEED=1
```

- `CPS_PROFILE`: `opportunistic` (biggest reachable impact), `targeted` (with
  `CPS_GOAL`), `stealthy` (quietest impact, longer dwell).
- `CPS_DWELL`: seconds between steps — the window the defender gets. It pays off
  once IT-side telemetry makes the early steps observable.

Each step is recorded as a `plan_step` in the ground truth, and `cps-metrics`
reports the furthest **stage reached** (access / exec / pivot / impact), whether
the attack **succeeded**, and whether it was **prevented** (no write landed).

### IT-side telemetry: responding before the plant is touched

The OT sensor sees only Modbus, so the attacker's first steps can only be
*inferred* and the defence can act only once a write reaches the plant.
`CPS_IT=1` adds an **IT-side sensor on the HMI**
(`cyberrange/planes/defense/agents/it_sensor.py`, stdlib) that makes those steps
*observed*:

- the diagnostics app's access log → `web_injection_pattern` (it_access);
- the process table (`/proc`) → `web_child_process` (it_exec);
- open connections (`/proc/net/tcp`) → `unexpected_modbus_client` (pivot).

What is normal — the operator's legitimate diagnostic traffic, the real Modbus
client — is learned during the first `CPS_LEARN` seconds, like the OT model. The
IT sensor also turns on legitimate periodic diagnostics on the HMI and the app's
access log. Its findings carry the `ot_finding` shape (`detector="it"`), so the
same mapping and responder consume them: the early steps become *confirmed*, and
two IT countermeasures become available — `kill_proc_tree` (end the RCE) and
`block_web_src` (block the attacking source). With the IT sensor, a confirmed
early step triggers an early response (rules: `it_exec` → `kill_proc_tree` +
`block_flow`; `it_access` → `block_web_src`).

```bash
make cps-attack CPS_OUT=output/cps/it CPS_ATTACK_DRIVER=planner CPS_DWELL=3 \
    CPS_IT=1 CPS_RESPOND=rules SEED=1
```

With a dwell, this stops the attack *before* the plant is touched: in a seed-1
run the same opportunistic attack reaches the plant with the OT sensor alone
(`stage_reached=impact`) but is stopped at `it_access` with the IT sensor
(`prevented`, no write). `cps-metrics` adds an `it` detection row and a
`prevented before the plant was touched` line.

The responder writes to the run directory `response.jsonl` — kinds
`response_up`, `tree_state`, `decision`, `approval` and `action` (with
per-command return codes) — plus `kg.json` and `tree.json`. `cps-metrics` then
reports: MTM (first malicious write → plant back in band for good), decision
latency, accuracy against the countermeasures each mode needs plus
over-response, attacker writes that still succeeded after the block, false
responses, explained-decision coverage, and the seconds the operator HMI was cut
off.

## 11. Scope and what is next

The scenario covers phases 1–4 of the prototype: foundations, OT emulation, the
IT/OT boundary, and detection. The response loop above sits on top of them as a
deliberately small prototype, meant to fix the interfaces of WP2 and WP3 (see
[piano-wp2-wp3.md](piano-wp2-wp3.md)). Still to do:

- automatic generation of the attack trees;
- the stochastic game model;
- real energy measurement of the countermeasures;
- the management network in the attack tree (reaching the manager's API from
  the HMI, with its default credentials) and a step of the planner that walks it;
- relocating the guest agents under `cyberrange/planes/*/agents/` to `nodes/`.

## 12. Quick reference

| What | Where |
|---|---|
| Plant contract (registers, policy, bands) | `cyberrange/planes/defense/ot_registers.py` |
| Digital twin and Modbus server | `cyberrange/planes/traffic/agents/grid_sim.py`, `modbus_engine.py` |
| PLC and HMI | `cyberrange/planes/traffic/agents/plc_controller.py`, `hmi_client.py` |
| Attack chain | `cyberrange/planes/attack/agents/`, `cyberrange/planes/attack/active_attack.py` |
| Sensor and model | `cyberrange/planes/defense/agents/ot_sensor.py`, `ot_model.py` |
| SOAR: graph, tree, mapping, policies | `nodes/soc/soar_*.py` (node software), bound to this lab by `cyberrange/scenarios/cps/inventory.py` |
| Lab and orchestration | `cyberrange/scenarios/cps/` (topology, episode) on `cyberrange/core/`; CLI `cli.py`, campaigns `campaign.py` |
| Metrics and dashboard panel | `cyberrange/scenarios/cps/metrics.py`, `panel.js`; the dashboard itself is `cyberrange/core/dashboard.py` |
| The platform underneath | [platform.md](platform.md), [structure.md](structure.md) |
