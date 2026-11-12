# Components reference

Components are the building blocks a scenario is composed of. Each plane
exposes its components in `cyberrange/planes/<plane>/components.py`. A scenario's episode
configures them and starts them; the platform core then stops them, downloads
their files and mirrors their telemetry onto the progress ledger.

This page lists every component available today. For how the core runs a
scenario, see [platform.md](platform.md).

- [1. How a component works](#1-how-a-component-works)
- [2. Catalogue](#2-catalogue)
- [3. Traffic plane](#3-traffic-plane-cyberrangeplanestrafficcomponentspy)
- [4. Attack plane](#4-attack-plane-cyberrangeplanesattackcomponentspy)
- [5. Defense plane](#5-defense-plane-cyberrangeplanesdefensecomponentspy)
- [6. Monitor plane](#6-monitor-plane-monitorcomponentspy)
- [7. Composition recipes](#7-composition-recipes)
- [8. Writing a new component](#8-writing-a-new-component)

---

## 1. How a component works

A component subclasses `cyberrange.core.component.Component` and may
override any of these hooks:

| Hook | When it is called | What it does |
|---|---|---|
| `start(ctx)` | `ctx.start(c)` in the episode | Launches the component: guest processes through `ctx.exec`, or a host thread. `ctx.start` also registers it. |
| `stop(ctx)` | By the core when the episode ends, in reverse start order | Stops host-side work (threads). Guest processes die with the lab. |
| `artifacts()` | By the core in the `download` phase | Returns `[Artifact(node, guest_path, local_name, required)]`, the files to copy into the run directory. A missing `required` file fails the run; any other missing file is only logged. |
| `telemetry()` | By readers of guest telemetry (`TelemetryMirror`) | Returns `[TelemetrySource(node, path, name)]`, the guest JSONL telemetry files the component writes. |
| `mirror(ev)` | By `TelemetryMirror`, for each new telemetry event | Returns `(kind, fields)` to emit on the ledger, or `None` to skip the event. |
| `poll(ctx)` | By `ctx.observe(...)` / `ctx.live()` every `--poll-interval` seconds | Pulls live state onto the ledger. It must not raise; the core catches and logs errors anyway. |

Components that act at one moment of the episode (an attack, sniffing,
scoring) expose their own blocking method, such as `attack(ctx)` or
`sniff(ctx, s)`. The scenario calls it inside the right phase.

### Base classes and data types

| Name | Purpose |
|---|---|
| `Component` | Base class: every hook is a no-op. `plane` and `name` label it. |
| `GuestAgent(node, command, console_log, plane=, name=, artifacts=(), wait=False)` | One process in one container. `start` runs `command` on `node` with stdout and stderr captured to the guest file `/<console_log>`. That file is always an artifact, saved as `<node>.<console_log>`; extra artifacts can be added. |
| `Artifact(node, guest_path, local_name, required=False)` | A file to download after the episode. |
| `TelemetrySource(node, path, name)` | A guest telemetry file. `name` is a label (`"ot"`, `"it"`, `"mtd"`) that consumers filter on. |
| `TelemetryCursor(read)` | Reads a growing JSONL file incrementally. It consumes complete lines only, so a partial last line is read again on the next pull, and an unparseable line is skipped. |
| `tail_reader(exec_text, node, path)` | A `read` function for `TelemetryCursor`, built on `tail -n +N` inside the guest. |

### Using components in an episode

```python
def episode(self, ctx):
    with ctx.phase("services"):
        ctx.start(defense.OtSensor("sensor", "eth0", ENGINE_IP, 5020, PLC_IP, HMI_IP,
                                   "rules,model", 45))
        ctx.start(traffic.PhysicalProcess("engine", 5020, 1.0, seed=ctx.role_seed("engine")))
    ctx.start(monitor.TelemetryMirror())          # live findings on the ledger
    with ctx.phase("normal"):
        ctx.observe(60)                           # polls the started components
    driver = ctx.start(attack.ScriptedChain("manual-hijack", url, ENGINE_IP, 5020))
    with ctx.phase("attack", mode=driver.label):
        driver.attack(ctx)
```

You never stop components or download their files yourself; the core does
both.

**Seeds.** Pass `ctx.role_seed("<role>")` to every component that takes a
`seed`. Each role then gets its own reproducible random stream, derived from
the run's `--seed` (unseeded when the run is).

---

## 2. Catalogue

| Component | Plane | Runs | Node / image | Used by |
|---|---|---|---|---|
| `PhysicalProcess` | traffic | guest | engine · `kathara/cps` | cps |
| `PlcController` | traffic | guest | plc · `kathara/cps` | cps |
| `HmiClient` | traffic | guest | hmi · `kathara/cps` | cps |
| `BackgroundReplay` | traffic | guest | router · `kathara/mqtt` | mqtt-mtd |
| `ScmcPublisher` | traffic | guest | scmc · `kathara/mqtt` | mqtt-mtd |
| `VulnApp` | attack | guest | hmi · `kathara/cps` | cps |
| `ScriptedChain` | attack | host → guest | attacker · `kathara/cps` | cps |
| `PlannedAttacker` | attack | host → guest | attacker · `kathara/cps` | cps |
| `PassiveFingerprinter` | attack | guest + host | attacker · any image with tcpdump | mqtt-mtd |
| `DeliveryAttack` | attack | host → guest | router, scmc · `kathara/mqtt` | mqtt-mtd |
| `OtSensor` | defense | guest | sensor · `kathara/cps` | cps |
| `ItSensor` | defense | guest | hmi · `kathara/cps` | cps (`--it-telemetry`) |
| `SocAnalytics` | defense | guest | soc · `kathara/soc` | cps (always; acts with `--respond`) |
| `WazuhManager` | defense | guest | soc · `kathara/soc` | cps (`--respond`) |
| `WazuhAgent` | defense | guest | sensor, hmi, firewall · `kathara/cps` | cps (`--respond`) |
| `QkdCertBootstrap` | defense | guest | semp, scmc · `kathara/mqtt` | mqtt-mtd |
| `MtdCoordinator` | defense | guest | semp · `kathara/mqtt` | mqtt-mtd |
| `Capture` | monitor | guest | any image with tcpdump | mqtt-mtd |
| `TelemetryMirror` | monitor | host | any | both |
| `PlantMirror` | monitor | host | engine | cps |

**Runs** says where the component's work happens:

- **guest:** a process inside a container. The guest code must be staged on that node by its deploy manifest in `cyberrange/scenarios/<name>/guest_files.py`.
- **host:** a thread on the host.
- **host → guest:** the host drives commands inside a container.

Shared helpers:

| Helper | Module | Purpose |
|---|---|---|
| `emit_attack_writes(ctx)` | `cyberrange.planes.attack.components` | Copies the attack's Modbus writes from the ground truth onto the ledger. |
| `detect_nanogrid_ip(...)`, `BLOCK_POLICIES` | `cyberrange.planes.attack.components` | The CNN fingerprinting step. |
| `generate_shared_key()` | `cyberrange.planes.defense.components` | The key that stands in for the QKD device's output. |

---

## 3. Traffic plane (`cyberrange/planes/traffic/components.py`)

The legitimate activity of the system, which attacks and defenses play
against.

### `PhysicalProcess(node, port, step_interval, seed=None, frame_log="engine_frames.jsonl")`

The plant: a pandapower low-voltage feeder (`cyberrange/planes/traffic/agents/grid_sim.py`)
stepped every `step_interval` seconds behind a Modbus/TCP server
(`modbus_engine.py`).

| | |
|---|---|
| **Starts** | `python3 modbus_engine.py --host 0.0.0.0 --port P --interval S --frame-log F [--seed N]` |
| **Register map** | Defined in `cyberrange/planes/defense/ot_registers.py`. Input registers (fc04) carry the sensors; holding registers (fc03/06/10) carry the actuators: DG setpoint (HR 0), feeder breaker (HR 1), control mode (HR 2). |
| **Artifacts** | `<node>.engine.log`; `<node>.<frame_log>` with one physical frame per step (voltages, line loading, power, energy, actuators, `abnormal`) |
| **Read live by** | `PlantMirror` (reads `frame_log`) |

Start it before its Modbus clients. The CPS scenario waits about 2 s after it.

### `PlcController(node, engine_ip, port, interval, seed=None)`

The PLC: a Modbus master closing the control loop. It reads the plant,
curtails the DG on overvoltage, rejects setpoints outside the envelope, and
hands control over while control mode is MANUAL. This is the legitimate OT
traffic.

| | |
|---|---|
| **Starts** | `python3 plc_controller.py --engine-host IP --port P --interval S [--seed N]` |
| **Artifacts** | `<node>.plc.log` |

### `HmiClient(node, engine_ip, port, seed=None, diag_url=None)`

The HMI/SCADA host: operator polling plus occasional dispatches. It is the one
IT client the boundary firewall lets reach the plant. With `diag_url` it also
makes the operator's legitimate requests to the diagnostics web app, which
gives the IT sensor a baseline of normal use.

| | |
|---|---|
| **Starts** | `python3 hmi_client.py --engine-host IP --port P [--seed N] [--diag-url URL]` |
| **Artifacts** | `<node>.hmi.log` |

### `BackgroundReplay(node, iface, mbps, duration=None)`

Replays the real background trace (staged on the router as `traccia.pcap`)
onto `iface` at `mbps` Mbit/s. This is the noise the passive attacker has to
separate the nanogrid from. With `duration=None` it runs until the lab goes
down.

| | |
|---|---|
| **Starts** | `[timeout D] bash ./replay_background.sh IFACE MBPS 0` (no console log) |
| **Artifacts** | none |

### `ScmcPublisher(node, mtd, scmc_ip_pool, shared_key=None, seed=None, console_log="client.console.log", state=None)`

The nanogrid's SCMC, publishing microgrid snapshots over MQTT with mutual TLS.

- With `mtd=False` it runs the plain publisher (`simple_client.py`, broker 10.1.0.2:8883).
- With `mtd=True` it runs the MTD executor (`mtd_executor.py`). The executor follows the coordinator's moves over the encrypted control channel: broker IP/port hops, source-IP hops across `scmc_ip_pool`, padding, publish frequency.

| | |
|---|---|
| **Starts** | the publisher command, console to `console_log` |
| **`log_file`** | `mtd_executor.log` or `simple_client.log`, the guest log the scenario downloads as `[<capture>.]client.log` |
| **`command_for(state)`** | The command that restarts the executor where the MTD left it (broker endpoint, current source IP first, interval, padding). `state` comes from `detection_scenario.executor_state`; `DeliveryAttack` uses this on executor restarts. |
| **Artifacts** | none of its own. The scenario names the logs per capture. |
| **Needs** | the client certificate from `QkdCertBootstrap` |

---

## 4. Attack plane (`cyberrange/planes/attack/components.py`)

Every attack records what it really did in the run's ground truth
(`ground_truth.jsonl`, host-only). Defenders never see this file; scorers do.

### `VulnApp(node, port, access_log=None)`

The deliberately vulnerable diagnostics web app on the HMI: a "ping" page with
a command injection. It is the attacker's foothold in the CPS scenario. With
`access_log`, every request is logged as JSON for the IT sensor.

| | |
|---|---|
| **Starts** | `python3 vuln_app.py --host 0.0.0.0 --port P [--access-log PATH]` |
| **Artifacts** | `<node>.vuln_app.log`; `<node>.<basename(access_log)>` when logging |

### `ScriptedChain(mode, target_url, engine_ip, engine_port, repeat=None, interval=0.5)`

The fixed chain of one attack mode: RCE on the web app, then a pivot from the
HMI (an allowed host), then unauthorized Modbus writes. `exploit_client.py`
runs on the attacker node.

| `mode` | Writes | Effect |
|---|---|---|
| `setpoint-overvoltage` | DG setpoint 200 kW (out of range) | Overvoltage at the DG bus; the PLC rejects the value and recovers |
| `breaker-open` | feeder breaker open | Load de-energized |
| `manual-hijack` | control mode MANUAL, then an in-range unsafe setpoint (60 kW) | Stealthy: in-envelope writes from an allowed host, with persistent impact |

| | |
|---|---|
| **Call** | `attack(ctx)`, blocking. Inside the attack phase, after `ctx.open_ground_truth(...)`. |
| **Ground truth** | `attack_start`; `rce`; one `modbus_write` per write (send time from the attacker, register, value, ok); `attack_end` |
| **Ledger** | one `attack_write` per write (`emit_attack_writes`) |
| **Artifacts** | `attacker.exploit.log` |
| **`label`** | the mode, used for the attack phase and `run_start.mode` |

### `PlannedAttacker(profile, target_url, engine_ip, engine_port, goal=None, dwell=0.0, max_steps=12, interval=0.5)`

A reactive attacker (`cyberrange/planes/attack/planner`). It walks the attack tree of the
**deployed** lab's knowledge graph and runs one step at a time
(`it_access`, `it_exec`, `pivot`, then an impact). When a countermeasure
closes its path, it tries another branch, or stops.

| `profile` | Chooses |
|---|---|
| `opportunistic` | the reachable impact with the highest impact first |
| `targeted` | only `goal` (`setpoint_oor`, `breaker_open` or `mode_hijack`; required) |
| `stealthy` | the least detectable reachable impact first |

| | |
|---|---|
| **Call** | `attack(ctx)`, blocking |
| **Options** | `dwell` = seconds between steps (the defender's window); `max_steps` = step budget |
| **Ground truth** | `attack_start` (mode `planner:<profile>`); `plan_step` per step; `rce`; `modbus_write`; `attack_end` (success, stage reached) |
| **Ledger** | `plan_step` per step; `attack_write` |
| **Artifacts** | `attacker.exploit.log` |
| **`label`** | `planner:<profile>` |

### `PassiveFingerprinter(node, iface, model, scaler, block_policy="top1", threshold=None)`

The passive attacker on the broker-side link. It sniffs, scores the capture
with its 1D-CNN (`cyberrange/planes/attack/classify.py`), ranks source IPs by how
nanogrid-like their traffic is, and picks the one to blackhole.

| | |
|---|---|
| **`sniff(ctx, seconds)`** | `timeout S tcpdump -i IFACE -w attacker_capture.pcap` on the attacker, then downloads it. Returns the local path. |
| **`score(ctx, capture)`** | Runs `detect_nanogrid_ip` and writes `nanogrid_ranking.csv`. It logs `Blocking nanogrid IP: <ip>`, a line `plot_results` reads back from `run.log`. Returns the IP, or `""`. |
| **`block_policy`** | `top1` always blocks the top-ranked IP (the workshop paper). `threshold` blocks only if its `nanogrid_frac` ≥ `threshold` (default `cyberrange.planes.attack.thresholds.DETECT_THRESHOLD`). |
| **Needs** | a model trained on this scenario's datasets (`make train`) |

### `DeliveryAttack(router, scmc, port_pool, relaunch, oracle=None, block_duration=None, block_episodes=1, impair=False)`

The attacker's active phase, plus benign faults, during post-attack
observation. It wraps the scenario's fault injector (`cyberrange/scenarios/mqtt_mtd/attacks.py`), passed in as `injector=`.

| | |
|---|---|
| **`attack(ctx, cnn_ip)`** | Starts the episodes, which run in background threads. With no `oracle` and no `block_duration`, it applies the paper's single permanent block of `cnn_ip`. |
| **`oracle`** | `src`, `broker` or `random`: blackhole the address the SCMC's MQTT path uses *right now*, read from its live socket. This is the worst-case attacker. |
| **`block_duration` / `block_episodes`** | Lift each blackhole after N s; repeat it, 20–40 s apart. |
| **`impair=True`** | Seeded benign faults on the router: netem loss, delay or burst loss, and executor restarts (through `relaunch(state, n)`, normally `ScmcPublisher.command_for`). |
| **`stop(ctx)`** | Ends the episodes, removes the faults, keeps the blackholes. Call it explicitly at the end of the post-attack window. The core also calls it. |
| **Ground truth** | `block`, `unblock`, `impair_start`, `impair_stop`, `executor_restart` (kill / relaunch). `cyberrange/scenarios/mqtt_mtd/analysis/delivery_dataset.py` turns these into detector labels. |
| **`restarts`** | how many executor restarts happened, so the scenario can download their console logs |

---

## 5. Defense plane (`cyberrange/planes/defense/components.py`)

Detection and response, both proactive (MTD) and reactive (sensors, SOAR).
Guest sensors write telemetry with `cyberrange/planes/defense/agents/mtd_telemetry.py`,
declare it as a `TelemetrySource`, and map it onto the ledger with `mirror`.

### `OtSensor(node, iface, engine_ip, engine_port, plc_ip, hmi_ip, detectors, learn_seconds, dashboard_port=None, responder_ip=None)`

Passive Modbus deep-packet inspection on the OT link. It sniffs a promiscuous
NIC with no address and reports on its management NIC. It is stdlib + numpy
only.

| | |
|---|---|
| **Starts** | `python3 ot_sensor.py --iface IFACE --engine-ip … --detectors D --learn-seconds L --telemetry-file telemetry.jsonl [--responder-ip R] [--dashboard-port P]` |
| **`detectors`** | `rules`, `model` or `rules,model`. **Rules** pair requests with responses and apply the role policy: `unauthorized_write`, `unauthorized_write_to_actuator`, `unauthorized_read`, `policy_violation`, `out_of_range_command`, `unsafe_command`, `manual_mode_excursion`. **Model** fits a median/MAD profile during the first `learn_seconds` and then reports `behavioral_anomaly`. |
| **`responder_ip`** | The address the automated response writes to the plant from (role `responder`). Its writes raise no finding and stay out of the model's features; without it the sensor reports them as an unknown writer. Pass it only when a response runs. |
| **Telemetry** | `sensor:/telemetry.jsonl`, name `ot`: `ot_finding`, `ot_alert` (raised/cleared), `model_fitted`, `model_error`, `ot_response_write` |
| **Ledger (`mirror`)** | `finding`, `alert`, `model_fitted`, `model_error`, `response_write` |
| **Artifacts** | `<node>.sensor.log`, `<node>.telemetry.jsonl` |

Start it first, so that its calibration window also covers the clients'
session setup. The attack must start after `learn_seconds`; the CPS scenario
enforces a margin of 5 s.

### `ItSensor(node, engine_ip, engine_port, access_log, learn_seconds)`

A host sensor on the HMI that makes the attacker's IT steps observable before
the plant is touched. What is "normal" is learned during `learn_seconds`.

| Source | Finding (step of the attack tree) |
|---|---|
| web app access log | `web_injection_pattern` (it_access, T1190) |
| process table | `web_child_process`, a child of the web server that is not learned-normal (it_exec, T1059) |
| `/proc/net/tcp` | `unexpected_modbus_client`, a new connection to the plant's Modbus port (pivot) |

| | |
|---|---|
| **Starts** | `python3 it_sensor.py --engine-ip … --access-log PATH --learn-seconds L --telemetry-file it_telemetry.jsonl` |
| **Telemetry** | `hmi:/it_telemetry.jsonl`, name `it`. Same `ot_finding` shape, with `detector="it"`. |
| **Ledger** | `finding`, `alert` |
| **Artifacts** | `<node>.it_sensor.log`, `<node>.it_telemetry.jsonl` |
| **Needs** | `VulnApp(access_log=…)` on the same node. Give `HmiClient` a `diag_url` too, so normal use is learned. |

### `SocAnalytics(node, inventory, policy="off", approval="auto", interval=0.5, it=False, operator_port=None, operator_token=None, operator_origins=())`

The SOC's decision, as a guest agent on the manager's node
(`nodes/soc/soc_analytics.py`). It reads the manager's alerts, folds each
finding into the attack tree's campaign state, asks the policy for a decision
and requests the chosen countermeasures from the manager as active responses on
the agents. The reasoning is the node's software (`nodes/soc/soar_*.py`), built
from `inventory` — the lab as the SOC is told it (`cps.inventory`). It runs in
every episode; `policy="off"` watches and requests nothing.

| | |
|---|---|
| **`policy`** | `off` (watch only), `rules` (a playbook per impact) or `solver` (the minimal-cost set that covers the active tree, with causal pairing) |
| **`approval`** | `auto`, `deny`, or `delay:<s>` (operator approval for high-impact countermeasures, simulated); `operator:<s>` makes the SOC an advisor: every countermeasure waits up to `<s>` for a person's verdict, then expires unapplied |
| **`operator_*`** | With `operator:<s>`: the port and bearer token of the SOC's operator API (`nodes/soc/soc_operator.py`: `GET /approvals`, `POST /approvals/<id>`), and the browser origins it answers CORS for. The scenario publishes the port (`Node.mgmt_port`) and closes it on MGMT. |
| **`it`** | Also allow the IT countermeasures. Set it when `ItSensor` runs. |
| **Countermeasures** | `notify`, `block_flow` (firewall drops HMI→plant Modbus), `isolate_hmi`, `force_auto` (the firewall writes AUTO + nominal setpoint to the plant), `restore_breaker`; with `it`: `kill_proc_tree`, `block_web_src` |
| **Writes** | `response.jsonl` (`response_up`, `tree_state`, `decision`, `approval`, `action` with per-leg times `alert_t`/`issued_t`/`node_started_t`/`node_done_t`), `kg.json`, `tree.json` on the node |
| **Ledger** | `tree_state`, `decision` (with justification), `action`, `approval` (a suggestion with its explanation, then `granted` / `rejected` / `expired`) |

Offline, the same tool runs on the host through `soc_tool` (a subprocess, no
import): `cps-replay` shows what a policy *would* have done on a finished run,
and the run's structure (`kg.json`/`tree.json`) is written this way at deploy.

### `WazuhManager(node, agents)` · `WazuhAgent(node, manager_ip, agent_id, key, responses=None, logs=())`

The management network's tooling. The software is Wazuh, installed by the node
images and configured from `nodes/wazuh/`; these components launch it and name
its artifacts, and hold no logic of their own.

| | |
|---|---|
| **`WazuhManager`** | Starts the manager on the SOC node (`bash /wazuh-manager-setup.sh ID:NAME:KEY …`). `agents` is `{name: (id, key)}`. Artifacts: `<node>.alerts.json`, `<node>.ossec.log`, `<node>.wazuh_manager.log`. |
| **`WazuhAgent`** | Starts an agent with the same pre-shared `key`, shipping the JSONL files in `logs` and allowed to run the countermeasures in `responses` (`{id: {"apply": [cmd], "revert": [cmd]}}`). The script waits for the manager's port, so start order does not matter. Artifacts: `<node>.cps-response.jsonl` (one record per response run), `<node>.ossec.log`, `<node>.wazuh_agent.log`. The `cps-response.jsonl` is what the SOC analytics reads back to close each action, and a request already recorded is not run twice. |

Timings measured in the lab: manager and agents ready about 8 s after start;
finding → manager alert 0.5 s (median); API call → response started on the
host 0.1–0.5 s.

### `QkdCertBootstrap(ca_node, client_node, shared_key, server_ips, client_ips, ca_ip="10.1.0.2", ca_port=9999, server_cn="semp", client_cn="scmc1")`

Bootstraps the mutual TLS. A certificate authority on `ca_node` is
authenticated with the QKD-simulated shared key. `client_node` fetches its
bundle from it, retrying up to 5 times because right after deploy the client
may still be unconfigured. Its `start` blocks until the client has its
certificate, and raises if it never does.

| | |
|---|---|
| **Key** | `generate_shared_key()`: a host-generated random key stands in for the QKD device's output |
| **SANs** | `server_ips` / `client_ips` must cover every address the MTD will hop to |

### `MtdCoordinator(node, shared_key, ip_pool, port_pool, pad_buckets, scmc_ip_pool, freq_pool, hop_timeout=10.0, hop_interval=2, pad_interval=3, src_hop_interval=2, freq_interval=30, rl_policy=None, rl_tick=1.0, seed=None, dashboard_port=None, detector_model=None, observe_data=True)`

The moving-target defense on the SEMP. It drives five knobs over the encrypted
control channel, with ACK/DONE, watchdog and rollback:

- broker port hop (NAT);
- broker IP hop;
- SCMC source-IP hop;
- payload padding;
- publish frequency.

Who decides when to move:

- **Fixed timers:** one interval per knob (`mtd_coordinator.py`).
- **RL policy:** `rl_policy` is the guest path of a distilled `.npz` (`mtd_rl_coordinator.py`), which decides every `rl_tick` seconds.

| | |
|---|---|
| **`observe_data`** | Watches the data reaching the broker through the loopback listener: `data` and `data_gap` events, which the delivery detector needs. Independent of the dashboard. |
| **`dashboard_port`** | The live MTD page inside the container. The scenario forwards it through a bridged management NIC. |
| **`detector_model`** | Guest path of the delivery-attack detector, which scores the observed data plane live |
| **Telemetry** | `semp:/telemetry.jsonl`, name `mtd`: `run_info`, `action_scheduled`, `reply`, `action_outcome`, `action_late`, `action_skipped`, `client`, `nat`, `data`, `data_gap`, `rl_decision`, `detection`, `detector_alert` |
| **Ledger (`mirror`)** | `mtd_action` (action, status applied/failed/timed_out/client_lost, cost), `data_gap`, `detection`, `detector_alert` |
| **Artifacts** | none of its own. The scenario downloads `coordinator.log` and `telemetry.jsonl` with the capture prefix. |
| **`kind`** | `fixed` or `rl` |

Knob costs are the RL reward's per-knob weights
(`cyberrange/planes/defense/rl_policy.KNOB_COST`); `cyberrange/scenarios/mqtt_mtd/metrics.py` uses the same
weights.

---

## 6. Monitor plane (`cyberrange/planes/monitor/components.py`)

These components only read: they never write into the containers, and a
failed pull never breaks a run.

### `Capture(node, iface, file, local=None)`

`tcpdump -i IFACE -w FILE` on a node, running from `start` until
`stop_capture(ctx)`. `stop_capture` sends `pkill -INT tcpdump` and waits 2 s
for the flush. The capture is a **required** artifact, saved as `local`
(default: same name). A capture that is never stopped is still downloaded, as
far as it got.

### `TelemetryMirror()`

Copies guest telemetry onto the ledger while the run observes. On every poll,
for each started component that has a `mirror`, it reads the new lines of each
of its `TelemetrySource`s (one `TelemetryCursor` per file) and emits whatever
`mirror(ev)` returns. Start it **after** the components it mirrors. One
instance mirrors all of them.

### `PlantMirror(node="engine", frames="/engine_frames.jsonl")`

The CPS twin's latest frame, emitted as a `plant` event once per new physics
step, with load and DG bus voltages, `abnormal`, line loading, DG power,
energy, setpoint, breaker and control mode. This is what the dashboard's
voltage chart draws.

---

## 7. Composition recipes

### CPS run (`cyberrange/scenarios/cps/scenario.py`)

```
services     OtSensor → PhysicalProcess → (2 s) → PlcController → HmiClient → VulnApp [→ ItSensor]
monitor      PlantMirror, TelemetryMirror
response     SocAnalytics(inventory, policy, it=…)          always; acts with --respond
normal       ctx.observe(normal_duration)                   the model calibrates here
attack       ScriptedChain(mode) | PlannedAttacker(profile) → attack(ctx)
post_attack  ctx.observe(post_attack_duration)
```

**IT telemetry (`--it-telemetry`)** changes four components together:

- `HmiClient(diag_url="http://127.0.0.1:8080")`
- `VulnApp(access_log="/vuln_app.access.jsonl")`
- `ItSensor(access_log=…)` is started
- `SocAnalytics(it=True)`

### MQTT run (`cyberrange/scenarios/mqtt_mtd/scenario.py`)

```
services     QkdCertBootstrap → mosquitto → [MtdCoordinator + TelemetryMirror]
dataset      BackgroundReplay(duration) + ScmcPublisher → tcpdump on the router for N s
attack       BackgroundReplay + ScmcPublisher + Capture(router) + Capture(scmc)
             → PassiveFingerprinter.sniff → .score
             → DeliveryAttack.attack(cnn_ip) for the post-attack window → Capture.stop_capture
```

The baseline (`--no-mtd`) leaves out `MtdCoordinator` and runs the plain
publisher.

---

## 8. Writing a new component

1. **Choose the plane.** Ask what it *is*: legitimate activity (traffic), an adversary (attack), detection or response (defense), or observation (monitor). Add it to that plane's `components.py`.
2. **Guest process?** Subclass `GuestAgent` and build the command in `__init__`. Put the guest code in `cyberrange/planes/<plane>/agents/` as a flat module with bare imports, and add it to the node's manifest in the scenario's own `guest_files.py`. `tests/core/test_guest_imports.py` then checks it imports on the guest, and `tests/core/test_deploy_contract.py` freezes what the node receives.
3. **Host work?** Subclass `Component`: start a thread in `start`, join it in `stop`.
4. **Declare its outputs.** Files go in `artifacts()`. Telemetry goes in `telemetry()`, with a `mirror(ev)` that maps the interesting events onto ledger kinds. Anything it *does* to the lab belongs in the ground truth (`ctx.gt.record(...)`), never in telemetry.
5. **Seeds.** Take a `seed` argument and pass it to the guest as `seed_arg(seed)`. The scenario gives it `ctx.role_seed("<role>")`.
6. **Test it without Docker.** Use `tests/helpers/kathara.py`: `FakeManager` records every command and serves canned `tail` output, and `fake_downloads` serves artifacts. `tests/core/test_progress.py` and `tests/scenarios/mqtt_mtd/test_mqtt_scenario.py` show the pattern.
7. **Document it here,** and run `make platform-loc` to see what it adds.
