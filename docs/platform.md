# The platform: core, plane components, scenarios

The cyber range is a **platform** on which **scenarios** run. The platform owns
everything that is the same for every experiment: how a lab is described,
deployed, observed and torn down; how runs are repeated, scored and
aggregated; how they are followed live. A scenario only declares what is
specific to it: its network, the components it runs, its episode and its
metrics.

```
                 ┌───────────────── scenarios ─────────────────┐
                 │  mqtt-mtd (MQTT smart grid, MTD vs CNN)      │
                 │  cps      (OT/Modbus, active attack, SOAR)   │
                 └───────────────┬──────────────────────────────┘
                     compose     │
   ┌─────────── plane components (<plane>/components.py) ───────────┐
   │ traffic  PhysicalProcess PlcController HmiClient                │
   │          BackgroundReplay ScmcPublisher                         │
   │ attack   VulnApp ScriptedChain PlannedAttacker                  │
   │          PassiveFingerprinter DeliveryAttack                    │
   │ defense  OtSensor ItSensor SoarResponder                        │
   │          QkdCertBootstrap MtdCoordinator                        │
   │ monitor  Capture TelemetryMirror PlantMirror                    │
   └───────────────┬─────────────────────────────────────────────────┘
                   │ run on
   ┌────────── platform core (network_scenario/core) ──────────┐
   │ topology · lifecycle · context · streams · campaign ·      │
   │ aggregate · registry · cli   +  ledger · dashboard         │
   └────────────────────────────────────────────────────────────┘
```

`python -m network_scenario.core loc` (or `make platform-loc`) measures the
split: how many lines are platform and how many each scenario had to write.

## 1. The three properties, and where they come from

| Property | Mechanism |
|---|---|
| **Safe** | Every attack runs against an emulated network and a digital twin, never real equipment. Each lab is an isolated set of containers (Kathará), named per scenario (`test`, `cps`) so one never replaces the other. Zones and boundary rules are part of the declared topology. The lifecycle always undeploys a lab, even when the episode fails. |
| **Reproducible** | Seeds are derived per role (`core.context.role_seed`), so each process of a run is reproducible on its own. Topology, options and components are declared, and every run writes its `topology.json`. Campaigns resume, retry, and record their grid and parameters (`campaign.json`). Dependencies and images are pinned. Ground truth is recorded host-side for every run. |
| **Observable** | Three event streams per run (section 3). There is a live progress ledger for every run and campaign of every scenario, and one dashboard that reads it. Per-run metrics and a 95%-CI aggregate are computed as runs finish. |

## 2. Writing a scenario: the contract

A scenario is a subclass of `network_scenario.core.scenario.Scenario`,
registered in `network_scenario/core/registry.py`:

| Member | Purpose |
|---|---|
| `name`, `lab_name` | Registry key, and the Kathará lab name. A deploy replaces a lab with the same name. |
| `add_arguments(ap)` | The scenario's options. The core adds `--seed --progress-file --run-id --poll-interval`. |
| `validate(args)` | Fail fast with `SystemExit` before anything is deployed. |
| `topology(args)` | A `core.topology.Topology` (see below). |
| `episode_phases(args)` | `[PhaseSpec(name, planned_s, timed)]`, the phases between deploy and download. They drive the ETA. |
| `episode(ctx)` | Start components, drive the phases. |
| `run_info(args)` | Extra fields for `run_start` (mode, seed, …). |
| `out_dir(args)`, `run_id(args)`, `prepare(args)` | Where the run writes, its ledger id, and anything to do before the lab is built (e.g. tee a run log). |
| `write_structure(ctx)` | Optional files for the dashboard (CPS: `kg.json`, `tree.json`). |
| `check_run(ctx) -> int` | 0 if the run is valid; anything else becomes the exit code (MQTT: 3 when the SCMC never published). |
| `metrics(run_dir) -> dict` | The run's metrics, used by campaigns and the dashboard. |

Each scenario's command-line entry point is a few lines long
(`network_scenario/cps_experiment.py`, `network_scenario/run_experiment.py`):

```python
def main(argv=None):
    cli.main(CpsScenario(), argv)
```

### Topology

The network is plain data. Interface order fixes `eth0`, `eth1`, …:

```python
Topology("cps", default_image="kathara/cps", nodes=[
    Node("hmi", [Iface("IT", "10.10.0.20/24")], role="hmi",
         routes=[Route("default", "10.10.0.1", "eth0")], files=HMI_FILES),
    Node("sensor", [Iface("OT", promisc=True), Iface("DEF", "10.30.0.10/24")],
         role="sensor", files=SENSOR_FILES, mgmt_port="8090:8080/tcp"),
    ...
])
```

`core.topology.build_lab` turns the topology into a Kathará Lab: startup
commands, staged files, the bridged management NIC, and an `addresses` meta on
every machine (the SOAR knowledge graph reads it). `export_lab_conf` writes
the same lab as `lab.conf` + `.startup` files (`make lab-conf SCENARIO=cps`),
which is the scenario description to show in the paper.

### The run lifecycle (`core.lifecycle.run`)

```
run_start → build lab → topology.json + structure → deploy (replacing a same-name lab)
          → episode → stop components → download artifacts → undeploy (always)
          → check_run → run_end{status, rc}
```

The episode drives the lab through a `RunContext`:

| Call | What it does |
|---|---|
| `ctx.start(component)` | Start a component and register it for stop, artifacts and live polling. |
| `ctx.exec(node, cmd, console_log=…)`, `ctx.run(node, cmd)`, `ctx.exec_text(...)` | Run commands in the guests. |
| `ctx.phase(name)` | Phase start and end on the ledger. |
| `ctx.observe(seconds)` | Wait on a fixed deadline while polling the components. |
| `ctx.live()` | Poll in the background while a block waits on a guest command. |
| `ctx.open_ground_truth(**run_meta)` | Open `ground_truth.jsonl`. |
| `ctx.role_seed(role)` | The seed for one role of the run. |
| `ctx.add_artifact(...)`, `ctx.download(...)` | Extra files to fetch. |

### Components

A component (`core.component.Component`) has:

- `start(ctx)` and `stop(ctx)`;
- `artifacts()`: `[Artifact(node, guest_path, local_name, required)]`;
- `telemetry()`: `[TelemetrySource(node, path, name)]`;
- `mirror(ev)`: maps one of its telemetry events onto the ledger;
- `poll(ctx)`: pulls live state.

`GuestAgent` covers the common case: one process in one container, with its
console captured to a log file.

Components are configurable and the scenario wires them together. For
example, the CPS scenario's `--it-telemetry` starts `ItSensor`, gives
`VulnApp` an access log and `HmiClient` a diagnostics URL, and lets the
responder use the IT countermeasures.

The artifacts a run downloads are the union of its components' artifacts. The
`SoarResponder` reads the telemetry of every started sensor through the same
`TelemetryCursor` the live mirror uses.

## 3. The three streams of a run

| File | Written by | What it holds | Who reads it |
|---|---|---|---|
| `ground_truth.jsonl` | the host only: attack drivers, fault injection, the scenario | what really happened: `run_meta`, attack steps, writes, blocks, faults, `run_end` | scorers, dataset builders. Never readable by a defender. |
| `<node>.telemetry.jsonl` | defense components in the guests (`mtd_telemetry.py`) | what the defenders observed and did: findings, alerts, MTD actions, delivery gaps | detectors, the responder, metrics |
| `progress.jsonl` | the host ledger (`monitor/progress.py`) | the run as it happens: lifecycle, campaign bookkeeping, a live mirror of the telemetry | the dashboard |

The separation is deliberate. A detector or a response policy can only be
scored against information it could not have had.

Event kinds common to every scenario are documented in
`network_scenario/core/streams.py`. Scenario-specific kinds are:

- **CPS:** `plant`, `finding`, `alert`, `model_fitted`, `attack_write`, `plan_step`, `tree_state`, `decision`, `action`.
- **MQTT:** `mtd_action`, `data_gap`, `detection`, `detector_alert`.

## 4. Campaigns (`core.campaign`)

A campaign is a list of **units**, run in order on one ledger.

- A **unit** is one configuration × one repetition. Its **steps** run in order, and a failed step stops the rest of the unit. `needs` names units that must have succeeded first.
- A **step** is either in-process (`run(emit)`: a scenario run, bound to the campaign ledger) or a command (`cmd`, e.g. a `make` target).
- `skip_if()` reuses earlier results.
- A **scored** step (`run_dir` + `metrics`) gets `metrics.json`, which is also what `--resume` skips on, and is folded into the aggregate after every run.
- `core.aggregate.summarize` gives n / mean / std / 95% CI (Student t) / median / min / max of every numeric metric per group. It writes `ci.csv` and a mean [CI] table in `summary.md`.

| Campaign | Units | Steps |
|---|---|---|
| CPS (`make cps-campaign`, `network_scenario/cps_campaign.py`) | modes × seeds | one scored scenario run each. Every option of the CPS scenario passes through, e.g. `--respond solver --it-telemetry --attack-driver planner`. |
| Paper (`main.py`, `network_scenario/scenarios/mqtt_mtd/campaign.py`) | baseline + three MTD configs + figures, × runs | the same `make` targets as `run_single.sh`, with lab steps retried. Every config needs its run's baseline (cross-model attack); the figures need all four. The ledger and summary are in `output/campaigns/paper-mbps<M>/`. |

## 5. Following it live

```bash
make dashboard            # every scenario's runs and campaigns under output/ (127.0.0.1:8765)
make cps-dashboard        # only output/cps
```

`monitor/dashboard.py` only reads. It shows two kinds of content.

**Common to every scenario:**

- the list of ledgers, with the scenario of each;
- campaign progress and ETA (fixed-length phases are flagged `timed`);
- the queue;
- the current run's phases;
- results, with a mean [95% CI] tab.

**Per scenario:**

- **CPS:** the plant voltage chart, findings, and the topology, knowledge graph and attack tree with the response decisions over time.
- **MQTT:** MTD actions per knob coloured by outcome, delivery gaps, and the coordinator's actions table.

## 6. Adding a scenario: checklist

1. **Image.** Reuse `kathara/mqtt` or `kathara/cps`, or add `docker/<name>/Dockerfile`.
2. **Guest agents.** Add them under `<plane>/agents/`. They are flat modules with bare imports. Add a manifest in `network_scenario/guest_files.py` and `tests/test_guest_imports.py` will check it.
3. **Components.** Add to `<plane>/components.py` whatever the existing ones do not cover. Reuse first: `Capture`, `TelemetryMirror`, `GuestAgent`, the sensors, the attack drivers.
4. **Scenario package.** Create `network_scenario/scenarios/<name>/` with:
   - `topology.py`: a `Topology`;
   - `scenario.py`: the `Scenario` subclass;
   - optionally `campaign.py`;
   - `SOURCES` and `GUEST_MANIFESTS` in `__init__.py`, for the code accounting.
5. **Register it** in `core/registry.py`, and add a CLI module (`network_scenario/<name>_experiment.py`).
6. **Metrics.** Add `monitor/<name>_metrics.py: compute_metrics(run_dir)`, returned by `Scenario.metrics`.
7. **Tests.** Write `tests/test_<name>_scenario.py` with `tests/fakes/kathara.py`. `FakeManager` and `fake_downloads` run the whole lifecycle without Docker: commands, artifacts, ledger, ground truth, exit code.
8. **Measure.** Run `make platform-loc` before and after; the difference is what the scenario cost.
