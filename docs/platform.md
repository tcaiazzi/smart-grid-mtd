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
                 │  cps-advisor (cps, the SOC advises a person) │
                 └───────────────┬──────────────────────────────┘
                     compose     │
   ┌──── plane components (cyberrange/planes/<x>/components.py) ────┐
   │ traffic  PhysicalProcess PlcController HmiClient                │
   │          BackgroundReplay ScmcPublisher                         │
   │ attack   VulnApp ScriptedChain PlannedAttacker RedConsole       │
   │          PassiveFingerprinter DeliveryAttack                    │
   │ defense  OtSensor ItSensor SocAnalytics WazuhManager WazuhAgent │
   │          JumpHost QkdCertBootstrap MtdCoordinator               │
   │ monitor  Capture TelemetryMirror PlantMirror                    │
   │          WebTerminal RecordedShell                              │
   └───────────────┬─────────────────────────────────────────────────┘
                   │ run on
   ┌─────────────── platform core (cyberrange/core) ─────────────────┐
   │ topology · lifecycle · context · streams · campaign ·           │
   │ aggregate · registry · cli · paths  +  ledger · dashboard       │
   └─────────────────────────────────────────────────────────────────┘

Imports point downwards only — scenarios on planes, planes on the core — and
tests/core/test_layering.py enforces it. See [structure.md](structure.md).
```

Beside the platform sits `nodes/`: the software the lab's nodes run that is not
the platform's — Wazuh's configuration, the SOC's analytics and console, the
red team's console, the scripts that give people a shell. Several components
above only stage and launch it (`WazuhManager`, `WazuhAgent`, `SocAnalytics`,
`JumpHost`, `WebTerminal`, `RecordedShell`, `RedConsole`); the boundary is
described in [structure.md](structure.md).

Every component, with its options, artifacts, telemetry and ground truth, is
documented in [components.md](components.md).

`python -m cyberrange.core loc` (or `make platform-loc`) measures the
split: how many lines are platform and how many each scenario had to write.

## 1. The three properties, and where they come from

| Property | Mechanism |
|---|---|
| **Safe** | Every attack runs against an emulated network and a digital twin, never real equipment. Each lab is an isolated set of containers (Kathará), named per scenario (`test` for `mqtt-mtd`, `cps`, `cps-advisor`) so one never replaces the other. Zones and boundary rules are part of the declared topology. The lifecycle always undeploys a lab, even when the episode fails. |
| **Reproducible** | Seeds are derived per role (`core.context.role_seed`), so each process of a run is reproducible on its own. Topology, options and components are declared, and every run writes its `topology.json`. Campaigns resume, retry, and record their grid and parameters (`campaign.json`). Dependencies and images are pinned. Ground truth is recorded host-side for every run. |
| **Observable** | Three event streams per run (section 3). There is a live progress ledger for every run and campaign of every scenario, and one dashboard that reads it. Per-run metrics and a 95%-CI aggregate are computed as runs finish. |

## 2. Writing a scenario: the contract

A scenario is a subclass of `cyberrange.core.scenario.Scenario`,
registered in `cyberrange/core/registry.py`:

| Member | Purpose |
|---|---|
| `name`, `lab_name` | Registry key, and the Kathará lab name. A deploy replaces a lab with the same name. |
| `add_arguments(ap)` | The scenario's options. The core adds `--seed --progress-file --run-id --poll-interval --playground`. |
| `validate(args)` | Fail fast with `SystemExit` before anything is deployed. |
| `topology(args)` | A `core.topology.Topology` (see below). |
| `episode_phases(args)` | `[PhaseSpec(name, planned_s, timed)]`, the phases between deploy and download. They drive the ETA. The core adds `deploy`, `download`, `undeploy` around them, and `open` for a run held up with `--playground`. |
| `episode(ctx)` | Start components, drive the phases. |
| `run_info(args)` | Extra fields for `run_start` (mode, seed, …). |
| `out_dir(args)`, `run_id(args)`, `prepare(args)` | Where the run writes, its ledger id, and anything to do before the lab is built (e.g. tee a run log). |
| `write_structure(ctx)` | Optional files for the dashboard (CPS: `kg.json`, `tree.json`). |
| `panel_js()` | Path of the JavaScript file that draws the scenario's own part of the dashboard (section 5), or `None`. |
| `structure()` | `{"kg": …, "tree": …}` rebuilt from the declared topology, for runs recorded without their structure files; `None` when the scenario has none. |
| `check_run(ctx) -> int` | 0 if the run is valid; anything else becomes the exit code (MQTT: 3 when the SCMC never published). |
| `metrics(run_dir) -> dict` | The run's metrics, used by campaigns and the dashboard. |

Each scenario's command-line entry point is a few lines long
(`cyberrange/scenarios/<name>/cli.py`):

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
    Node("sensor", [Iface("OT", promisc=True), Iface("MGMT", "10.30.0.10/24")],
         role="sensor", files=SENSOR_FILES, mgmt_port="8090:8080/tcp"),
    ...
])
```

`mgmt_port` publishes guest ports on the host (`"HOST:GUEST/tcp"`, or a list of
them) through a bridged NIC that is not a lab network. That NIC brings a default
route of its own, so a node that has both a published port and a default route
in the lab declares the latter with `Route(..., replace=True)`.

`core.topology.build_lab` turns the topology into a Kathará Lab: startup
commands, staged files, the bridged NIC of the published ports, and an
`addresses` meta on every machine. `export_lab_conf` writes
the same lab as `lab.conf` + `.startup` files (`make lab-conf SCENARIO=cps`),
which is the scenario description to show in the paper.

### The run lifecycle (`core.lifecycle.run`)

```
run_start → build lab → topology.json + structure → deploy (replacing a same-name lab)
          → episode → [open, until Ctrl-C: --playground]
          → stop components → download artifacts → undeploy (always)
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
| `ctx.open_ground_truth(**run_meta)` | Open `ground_truth.jsonl`; afterwards `ctx.gt.record(kind, ...)` writes to it. |
| `ctx.emit(kind, **fields)` | Put one event on the progress ledger. |
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
`TelemetryMirror` reads the telemetry of every started component through a
`TelemetryCursor` and folds it onto the progress ledger.

### A scenario built on another

A scenario may subclass another and deploy the same lab under its own name;
the base never knows. `cps-advisor` does this with `cps`, and what it varies is
only what the base exposes for the purpose:

| On the base (`CpsScenario`) | What the derived scenario does with it |
|---|---|
| `DEFAULT_OUT_DIR`, `DEFAULT_RESPOND`, `DEFAULT_APPROVAL`, `APPROVAL_HELP` | other defaults for the same options |
| `check_approval(spec)` | accepts `operator:<s>` only, where the base accepts `auto`, `deny`, `delay:<s>` |
| `operator_api(args)` | the `operator_*` arguments of `SocAnalytics`: the base returns none |
| `extra_services(ctx)` | components started with the services (terminals, recorded shells, the jump host) |
| `engage(ctx)` | called once the ground truth is open, when an attack may begin (the red team is let in) |
| `topology.topology(args, name=, extras=)` | the same lab under another name, with `{node: Extra(files, ports, startup)}` added to its nodes |

The derived scenario's `SOURCES` list only its own directory and its manifests
only what it adds, so the shared lab is counted once (see
[structure.md](structure.md)).

## 3. The three streams of a run

| File | Written by | What it holds | Who reads it |
|---|---|---|---|
| `ground_truth.jsonl` | the host only: attack drivers, fault injection, the scenario | what really happened: `run_meta`, attack steps, writes, blocks, faults, `run_end` | scorers, dataset builders. Never readable by a defender. |
| `<node>.telemetry.jsonl` | defense components in the guests (`mtd_telemetry.py`) | what the defenders observed and did: findings, alerts, MTD actions, delivery gaps | detectors, the responder, metrics |
| `progress.jsonl` | the host ledger (`cyberrange/core/progress.py`) | the run as it happens: lifecycle, campaign bookkeeping, a live mirror of the telemetry | the dashboard |

The separation is deliberate. A detector or a response policy can only be
scored against information it could not have had.

Event kinds common to every scenario are documented in
`cyberrange/core/streams.py`. Scenario-specific kinds are:

- **CPS:** `plant`, `finding`, `alert`, `model_fitted`, `model_error`, `response_write`, `attack_write`, `plan_step`, `tree_state`, `decision`, `approval`, `action`.
- **CPS advisor:** the CPS kinds — `approval` here is a suggestion put to the operator, then its outcome — plus `soc_mode`, `team_command` and `red_step`.
- **MQTT:** `mtd_action`, `data_gap`, `detection`, `detector_alert`.

## 4. Campaigns (`core.campaign`)

A campaign is a list of **units**, run in order on one ledger.

- A **unit** is one configuration × one repetition. Its **steps** run in order, and a failed step stops the rest of the unit. `needs` names units that must have succeeded first.
- A **step** is either in-process (`run(emit)`: a scenario run, bound to the campaign ledger) or a command (`cmd`, e.g. a `make` target).
- A command step may carry a `timeout` in seconds. When it expires the command and everything it started are stopped (interrupted first, so a lab run undeploys itself) and the step fails like any other, which is what lets `retries` take over. The MQTT campaigns set it on their lab steps from `--lab-timeout`; without it a step has no limit.
- `skip_if()` reuses earlier results.
- A **scored** step (`run_dir` + `metrics`) gets `metrics.json`, which is also what `--resume` skips on, and is folded into the aggregate after every run.
- A campaign's command line ends in `core.campaign.run_cli(campaign)`, which checks once that a lab can start, runs the units, prints the verdict and returns the exit code: `0` when every unit finished, `1` when one failed or was blocked, `EXIT_NO_LAB` (4) when no lab could start. A scenario's `campaign.py` builds the units and handles `--dry-run` itself; everything after that is shared. `epilogue=` adds the scenario's own lines before the verdict (the paper lists its figures).
- `core.aggregate.summarize` gives n / mean / std / 95% CI (Student t) / median / min / max of every numeric metric per group. It writes `ci.csv` and a mean [CI] table in `summary.md`.

| Campaign | Units | Steps |
|---|---|---|
| CPS (`make cps-campaign`, `cyberrange/scenarios/cps/campaign.py`) | modes × seeds | one scored scenario run each. Every option of the CPS scenario passes through, e.g. `--respond solver --it-telemetry --attack-driver planner`. |
| Paper (`main.py`, `cyberrange/scenarios/mqtt_mtd/campaign.py`) | baseline + three MTD configs + figures, × runs | the same `make` targets as `scripts/run_single.sh`, with lab steps retried. Every config needs its run's baseline (cross-model attack); the figures need all four. The ledger and summary are in `output/campaigns/paper-mbps<M>/`. |
| MTD ablation (`make sweep`, `cyberrange/scenarios/mqtt_mtd/ablation.py`) | 15 named MTD configurations in five groups (e0–e4), no seeds | the paper's `make` steps per configuration, plus its entropy and its row of the manifest; a last unit draws the figures with `plot_sweep` from the configurations that finished. |

## 5. Following it live

```bash
make dashboard            # every scenario's runs and campaigns under output/ (127.0.0.1:8765)
make cps-dashboard        # only the cps runs
make cps-advisor-dashboard  # only the cps-advisor runs
```

`cyberrange/core/dashboard.py` only reads: the server has no endpoint that
changes anything, in the lab or on disk. It shows two kinds of content.

**Common to every scenario:**

- the list of ledgers, with the scenario of each;
- campaign progress and ETA (fixed-length phases are flagged `timed`);
- the queue;
- the current run's phases;
- results, with a mean [95% CI] tab.

A ledger that is open keeps its file's modification time fresh
(`progress.HEARTBEAT_S`), so a campaign busy in a step that emits nothing is
still shown as running; one whose writer died turns "interrupted" after
`ledgers.STALE_S`.

**Per scenario**, drawn by the scenario's `panel.js` and not by the page — the
hooks are `queue` (its columns of the run table), `detail` (the selected run),
`results` (`{tabs: [{id, label}], render(tab, aggregate, table)}`, its tabs
next to the mean [95% CI] one) and `graph` (its structure views):

- **CPS:** the plant voltage chart, findings, and the topology, knowledge graph and attack tree with the response decisions over time.
- **CPS advisor:** the CPS panel (its `panel.js` delegates to it).
- **MQTT:** MTD actions per knob coloured by outcome, delivery gaps, and the coordinator's actions table.

### A run kept open: `--playground`

Every scenario's run takes `--playground` (`PLAYGROUND=1` on the single-run
`make` targets). After its episode the run does not tear down: the lab, the
components and the live mirrors stay up, in a phase named `open`, until Ctrl-C.
The interrupt is how such a run ends, so it is followed by the usual teardown
(stop, download, undeploy, `check_run`) and the run is recorded as `ok`. A
second Ctrl-C during the teardown interrupts it for real.

It is for trying things by hand — a lab to attack, a defender to watch — and it
is not an experiment: the run's length is whatever it was left open, so its
duration-dependent metrics do not compare with a campaign's. Campaigns never
set it.

### People in a lab

The dashboard is the referee's view and stays read-only when people play in a
lab (`cps-advisor`, `docs/scenario-cps-advisor.md`). A team does not act
through the platform: each has a console served by its own node — the SOC's
for the defenders, one on the attacker node for a red team — and a web
terminal there. The platform's part is to let them in and keep sight of them:

- `monitor.WebTerminal` serves a shell of a node to a browser; `defense.JumpHost`
  gives the defenders SSH from their node to the hosts they manage;
- `monitor.RecordedShell` puts every command typed there on the ledger
  (`team_command`), with the team read from how the shell got onto the node —
  a referee's own shell is `control`, never the attack — and `attack.RedConsole` turns the steps a red team runs into
  ground truth;
- the page shows the defender's suggestions with their outcome, and a *Teams*
  timeline of both sides' steps and commands.

A team's token never goes on the ledger: the scenario writes the teams' links
to a file in the run directory, on the host.

## 6. Adding a scenario: checklist

1. **Image.** Reuse `kathara/mqtt`, `kathara/cps` or `kathara/soc`, or add `docker/<name>/Dockerfile`.
2. **Guest code.** Agents go under `cyberrange/planes/<plane>/agents/`; the configuration and glue of a tool a node runs go under `nodes/<tool>/` (prefer an existing open-source tool, installed by the image, to code of our own). Both are flat modules with bare imports, and may import only the stdlib and what the node image installs. List them in your scenario's own `guest_files.py`; `tests/core/test_guest_imports.py` replays the manifest and `tests/core/test_deploy_contract.py` freezes what each node receives.
3. **Components.** Add to `cyberrange/planes/<plane>/components.py` whatever the existing ones do not cover. A component must not import your scenario: take what is specific to it as a constructor argument (as `PlannedAttacker` takes its attack tree). Reuse first: `Capture`, `TelemetryMirror`, `GuestAgent`, the sensors, the attack drivers.
4. **Scenario package.** Create `cyberrange/scenarios/<name>/` with:
   - `topology.py`: a `Topology`;
   - `scenario.py`: the `Scenario` subclass;
   - `cli.py`: three lines wrapping `cli.main`;
   - `guest_files.py`: what each node is staged with;
   - optionally `campaign.py`, `analysis/`, `training/`;
   - `SOURCES` and `GUEST_MANIFESTS` in `__init__.py`, for the code accounting. Keep the `SOURCES` categories disjoint (one directory each): loc sums them independently, so a file matched twice is counted twice.
5. **Register it** in `core/registry.py` (name -> `cyberrange.scenarios.<name>.scenario:<Class>`).
6. **Metrics.** Add `cyberrange/scenarios/<name>/metrics.py: compute_metrics(run_dir)`, returned by `Scenario.metrics`.
7. **Tests.** Write `tests/scenarios/<name>/test_<name>_scenario.py` with `tests/helpers/kathara.py`. `FakeManager` and `fake_downloads` run the whole lifecycle without Docker: commands, artifacts, ledger, ground truth, exit code.
8. **Measure.** Run `make platform-loc` before and after; the difference is what the scenario cost.
