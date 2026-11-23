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
                 │  cps-recon   (cps, attacker derives the tree)│
                 │  cps-soc     (cps-advisor on Wazuh and IRIS) │
                 └───────────────┬──────────────────────────────┘
                     compose     │
   ┌──── plane components (cyberrange/planes/<x>/components.py) ────┐
   │ traffic  PhysicalProcess PlcController HmiClient                │
   │          BackgroundReplay ScmcPublisher                         │
   │ attack   VulnApp EwsMaintenance ScriptedChain PlannedAttacker   │
   │          ReconAttacker RedConsole PassiveFingerprinter          │
   │          DeliveryAttack                                         │
   │ defense  OtSensor ItSensor SocAnalytics WazuhManager WazuhAgent │
   │          WazuhIndexer WazuhDashboard AlertShipper               │
   │          IrisAlertForwarder IrisService JumpHost                │
   │          QkdCertBootstrap MtdCoordinator                        │
   │ monitor  Capture TelemetryMirror PlantMirror                    │
   │          WebTerminal RecordedShell                              │
   └───────────────┬─────────────────────────────────────────────────┘
                   │ run on
   ┌─────────────── platform core (cyberrange/core) ─────────────────┐
   │ topology · lifecycle · context · streams · campaign ·           │
   │ aggregate · registry · cli · paths  +  ledger · dashboard       │
   └─────────────────────────────────────────────────────────────────┘
```

Imports point downwards only — scenarios on planes, planes on the core — and
`tests/core/test_layering.py` enforces it. See [Where files go](structure.md).

Beside the platform sits `nodes/`: the software the lab's nodes run that is not
the platform's — Wazuh's and DFIR-IRIS's configuration, the SOC's analytics and
console, the red team's agents and console, the harnesses that play a seat, the
scripts that give people a shell. Several components above only stage and
launch it (`WazuhManager`, `WazuhAgent`, the SOC's tools, `SocAnalytics`,
`PlannedAttacker`, `ReconAttacker`, `RedConsole`, `JumpHost`, `WebTerminal`,
`RecordedShell`); the boundary is described in
[Where files go](structure.md#beside-the-layers-nodes).

Every component, with its options, artifacts, telemetry and ground truth, is
documented in [components.md](components.md).

The core has a command line of its own, `python -m cyberrange.core <command>`:

| Command | What it does |
|---|---|
| `scenarios` | Lists the registered scenarios. |
| `export <scenario> --out <dir>` | Writes the scenario's lab as `lab.conf` and `.startup` files (`make lab-conf SCENARIO=…`). |
| `loc` | Measures the split: how many lines are platform and how many each scenario had to write (`make platform-loc`). |
| `runs` | Lists the runs kept under a directory, one line each (`make runs`). |

## 1. The three properties, and where they come from

| Property | Mechanism |
|---|---|
| **Safe** | Every attack runs against an emulated network and a digital twin, never real equipment. Each lab is an isolated set of containers (Kathará), named per scenario (`test` for `mqtt-mtd`; `cps`, `cps-advisor`, `cps-recon` and `cps-soc` for the others) so one never replaces the other. Zones and boundary rules are part of the declared topology. The lifecycle always undeploys a lab, even when the episode fails. |
| **Reproducible** | Seeds are derived per role (`core.context.role_seed`), so each process of a run is reproducible on its own. Topology, options and components are declared, and every run writes its `topology.json`. Campaigns resume, retry, and record their grid and parameters (`campaign.json`). Dependencies and images are pinned. Ground truth is recorded host-side for every run. |
| **Observable** | Three event streams per run (section 3). There is a live progress ledger for every run and campaign of every scenario, and one dashboard that reads it. Per-run metrics and a 95%-CI aggregate are computed as runs finish. |

## 2. Writing a scenario: the contract

A scenario is a subclass of `cyberrange.core.scenario.Scenario`,
registered in `cyberrange/core/registry.py`:

| Member | Purpose |
|---|---|
| `name`, `lab_name` | Registry key, and the Kathará lab name. A deploy replaces a lab with the same name. |
| `add_arguments(ap)` | The scenario's options. The core adds `--seed --progress-file --run-id --poll-interval --playground --out-root --run-name --overwrite`. |
| `validate(args)` | Fail fast with `SystemExit` before anything is deployed. |
| `topology(args)` | A `core.topology.Topology` (see below). |
| `episode_phases(args)` | `[PhaseSpec(name, planned_s, timed)]`, the phases between deploy and download. They drive the ETA. The core adds `deploy`, `download`, `undeploy` around them, and `open` for a run held up with `--playground`. |
| `episode(ctx)` | Start components, drive the phases. |
| `run_info(args)` | Extra fields for `run_start` (mode, seed, …). |
| `out_dir(args)`, `run_id(args)`, `prepare(args)` | Where the run writes, its ledger id, and anything to do before the lab is built (e.g. tee a run log). |
| `one_run_per_dir` | `True` for a scenario whose run owns its output directory (the CPS scenarios): a standalone run is given a new one unless told where to go, and refuses one that already holds a run. `False` for one that puts several runs in a directory on purpose (`mqtt-mtd`, each under its own prefix). |
| `run_card(args)`, `secret_options(args)` | What the scenario adds to the run's card (below): flat values that tell whether two runs ran the same thing; and the names of the options whose value must not be kept with the run. |
| `structure_files` | The files `write_structure` writes that describe the lab; the run's card carries their fingerprints. |
| `write_structure(ctx)` | Optional files for the dashboard (CPS: `kg.json`, `tree.json`). |
| `panel_js()` | Path of the JavaScript file that draws the scenario's own part of the dashboard (section 5), or `None`. |
| `structure()` | `{"kg": …, "tree": …}` rebuilt from the declared topology, for runs recorded without their structure files; `None` when the scenario has none. |
| `check_run(ctx) -> int` | 0 if the run is valid; anything else becomes the exit code (MQTT: 3 when the SCMC never published). |
| `metrics(run_dir) -> dict` | The run's metrics, used by campaigns and the dashboard. |
| `report(metrics)` | The metrics as text, written beside `metrics.json` as `metrics.md`; `None` for no report. |
| `headline(card, metrics)` | One line on how a finished run went, for `make runs`. |

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
          → check_run → score → run_end{status, rc}
```

**The run's card.** `core/runcard.py` writes `run.json` in the run directory
when the run starts, and completes it when it ends: the commit the run was made
with and whether the tree had uncommitted changes, fingerprints of the lab and
of the scenario's `structure_files`, the node images, the options (those named
by `secret_options` masked), what the scenario and its features add
(`run_card`), and how the run ended. A run that dies still says what it was.

**How a run ends.** `run_end` carries one of four statuses:

| Status | Meaning | Exit code |
|---|---|---|
| `ok` | The episode finished and `check_run` returned 0. A standalone run is then scored (`run_metrics`, `metrics.json`). | 0 |
| `invalid` | The episode finished but `check_run` refused the run. | what `check_run` returned |
| `failed` | An exception, among them `ComponentDown`: a component the run cannot do without was found dead (`ctx.require_alive`). | non-zero: the exception is raised |
| `interrupted` | Ctrl-C, outside a playground's `open` phase. | non-zero: the interrupt is raised |

Two failures come before a run exists: no container engine reachable exits
with `EXIT_NO_LAB` (4), and an output directory that already holds a run is
refused (`RunDirTaken`) unless `--overwrite` is given.

The episode drives the lab through a `RunContext`:

| Call | What it does |
|---|---|
| `ctx.start(component)` | Start a component and register it for stop, artifacts and live polling. |
| `ctx.exec(node, cmd, console_log=…)`, `ctx.run(node, cmd)`, `ctx.exec_text(...)` | Run commands in the guests. |
| `ctx.upload(node, guest_path, text, mode=0o600)` | Write a file in a guest without its content passing through a command line (tokens, secrets). |
| `ctx.phase(name)` | Phase start and end on the ledger. |
| `ctx.observe(seconds)` | Wait on a fixed deadline while polling the components. |
| `ctx.live()` | Poll in the background while a block waits on a guest command. |
| `ctx.hold()` | Keep the lab as the episode left it, polling, until Ctrl-C: what a `--playground` run does in its `open` phase. |
| `ctx.down()`, `ctx.require_alive()` | The watched components that are not running (each put on the ledger once, as `component_down`); fail the run now if there is one. |
| `ctx.open_ground_truth(**run_meta)`, `ctx.close_ground_truth()` | Open `ground_truth.jsonl`, after which `ctx.gt.record(kind, ...)` writes to it; record its `run_end` and close it. |
| `ctx.emit(kind, **fields)` | Put one event on the progress ledger. |
| `ctx.role_seed(role)` | The seed for one role of the run. |
| `ctx.add_artifact(...)`, `ctx.download(...)` | Extra files to fetch. |
| `ctx.path(name)` | A file's path in the run's output directory. |

### Components

A component (`core.component.Component`) has:

- `start(ctx)` and `stop(ctx)`;
- `artifacts()`: `[Artifact(node, guest_path, local_name, required)]`;
- `telemetry()`: `[TelemetrySource(node, path, name)]`;
- `mirror(ev)`: maps one of its telemetry events onto the ledger;
- `poll(ctx)`: pulls live state.

`GuestAgent` covers the common case: one process in one container, with its
console captured to a log file. Given `watch=`, the process is one the run
cannot do without: found dead, the run fails with a `component_down` event
([Components §1](components.md#1-how-a-component-works)). `SeatPlayer` is a
`GuestAgent` that seats a harness — the program that runs a model as a player,
described to the platform as data by `core/harness.py` — at a team's console
([Harnesses as players](playing-with-agents.md)).

Components are configurable and the scenario wires them together. For
example, the CPS scenario's `--it-telemetry` starts `ItSensor`, gives
`VulnApp` an access log and `HmiClient` a diagnostics URL, and lets the
responder use the IT countermeasures.

The artifacts a run downloads are the union of its components' artifacts. The
`TelemetryMirror` reads the telemetry of every started component through a
`TelemetryCursor` and folds it onto the progress ledger.

### A scenario built on another

The CPS scenarios share one lab and one episode, and differ by what they add
to them. Two things make that possible without copying the base.

**The lab is data.** `cyberrange/scenarios/cps/lab.py` describes a lab as a
`LabSpec`, which holds:

- zones, with their CIDR, and whether the boundary forwards between them;
- hosts, each with a role, NICs in interface order, services, and an optional
  image;
- the flows the boundary lets through.

Everything else is derived from the spec:

- addresses, routes and the boundary's ruleset;
- which hosts carry a Wazuh agent;
- the SOC's inventory.

`topology.py` turns a spec into the platform's `Topology`. The episode finds its
hosts by role (`plant_of(spec)`) instead of by name. When a spec is built,
`LabSpec.check()` refuses one that breaks a constraint the rest of the system
relies on: two NICs on one address, a primary address that does not sort first
for the knowledge graph, or a name Kathará refuses. `default_spec()` is the lab
every CPS scenario runs today. A larger lab is another spec, overriding
`CpsScenario.lab_spec(args)`.

**Additions are features.** A `Feature` (`cyberrange/scenarios/cps/feature.py`)
is one addition, with neutral hooks. A scenario is `CpsScenario` with a tuple
of them:

| Scenario | `features` |
|---|---|
| `cps` | `()` |
| `cps-advisor` | `(People(),)` |
| `cps-soc` | `(SocTools(), People(console=False))` |
| `cps-recon` | `(Recon(),)` |

| Hook | What a feature does with it |
|---|---|
| `add_arguments`, `validate`, `prepare`, `run_info` | its options, their checks, per-run secrets, what the ledger may know |
| `run_card(scenario, args)`, `secret_options(args)` | what it adds to the run's card; which of its options are secrets |
| `check_approval(spec)` | takes over what `--approval` may be (People: `operator:<s>` only) |
| `host_ports(args)` | the host ports it publishes; the scenario refuses two features publishing one port |
| `extras(spec, args)` | `{host: Extra(files, ports, startup, image)}` added to the lab's hosts |
| `nodes(spec, args)` | nodes of its own next to the lab (the SOC's tools) |
| `links(args)`, `operator_api(scenario, args)` | what each team is handed; the `SocAnalytics` arguments it sets |
| `phases(args)` | the phases it adds to the episode, after the lab's own (People: `engagement`, when two harnesses play each other) |
| `services(ctx)`, `engage(ctx)` | components started with the services; once the ground truth is open |
| `attacker(scenario, args)` | its own attack driver (Recon) |

The scenario calls the features in the order it lists them. What one feature
puts on a host (files, startup commands) comes before what the next one puts
there, and its services start first. Two features may not give one host two
different images.

A combination no scenario declares yet, such as the SOC's tools with a recon
attacker, is one more tuple (`tests/scenarios/cps/test_cps_lab.py` builds that
one).

Each feature lives in its scenario's directory. The scenario's `SOURCES` list
only that directory, and its manifests list only what it adds, so the shared lab
is counted once (see [Where files go](structure.md)).

## 3. The three streams of a run

| File | Written by | What it holds | Who reads it |
|---|---|---|---|
| `ground_truth.jsonl` | the host only: attack drivers, fault injection, the scenario | what really happened: `run_meta`, attack steps, writes, blocks, faults, `run_end` | scorers, dataset builders. Never readable by a defender. |
| `<node>.telemetry.jsonl` | defense components in the guests (`mtd_telemetry.py`) | what the defenders observed and did: findings, alerts, MTD actions, delivery gaps | detectors, the responder, metrics |
| `progress.jsonl` | the host ledger (`cyberrange/core/progress.py`) | the run as it happens: lifecycle, campaign bookkeeping, a live mirror of the telemetry | the dashboard |

The separation is deliberate. A detector or a response policy can only be
scored against information it could not have had.

Event kinds common to every scenario are documented in
`cyberrange/core/streams.py`: the lifecycle (`run_start`, `phase`, `run_end`)
and the campaign's bookkeeping. On the progress ledger the core also writes:

- `component_down{component, node}`, once for each watched component found
  dead;
- `run_metrics`, a run's score: by a standalone run on its own ledger, by a
  campaign for each of its runs;
- for a campaign, `run_failed`, `run_skipped` (a run whose earlier result was
  reused), `unit_blocked` (a unit whose `needs` did not succeed) and
  `aggregate_failed`;
- `player_start`, `player_call`, `player_event`, `player_usage` and
  `player_exit`, the transcript of a harness seated by `SeatPlayer` — without
  what a call was asked and gave back, which stays on the transcript.

Scenario-specific kinds are:

- **CPS:** `plant`, `finding`, `alert`, `model_fitted`, `model_error`, `response_write`, `attack_start`, `attack_write`, `attack_plan` (what the tree-guided attacker knows and intends: on the ledger only, never in the ground truth), `plan_step`, `tree_state`, `decision`, `approval`, `action`.
- **CPS advisor:** the CPS kinds — `approval` here is a suggestion put to the operator, then its outcome — plus `soc_mode`, `team_command`, `red_step` and the `player_*` kinds when a harness plays.
- **CPS recon:** the CPS kinds plus `recon` (what each stage of the reconnaissance found) and `attacker_belief` (the tree the attacker has derived).
- **CPS SOC:** the CPS advisor's.
- **MQTT:** `mtd_action`, `data_gap`, `detection`, `detector_alert`.

## 4. Campaigns (`core.campaign`)

A campaign is a list of **units**, run in order on one ledger.

- A **unit** is one configuration × one repetition. Its **steps** run in order, and a failed step stops the rest of the unit. `needs` names units that must have succeeded first.
- A **step** is either in-process (`run(emit)`: a scenario run, bound to the campaign ledger) or a command (`cmd`, e.g. a `make` target).
- A command step may carry a `timeout` in seconds. When it expires the command and everything it started are stopped (interrupted first, so a lab run undeploys itself) and the step fails like any other, which is what lets `retries` take over. The MQTT campaigns set it on their lab steps from `--lab-timeout`; without it a step has no limit.
- `skip_if()` reuses earlier results.
- A **scored** step (`run_dir` + `metrics`) gets `metrics.json`, which is also what `--resume` skips on, and is folded into the aggregate after every run.
- A campaign's command line ends in `core.campaign.run_cli(campaign)`, which checks once that a lab can start, runs the units, prints the verdict and returns the exit code: `0` when every unit finished, `1` when one failed or was blocked, `EXIT_NO_LAB` (4) when no lab could start. A scenario's `campaign.py` builds the units and handles `--dry-run` itself; everything after that is shared. `epilogue=` adds the scenario's own lines before the verdict (the MQTT evaluation lists its figures).
- `core.aggregate.summarize` gives n / mean / std / 95% CI (Student t) / median / min / max of every numeric metric per group. It writes `ci.csv` and a mean [CI] table in `summary.md`.

| Campaign | Units | Steps |
|---|---|---|
| CPS (`make cps-campaign`, `cyberrange/scenarios/cps/campaign.py`) | modes × seeds | one scored scenario run each. Every option of the CPS scenario passes through, e.g. `--respond solver --it-telemetry --attack-driver planner`. |
| MQTT MTD evaluation (`main.py`, `cyberrange/scenarios/mqtt_mtd/campaign.py`) | baseline + three MTD configs + figures, × runs | the same `make` targets as `scripts/run_single.sh`, with lab steps retried. Every config needs its run's baseline (cross-model attack); the figures need all four. The ledger and summary are in `output/campaigns/paper-mbps<M>/`. |
| Harness benchmark (`make cps-bench`, `cyberrange/scenarios/cps_advisor/campaign.py`) | harness × side × opponent × seed | one scored `cps-advisor` game each, a harness at one seat and a graded scripted opponent at the other; beside `ci.csv`, the aggregate writes the columns that matter for each side in `harness.csv`. See [Harnesses as players](playing-with-agents.md#7-benchmarking-harnesses). |
| MTD ablation (`make sweep`, `cyberrange/scenarios/mqtt_mtd/ablation.py`) | 15 named MTD configurations in five groups (e0–e4), no seeds | the evaluation's `make` steps per configuration, plus its entropy and its row of the manifest; a last unit draws the figures with `plot_sweep` from the configurations that finished. |

## 5. Following it live

[The dashboard](dashboard.md) is the guide to using it: how to start it, what
the page shows, the time bar, what each scenario adds. This section is for
whoever changes it or writes a scenario's panel.

`cyberrange/core/dashboard.py` only reads: the server has no endpoint that
changes anything, in the lab or on disk.

The page loads nothing from another host, so it works where a lab machine has
no internet access. Its libraries are files of this repository, under
`cyberrange/core/vendor/` and served at `/vendor/<file>`: **D3** (the attack
tree's layout, the links, zoom and pan on the structure views), **Observable
Plot** (every chart), **Split.js** (the widths of the page's columns, dragged by
their handles) and **Tabulator** (a list that may run to thousands of rows: only
the rows in sight are drawn). `VENDOR.json` there pins each one by version and
SHA-256, and is the route's whitelist; `tests/core/test_dashboard.py` fails if a
file is not the release the manifest names, if the page loads a script or a
stylesheet that is not listed, or if a vendored stylesheet fetches anything
itself. To update one, replace the file with the release's own build and record
its version, source and checksum in the manifest.

**How the page is laid out.** A band at the top stays in sight while the page
scrolls: the experiment chosen, its state, and the time bar. Under it, three
columns:

- on the left the **runs** of the experiment;
- in the middle the **views**, as tabs: each holds the sections that answer one
  question. A scenario's panel composes its own (`views`, below); without, the
  page has two, *Run* and *Campaign*. A section with nothing to show is left
  out, and so is a tab whose sections all are. The view chosen is in the
  address (`?show=<id>`);
- on the right what a panel **docks** beside the views (a card with
  `dock: "side"`): in sight whichever tab is chosen.

The page's own sections, common to every scenario, are the ones a view names:
the tiles, the run table, the selected run's detail, its results, the structure
views, and the cards of the people in a lab. Two things about them bind a
panel:

- a run's results list every metric it recorded, opening on the ones the panel
  names (`labels.metrics`) and filtered by the panel's kinds (`labels.kinds`).
  The keys are the ones a campaign aggregates under (`core/aggregate.py`), so a
  figure there and its mean in *Campaign* are the same metric;
- every time-aware view — the structure views and the panel's cards — is drawn
  as of the time the bar shows. `marks` (below) are the facts its ◀ ▶ step
  through.

Each section is drawn on its own: one that throws shows its error in its card
and the others are drawn as usual, and an event the page cannot fold is skipped
rather than stalling the ledger.

**The server.** `python -m cyberrange.core.dashboard --root output --port 8765`
is what `make dashboard` runs; `--scenario <name>` shows only that scenario's
runs and campaigns, and `--host` (default `127.0.0.1`) is the address it binds.
Every route is a `GET`:

| Route | Answers |
|---|---|
| `/` | The page, `dashboard.html`. |
| `/graph.js` | Every registered scenario's `panel.js`, concatenated into one script. |
| `/vendor/<file>` | A vendored library. Only the files `VENDOR.json` lists, `.js` and `.css`; served with a year-long `immutable` cache, since the page asks for it under a versioned URL. |
| `/api/ledgers` | `{root, now, ledgers}`: one summary per ledger found under the root, with its scenario and status, running ones first. |
| `/api/events?id=&since=&limit=` | One page of a ledger (below). |
| `/api/structure?id=&run=` | `{source, kg, tree}` of a run: its recorded `kg.json` and `tree.json`, or the ones `Scenario.structure()` rebuilds for a run recorded without them. |
| `/api/trajectories?id=&run=` | `{trajectories: {team: document}}` of a run: every `trajectory-<team>.json` in its directory, by team. Empty for a run that kept none; a document that cannot be read is left out. |

**How a ledger reaches the page.** `GET /api/events?id=&since=&limit=` answers
`{gen, next, total, events}`: one page of the events with `seq >= since`.
`next` is the `seq` to ask for next and `total` the `seq` after the last event,
so a long ledger is read page by page until `next` reaches `total`. `gen` names
the file's incarnation: when it changes (the ledger was replaced or cut short)
the page drops what it had folded and starts over. The answers are strict JSON:
a NaN in a ledger or a structure file is served as `null`, since a browser
rejects it. The root is walked for new ledgers at most every
`ledgers.DISCOVER_TTL_S`; asking for an id nobody has seen forces a walk.

**A fact is the event whole.** The page's reducer (`apply()` in
`dashboard.html`) keeps each event it lists as the ledger recorded it, with `t`
set to the time the fact happened (`guest_t`, `frame_t` or `write_t` when the
event carries one; the ledger's own `t`, when the host heard of it, stays as
`heard_t`). A view therefore reads any field a component records, without the
reducer having to name it. `FACTS` in the page lists the kinds kept this way and
the list of the run each goes to (`plant`, `findings`, `writes`, `states`,
`decisions`, `actions`, `alerts`, `mtd`, `gaps`, `detections`).

A ledger that is open keeps its file's modification time fresh
(`progress.HEARTBEAT_S`), so a campaign busy in a step that emits nothing is
still shown as running; one whose writer died turns "interrupted" after
`ledgers.STALE_S`.

**Per scenario**, drawn by the scenario's `panel.js` and not by the page. The
page calls the panel's factory once with its helpers; every panel is served in
one script, so a panel uses only these and its own names, never another
panel's. The helpers:

| helper | what it is for |
|---|---|
| `h`, `svg`, `$` | build an HTML or SVG element, find one by id |
| `num`, `dur`, `clock`, `rel(t, t0)`, `pretty` | a number, a duration, a wall-clock time (with its date when not today's), a time as an offset from an origin, an identifier spelled as words |
| `metric(key)`, `metricHead(m)` | a metric as `{label, unit, help}`: the panel's own words (`labels.metrics`), else the key spelled out and the unit read off its suffix (`_s`, `_pu`, `_kw`, `_rate`) |
| `term(id, label?, help?)`, `termText(id, label?)` | a recorded identifier shown by its name (the caller's, else `labels.terms`), the identifier on hover |
| `table(heads, rows, none)`, `empty(why)`, `queueTable` | a table with headers that explain themselves, a box that says why it is empty, the shared run table |
| `grid(box, options)` | a long list, drawn by Tabulator (`options` are its own: `index`, `columns`, `data`, …) in the page's type and theme; `list.keepPlace(change)` applies a change to the data and leaves the row the reader was on where it was |
| `plot(options)`, `plotTip(data, …)`, `timeAxis(span, since)` | an Observable Plot chart in the page's type and theme, its tooltip, a time axis in one unit that names its origin |
| `structure(run)` | the run's recorded knowledge graph and attack tree, or `null` while they load (the page draws again when they arrive): it is where the names of the tree's steps and countermeasures come from |
| `trajectories(run)` | `{team: document}`, what each player at a seat did step by step (`trajectory-<team>.json`), or `null` for a run that kept none. They are written when the run is scored, so the page asks only then, once, and draws again when they arrive |
| `time()`, `setTime(t)`, `view()`, `render()`, `select(id)`, `S` | the time shown and the view chosen, and the page's state |

A panel never shows a recorded identifier where it has a name for it: a reader
of the page does not know that `block_flow` is a countermeasure or what
`detectors.combined.latency_from_write_s` measures. A time relative to
something says to what (*since run start*, *since attack start*), in the
column's header or the axis's label.

The hooks, all optional:

| hook | what the panel does with it |
|---|---|
| `queue()` | its columns of the run table, through `ui.queueTable` |
| `detail(run)` | chips, chart and table of the selected run |
| `chart(run)` | the selected run's chart |
| `reduce(run, ev)` | folds the event kinds only it knows into `run.x`, and returns `true` for a kind it took (a kind nobody takes is listed at the foot of the page) |
| `cards: [{id, title, sub, help?, span?, dock?, live?, render(box, run, t)}]` | cards of its own, drawn as of the time bar's `t` (`null` = live); `help` is what its ⓘ says, `span` its width in twelfths of the view; `dock: "side"` puts the card in the column beside the views instead of in one of them; `live(run)` says whether the card has anything to show for a run, and one that answers no is left out as an empty page section is (without it the card is shown for every run) |
| `views: [{id, label, help, sections, options?}]` | the page's tabs, the first being the one it opens on: `sections` lists, in order, the page's sections (`tiles-card`, `runs-card`, `detail`, `score-card`, `graph-card`, `op-card`, `teams-card`, `results-card`) and its own cards (`card-<id>`) that the view shows; `options` sets graph switches on entering it. Every section and every card that is not docked must be in some view, or no tab leads to it |
| `graph: {index, overlayAt, marks, drawTopology, drawKG, drawTree, options?, origin?}` | the structure views; `marks(run)` are the time bar's stops, `options` its switches (`{id, label, view?, default}` a check box, with `choices: [{id, label}]` a row of buttons), `origin(run)` the time the bar counts from |
| `results: {tabs: [{id, label}], render(tab, aggregate, table)}` | its tabs next to the mean [95% CI] one; `aggregate` is the campaign's `aggregate` event whole |
| `labels: {metrics, kinds, terms, mode}` | its words: `metrics[key] = {label, unit, help}` for each metric it reports, `kinds: [{id, label, help, has(key)}]` what its metrics are about (the first whose `has` takes a key is its kind; a run's results are filtered by them), `terms[id]` the name of an identifier it records, `mode(mode, run)` a run's mode as a sentence |

`tests/core/test_panels.py` checks the contract (a view lists only sections that
exist, nothing is left out of every view, a docked card is in none, every
headline metric of a campaign has a label and a unit) and draws
runs through every hook of every panel, each card under every view and the
attack tree from every perspective. It runs under node with the page's own
reducer and helpers (the `data-part="model"` script of `dashboard.html`) and
its own libraries, and builds each run by folding ledger events, shaped as the
components write them, through `apply()`: a run built by hand would hold what
its author believes the reducer keeps. Charts are drawn for real. The two
libraries that lay out in a real window (`browser_only` in `VENDOR.json`) are
not loaded there: the harness has a stand-in for Tabulator that keeps a list's
data as its calls do, so a check can tell a list added to from one built again.

- **CPS:** six views — *Match*, *Structure*, *Attacker*, *Defender*, *Players*
  and *Campaign* — and the journal docked beside them (below); the plant
  voltage chart, findings and score; the **Attacker · Defender**
  card — what each side is doing and what it can see (the attacker from its own
  record: steps, plans, recon, observations; the defender from its telemetry,
  belief and decisions), a lane timeline of both sides and the plant, and a
  truth-vs-belief table per attack step; and the topology, knowledge graph and
  attack tree, the tree carrying both the defender's belief and the attacker's
  progress. Its results add four tabs: detection, physical impact, response and
  countermeasures.
- **CPS advisor:** the CPS panel (its `panel.js` delegates to it), with one more
  results tab, *Harnesses*: the table of a harness benchmark, one row per
  harness, side and opponent.
- **CPS SOC:** the CPS panel, whole: a `cps-soc` run puts the same events on
  the ledger. The blue team's own screens are Wazuh's and DFIR-IRIS's, outside
  the dashboard ([CPS SOC](scenario-cps-soc.md)).
- **CPS recon:** the CPS panel, with the attack tree framing the real nodes the
  attacker does not know (from the belief tree it puts on the ledger) and naming
  the ones it believes in that are not real.
- **MQTT:** the defence's changes on a timeline, one lane per thing it moves
  (broker address and port, client source address, message padding, publish
  timing) coloured by outcome, the delivery gaps, and the table of its actions.

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
lab ([CPS advisor](scenario-cps-advisor.md), [CPS SOC](scenario-cps-soc.md)). A team does not act
through the platform: each has a console served by its own node — the SOC's
for the defenders, one on the attacker node for a red team — and a web
terminal there. The platform's part is to let them in and keep sight of them:

- `monitor.WebTerminal` serves a shell of a node to a browser; `defense.JumpHost`
  gives the defenders SSH from their node to the hosts they manage;
- `monitor.RecordedShell` puts every command typed there on the ledger
  (`team_command`), with the team read from how the shell got onto the node —
  a referee's own shell is `control`, never the attack — and `attack.RedConsole` turns the steps a red team runs into
  ground truth;
- `SeatPlayer` seats a harness at a team's console in place of a person, on a
  node of its own, and mirrors what it does as `player_*` events;
- the page shows the defender's suggestions with their outcome, and a *Teams*
  section (in the CPS panel's *Players* view) with both sides' steps and
  commands.

A team's token never goes on the ledger: the scenario writes the teams' links
to a file in the run directory, on the host.

## 6. Adding a scenario: checklist

[Creating a scenario](new-scenario.md) has the steps in full, as a checklist
and as an interactive guide that writes the scenario's skeleton from your
answers. In short, a scenario is:

- **an image and guest code**: an existing node image or a new
  `docker/<image>/Dockerfile`; agents under `cyberrange/planes/<plane>/agents/`
  or a tool's configuration under `nodes/<tool>/`, listed in the scenario's
  `guest_files.py`;
- **components** for whatever the existing ones do not cover
  ([Components §8](components.md#8-writing-a-new-component)). A component never
  imports a scenario: it takes what is specific as a constructor argument;
- **a package** `cyberrange/scenarios/<name>/` — topology, `Scenario` subclass,
  `cli.py`, `guest_files.py`, `metrics.py`, `SOURCES` and `GUEST_MANIFESTS` —
  registered in `cyberrange/core/registry.py`;
- **what lives outside the package**: its `make` targets, its rows in the
  guardrails' tables, its snapshot, its tests, its page in the documentation.

A scenario that is the CPS lab with something added is a `Feature` instead
([above](#a-scenario-built-on-another)).
