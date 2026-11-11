---
name: cyberrange-scenario
description: "Write or change a scenario of this cyber range: the Scenario contract, the declarative Topology, episode phases, the cli.py entry point, the registry entry and the SOURCES/GUEST_MANIFESTS accounting. Use when: adding a scenario under cyberrange/scenarios/, editing scenario.py or topology.py of mqtt-mtd or cps, adding a node, link, address, route or zone to a lab, changing an episode's phases, options or validation, registering a scenario name, or deciding whether a new file belongs to core, a plane or a scenario."
argument-hint: "What the scenario should do: nodes and zones, what runs on them, the episode's phases, what it must measure"
user-invocable: true
---

# Writing a scenario

A scenario declares **what an experiment is**; the platform runs it. You write a
topology as data, an episode that starts components and drives phases, and a few
hooks. The core does the rest: ledger, deploy, artifacts, undeploy, exit code.

## Scope / Not this skill

| This skill | Elsewhere |
|---|---|
| The scenario package: topology, episode, phases, CLI, registry, `SOURCES` | — |
| Which node receives a deploy manifest | What is *inside* a manifest, and guest-side code → **cyberrange-components** |
| `Scenario.metrics` as a contract member | Writing the metric itself → **cyberrange-runs-and-metrics** |
| Declaring the lab | Running it → **cyberrange-runs-and-metrics** |

**Do not hand-write `lab.conf` or `.startup` files.** In this repo they are
*generated output* (`make lab-conf SCENARIO=<name>`), not inputs. Do not drive
Kathará directly either: a scenario never calls `Kathara.get_instance()`, it
declares a `Topology` and lets `core.lifecycle.run` deploy it. The `kathara-api`
and `kathara-lab-creation` skills are for generic Kathará repositories and for
the adapter inside `cyberrange/core/topology.py` — not for scenario work here.

## Read first

- `cyberrange/core/scenario.py` — the contract, as a docstring. Every member is
  listed there with one line of purpose.
- `docs/platform.md` §2 "Writing a scenario: the contract" (member-by-member
  table) and §6 "Adding a scenario: checklist".
- `docs/structure.md` — what belongs to a scenario versus a plane.
- The closest existing scenario: `cyberrange/scenarios/cps/` is the smaller one,
  `cyberrange/scenarios/mqtt_mtd/` the one with campaigns, analysis and training.

## What a scenario owns

Everything specific to one experiment, in one directory:

```
cyberrange/scenarios/<name>/
  __init__.py      docstring + SOURCES + GUEST_MANIFESTS (the code-size accounting)
  topology.py      the lab as data: Node, Iface, Route, zones, addresses
  scenario.py      the Scenario subclass: options, phases, episode, hooks
  cli.py           three lines wrapping core.cli.main
  guest_files.py   which files each node is staged with
  metrics.py       compute_metrics(run_dir) -> flat dict
  campaign.py      optional: repetitions, grids, resume
  analysis/        optional: figures from finished runs
  training/        optional: offline model training
```

What it does **not** own: anything a second scenario could reuse. That belongs to
a plane, even when only this scenario uses it today (the test is blunt: if a
`components.py` imports it, it is the plane's).

## Procedure

### 1) Declare the topology, do not build a lab

`topology.py` returns a `Topology` of `Node`s. Interface order fixes `eth0`,
`eth1`, …; links are named collision domains; `files=` attaches a manifest.

```python
Topology("cps", default_image="kathara/cps", nodes=[
    Node("hmi", [Iface("IT", "10.10.0.20/24")], role="hmi",
         routes=[Route("default", "10.10.0.1", "eth0")], files=HMI_FILES),
    Node("sensor", [Iface("OT", promisc=True), Iface("DEF", "10.30.0.10/24")],
         role="sensor", files=SENSOR_FILES, mgmt_port="8090:8080/tcp"),
])
```

Why data and not calls: the same declaration becomes the deployed lab, the
`topology.json` recorded with every run, the `lab.conf` export, and the SOAR
knowledge graph. One description, four consumers.

### 2) Subclass `Scenario`

Set `name` and `lab_name` (the Kathará lab name — **a deploy replaces a lab with
the same name**, so two scenarios must not share one). Implement `topology`,
`episode_phases`, `episode`; override `add_arguments`, `validate`, `run_info`,
`out_dir`, `check_run`, `metrics` as needed. Read the docstring in
`cyberrange/core/scenario.py` rather than this file for the full list.

Phases drive the progress ETA: `PhaseSpec(name, planned_s, timed=True)` for a
fixed-length observation, `timed=False` for best-effort setup.

### 3) Write the episode

`episode(ctx)` starts components and walks the phases:

```python
def episode(self, ctx):
    ctx.start(traffic.PhysicalProcess("engine", T.MODBUS_PORT, a.step_interval,
                                      seed=ctx.role_seed("engine")))
    with ctx.phase("normal", learn_s=a.learn_seconds):
        ctx.observe(a.normal_duration)
```

Rules that matter here: **every component whose behaviour is random takes
`seed=ctx.role_seed("<role>")`**, which derives a distinct, reproducible seed per
role from the run seed (a deterministic observer like the DPI sensor needs none);
use `ctx.phase` so the ledger and the dashboard see the structure; use
`ctx.observe` to wait on a deadline while components are polled, and `ctx.live()`
when blocking on a guest command.

### 4) Add the CLI

`cli.py` is three lines. It exists so the scenario has a `-m` entry point:

```python
def main(argv=None):
    cli.main(CpsScenario(), argv, description="Cyber-physical OT/Modbus scenario")
```

### 5) List the guest files

`guest_files.py` holds one constant per node, each a list of
`(host_path, guest_path)`. Changing a host path is free; a guest path is a
contract. Details in **cyberrange-components**.

### 6) Declare what the scenario is made of

In `__init__.py`:

```python
SOURCES = {
    "scenario (topology, episode, CLI, campaign, metrics, manifest)": [
        "cyberrange/scenarios/<name>/*.py"],
    "analysis & paper figures": ["cyberrange/scenarios/<name>/analysis/*.py"],
}
GUEST_MANIFESTS = ("ENGINE_FILES", "PLC_FILES", ...)
```

**Keep the categories disjoint** — one directory each. `make platform-loc` sums
every category independently, so a file matched by two patterns is counted twice
and the paper's "cost of a scenario" table overstates it. A pattern that matches
nothing is worse: it fails silently and the code disappears from the table.

### 7) Register it

`cyberrange/core/registry.py` maps a name to a module path *as a string*, imported
lazily so listing one scenario never imports another's dependencies:

```python
SCENARIOS = {"cps": "cyberrange.scenarios.cps.scenario:CpsScenario"}
```

### 8) Test it without Docker

`tests/scenarios/<name>/test_<name>_scenario.py`, using `tests/helpers/kathara.py`:
`FakeManager` records every command and serves canned output, `fake_downloads`
serves artifacts. The whole lifecycle runs — commands, artifacts, ledger, ground
truth, exit code — with no containers. See `tests/core/test_progress.py` and
`tests/scenarios/mqtt_mtd/test_mqtt_scenario.py` for the pattern.

## Decision branches

- **Changing an existing scenario?** Steps 1–3 only, plus step 6 if you added a
  file. Check `make lab-conf SCENARIO=<name>` output before and after: if the
  guest column or a `.startup` changed and you did not mean it,
  `tests/core/test_deploy_contract.py` will stop you.
- **The change needs a new component or guest agent?** Stop here and use
  **cyberrange-components**; come back for the wiring.
- **The scenario wants its own dashboard panel?** Implement `panel_js()` and
  `structure()` (see `cyberrange/core/scenario.py`); the dashboard asks the
  registry. Never make the dashboard import your scenario.
- **The code is useful to a second scenario?** It belongs in a plane, not here.

## Common pitfalls

- **Reusing a `lab_name`.** Deploying replaces the lab with that name, silently
  tearing down someone else's run.
- **Scenario logic drifting into a plane.** It starts as a lazy import inside a
  method "just to make it work" and passes every test except
  `tests/core/test_layering.py`. Take the dependency as a constructor argument.
- **Forgetting `ctx.role_seed` on a component that is random.** Nothing fails; the run is simply not
  reproducible, which is the worst defect a paper can have.
- **A `SOURCES` glob left behind after moving a file.** `glob` returns `[]`, no
  error, and the scenario looks cheaper than it is.
- **Phases that lie.** `planned_s` feeds the ETA on the dashboard; a phase
  declared `timed=True` is expected to last exactly that long.

## Completion criteria

```sh
make lab-conf SCENARIO=<name>      # renders the lab offline; read what it staged
.venv/bin/python -m pytest tests -q
make platform-loc                  # your scenario appears, totals move as expected
```

The scenario is done when: it is listed by `python -m cyberrange.core scenarios`,
one run writes `topology.json`, `ground_truth.jsonl` and `progress.jsonl` into its
output directory, `check_run` returns non-zero on a run that produced nothing, and
`metrics(run_dir)` returns a flat numeric dict a campaign can average.
