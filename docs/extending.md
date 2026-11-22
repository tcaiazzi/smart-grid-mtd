# Extending the platform

How to add to the cyber range without breaking it. This is a map, not a tutorial:
the reference is [Architecture](platform.md) (the scenario contract),
[Components](components.md) (every building block) and [Where files go](structure.md)
(the layering). The rules and the guardrails are in [Contributing](contributing.md).

## The rules that are not negotiable

There are eight, each enforced by a test; [Contributing](contributing.md#the-rules-that-are-not-negotiable)
is the list. The ones an extension meets first:

- **One-way imports** — `core ← planes ← scenarios`. A plane must not import a
  scenario: pass the scenario-specific part in as a constructor argument.
- **Guest paths are a contract** — a guest filename (`/ot_registers.py`) keeps
  its name forever, while the host file it comes from may live anywhere.
- **Guest imports** — guest code imports only the standard library and what its
  node image installs, never `cyberrange.*`.
- **Node software is not the platform** — what a node does at run time lives
  under `nodes/`; prefer an existing open-source tool to code of your own.
- **Names are internal API** — `make` targets and `-m` module paths are not
  renamed.

## Adding a component

A component belongs to one plane and lives in that plane's `components.py`
(`cyberrange/planes/<plane>/components.py`):

- **traffic** — what generates load or drives the physical process;
- **attack** — what attacks;
- **defense** — what detects and responds;
- **monitor** — what observes and records.

A component that launches guest code (a `GuestAgent`) ships a flat script under the
plane's `agents/` directory; the scenario that uses it lists that script in its
`guest_files.py`. Keep the component scenario-agnostic — anything scenario-specific
is a constructor argument.

[Writing a new component](components.md#8-writing-a-new-component) is the
procedure, step by step; the rest of [Components](components.md) has the hooks
(`artifacts`, `poll`, `mirror`, telemetry) and every existing component to reuse.

## Adding a scenario

One scenario is one directory, whole: `cyberrange/scenarios/<name>/` holds its
topology, episode, CLI, campaign, deploy manifest, metrics, and its `analysis/` and
`training/`. A scenario:

1. declares its lab as a **declarative `Topology`** (nodes, links, addresses,
   routes, zones) in `topology.py`;
2. composes **plane components** into the phases of its **episode**;
3. exposes a `cli.py` entry point and registers its name in the scenario registry;
4. accounts for its code in `SOURCES` (so `make platform-loc` stays honest) and for
   its staged files in `guest_files.py`.

[Creating a scenario](new-scenario.md) has the whole checklist, including the
edits a scenario needs outside its own directory, and the interactive guide that
writes the skeleton. [Architecture](platform.md) is the full contract.

## Adding to the CPS family

A new CPS experiment is mostly data, not code:

- **A different lab** is a `LabSpec` (`cyberrange/scenarios/cps/lab.py`): zones,
  hosts by role with their interfaces and services, the flows the boundary
  forwards. Addresses, routes, the firewall, the Wazuh agents and the SOC's
  inventory follow; the spec refuses a lab that breaks what the rest relies on.
  Return it from `lab_spec(args)`.
- **A different plant** is a description for `ot_registers.plant()`: feeders,
  each a Modbus unit, with their lines, load and generator. Return it from
  `plant_spec(args)`; bind each PLC and HMI to its feeder with `Host.unit`.
- **The attack tree and the countermeasures** follow from the graph
  (`nodes/common/attack_graph.py`). A new kind of impact is one entry in
  `nodes/common/techniques.py`, plus the places that name it by kind
  ([SOAR — KG & attack trees](kg-and-attack-trees.md) §9).
- **Something added to the run** — people, tools, another attacker — is a
  `Feature` (`cyberrange/scenarios/cps/feature.py`) in the new scenario's own
  directory. The scenario is `CpsScenario` with a tuple of features; existing
  ones (`People`, `SocTools`, `Recon`) compose with it.

## Adding a metric or a figure

A scenario's `metrics.py` exposes `compute_metrics(run_dir) -> dict`, returned by
`Scenario.metrics`. A campaign calls it when a scored run ends, stores the result
in `<run_dir>/metrics.json` and folds it into the aggregate.

- **Return numbers.** The aggregate flattens nested dicts into `a.b.c` keys and
  counts a boolean as 0 or 1, so that it averages into a rate. Every other leaf —
  a string, a list — is dropped without an error and never reaches `summary.md`
  or `ci.csv`.
- **A missing value is `None`**, and is left out of that metric's `n`: a latency
  is then averaged over the runs that detected. Say so in the metric's name.
- **Read the run's artifacts, never a live lab.** Scoring must be repeatable on
  a finished directory ([what a run leaves behind](running-and-metrics.md#what-a-run-leaves-behind)).
- A CPS variant is scored by the `cps` metrics: what it adds to the score goes
  in `cyberrange/scenarios/cps/metrics.py`, computed from the artifact the variant
  writes and absent from a run without it (`tree_fidelity` for `cps-recon`).

A figure lives in the scenario's `analysis/` directory and reads finished runs
under `output/`: offline code, with no Kathará and no containers. Give the module
a `main()`, name it once through an `M_*` variable in `make/common.mk`, and add a
make target for it (below). `cyberrange/scenarios/mqtt_mtd/analysis/` is the
example.

## Adding a dashboard panel

A scenario's panel is a `panel.js` in its own directory, returned by
`Scenario.panel_js()`; the dashboard asks the registry for it and never imports
a scenario. [Architecture §5](platform.md#5-following-it-live) lists the hooks a
panel implements and the helpers it is given. A variant's panel can show the
`cps` one and add to it, as `cyberrange/scenarios/cps_recon/panel.js` does.
`tests/core/test_panels.py` draws every panel on a recorded run: when a
component gains a field a view should show, add it to the events in
`tests/core/panel_draw_harness.js`. List the file under a `SOURCES` category of
its own.

## Adding a make target

Targets live in `make/<scenario>.mk` (`make/common.mk` for the platform's own).
For a new one:

1. write the rule, with a `## description` after its name;
2. name any module it runs through an `M_*` variable in `make/common.mk`, never
   inline;
3. add the target to `.PHONY` and to the `help` text in the `Makefile`;
4. bring the scenario guide's copy of the targets along
   (`UPDATE_GUIDE_CONTRACT=1`, see [Contributing](contributing.md#regenerating-on-purpose)).

`tests/core/test_entry_points.py` checks every module and target that `make -n`
prints, and `make check` dry-runs them all. An existing target is never renamed:
campaigns shell out to it.

## Adding or changing a node image

An image is `docker/<image>/Dockerfile`, built by a `<scenario>-image` target.
Every Python package it installs is pinned to the version in `requirements.txt`,
so that the guest runs what the host tested; `tests/core/test_guest_imports.py`
fails on an unpinned or diverging package, and checks each guest module's
imports against the image of the node it is staged on. A node on a new image
needs its entry in that test's `MACHINES` and `IMAGE_OF` tables. A system tool an
agent relies on (tcpdump, nmap, a Wazuh agent) is the image's to install, and no
test checks it: only a real run does.

## Adding a harness

A harness that plays a team's seat is a launcher under `nodes/players/`, an image
under `docker/player-<name>/` and an entry in
`cyberrange/scenarios/cps_advisor/harnesses.py`.
[Harnesses as players §6](playing-with-agents.md#6-adding-a-harness) has the
launcher's contract.

## The gate before a change is done

```bash
make fmt          # ruff format: layout only, never logic
make check        # lint, the whole suite (no Kathará, no Docker), and a dry run of every target
```

The dry run is there because campaigns shell out to the targets: one that no
longer expands is found otherwise hours into a run. Some of the suite's tests
are deliberate tripwires — frozen snapshots, layering and entry-point checks, a
floor on the number of tests. **Never make one green without understanding why
it went red.** [Contributing](contributing.md) says what each one freezes, when
regenerating a snapshot is legitimate, and the style the code follows.
