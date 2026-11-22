# Creating a scenario

**[Open the interactive guide →](scenario-guide.html)**

The guide takes you step by step through adding a scenario and writes its
skeleton from your answers. This page says what the guide does, and gives the
same steps as [a checklist you can read](#the-steps-as-a-checklist) and
[a worked variant](#a-worked-variant-an-attacker-of-its-own), for when you would
rather do it by hand or check what a step is for.

## Before you start

- **Start from a green suite**: `make selftest-fast`. A guardrail that is
  already red will be blamed on your scenario.
- **Read the contract**: [Architecture §2](platform.md#2-writing-a-scenario-the-contract).
- **Node.js** is needed by the guide's own test
  (`tests/core/test_scenario_guide.py`) and by the panel tests; without it they
  are skipped, not failed, so a green suite says less than it seems.
- **Decide which kind of scenario it is.** The guide asks in its second step:

    - **a lab of its own**, as `mqtt-mtd` has: its own nodes, networks and episode;
    - **a variant of the cps lab**, as `cps-recon`, `cps-advisor` and `cps-soc`
      are: the cps lab and episode, with a `Feature` that adds options, software
      on a host or services.

## What the guide does

You describe the scenario as you go. At each step the guide shows you the file
that step writes, built from your answers, and checks for the mistakes the
repository's guardrails would otherwise catch only later. It flags:

- a name or lab name already in use;
- a `-` in a node name;
- an address used twice on one link;
- a published port on a node whose default route is not replaced;
- a guest module name that is already taken;
- for a variant, a host the cps lab does not have, or an option cps already has;
- a component left without a required argument, or placed on a node whose image
  lacks a package its guest code imports.

While you declare the lab, the guide also shows what Kathará will be given:
`lab.conf` and each node's startup file, as `make lab-conf` renders them.

**Export answers** saves what you entered as `<name>.scenario.json`, and
**Import** loads such a file back. Use it to hand a scenario's design to someone
else, or to keep it next to the work. Your answers and ticks are also saved in
your browser, so you can close the page and pick up where you left off.

At the end you download every new file as one zip and unpack it at the
repository root. The zip also carries `scenario-edits.json`, the edits the
scenario needs in files that already exist: the registry, the make include,
`.PHONY` and help, the guardrail tables and the docs nav. A tool applies them:

```bash
.venv/bin/python tools/apply_scenario_edits.py            # show the diff
.venv/bin/python tools/apply_scenario_edits.py --write    # apply it
```

It writes every edit or none, and skips an edit already made, so you can run it
again. Two things stay yours, because they are deliberate acts: the snapshot
update and `MIN_TESTS`. The tool ends by recalling both, with the commands.

What you get is a skeleton that runs as soon as it is unpacked. For a lab of
its own:

- a `Topology` and a `Scenario` with a best-effort phase and a timed one;
- a placeholder guest agent and its manifest;
- the plane components you chose, started in their phase, with the guest files
  they launch staged on their nodes;
- `SOURCES`, `cli.py`, `metrics.py` and a `make/<name>.mk`;
- if you ask for them, a `campaign.py` (one scored run per seed, resumable)
  and a `panel.js` (a dashboard card with the run's metrics);
- a test that runs the whole lifecycle on the fake lab;
- this site's page for the scenario.

For a variant of the cps lab:

- a `Feature` with the options you declared, a placeholder agent staged on
  the cps host you chose, and the plane components you chose, all started
  with the lab's services;
- a `Scenario` that is `CpsScenario` with that feature;
- a `panel.js` that shows the cps panel, `SOURCES`, `cli.py` and a
  `make/<name>.mk` that reuses the `CPS_*` variables;
- a test of what the variant adds;
- this site's page for the scenario.

`tests/core/test_scenario_guide.py` generates that same skeleton, formats and
lints it, runs its tests and applies its edits to copies of the files they
touch. It renders every step of the page, and compares the page's `lab.conf`
preview with what the platform renders for the same lab. It also checks every
name the guide cites against the code, so the guide stays in step with the
repository.

## The steps as a checklist

The guide's eleven steps, with what each one leaves in the repository. `<name>`
is the scenario's name (`cps-recon`), `<pkg>` its package (`cps_recon`).

1. **Before you start.** The suite is green, the contract is read, and the
   scenario really needs to be one: an option of an existing scenario is
   cheaper than a scenario.
2. **Name it.** Choose `name` and `lab_name`. A deploy replaces a lab with the
   same name, so no other lab on the machine may use it. The dashboard is
   platform code and names no scenario, and `tests/core/test_dashboard.py` fails
   if the name or its first `-`-separated word appears in the dashboard's
   sources: pick a first word that does not. Node names carry no `-`.
3. **Declare the lab.** For a lab of its own, `topology.py` returns a `Topology`
   of `Node`s with their interfaces, addresses, routes and published ports. For
   a variant, check that the cps lab fits, or which hook changes it (`nodes`,
   `lab_spec`). Render it with `make lab-conf SCENARIO=<name>`: `lab.conf` and
   the startup files are output, never written by hand.
4. **Image and guest files.** Reuse an image under `docker/`, or add
   `docker/<image>/Dockerfile` with a `<name>-image` target and every Python
   package pinned to `requirements.txt`. List what each node is staged with in
   `guest_files.py`, one constant per node of `(host path, guest path)` pairs.
   The guest paths are final: other files import them by those names. Where an
   existing open-source tool does a node's job, the image installs it and
   `nodes/` configures it.
5. **Write the episode.** `scenario.py` subclasses `Scenario`: options,
   `episode_phases`, and an `episode(ctx)` that starts components and walks the
   phases. Every component that takes a seed gets `ctx.role_seed("<role>")`;
   each phase's planned length is honest, because the dashboard's ETA is built
   on it; `check_run` returns non-zero for a run with nothing to score. A
   variant puts all it adds in its `Feature` (`feature.py`), and its
   `scenario.py` only lists the feature.
6. **Package and registry.** `__init__.py` declares `SOURCES` (categories
   disjoint, one directory each) and `GUEST_MANIFESTS` (the names of the
   constants in `guest_files.py`). `cli.py` wraps `core.cli.main`, which gives
   the scenario its `-m` entry point. One line in `SCENARIOS`, in
   `cyberrange/core/registry.py`, maps the name to the class. Then
   `.venv/bin/python -m cyberrange.core scenarios` lists it and
   `make platform-loc` counts its files.
7. **Score a run.** `metrics.py` exposes `compute_metrics(run_dir)`, a flat dict
   of numbers computed from the run directory alone
   ([Adding a metric](extending.md#adding-a-metric-or-a-figure)). A variant is
   scored by the cps metrics.
8. **Make targets.** `make/<name>.mk` holds the targets; the module they run is
   named once, as an `M_*` variable in `make/common.mk`. In the `Makefile`: an
   `include make/<name>.mk` line, the targets in `.PHONY`, and a line each in
   the `help` text. `make -n <name>` prints the run command and `make help`
   lists the targets.
9. **Tests and guardrails.**
    - The scenario's own tests go in `tests/scenarios/<pkg>/` and run the whole
      lifecycle on the fake lab (`tests/helpers/kathara.py`).
    - Two tables name every scenario and must learn the new one: the list of
      registered names in `tests/core/test_core.py`, and `MACHINES` and
      `IMAGE_OF` in `tests/core/test_guest_imports.py`, which say what each node
      is staged with and on which image.
    - Regenerate the snapshots, on purpose: a new `tests/snapshots/lab-<name>.json`,
      and `tests/snapshots/loc-totals.json` with a new key for the scenario and
      `platform` one line larger (the registry entry).

        ```bash
        UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/core/test_deploy_contract.py -q
        UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/core/test_loc_coverage.py -q
        ```

      Read the diff: if another lab's snapshot or another key moved, something
      else changed, and you should find out what before committing.
    - Raise `MIN_TESTS` in `tests/conftest.py` by the number of tests added.
    - Bring the guide's own copy of the repository along
      ([below](#when-the-repository-changes)).
10. **Verify and run.** `make lab-conf SCENARIO=<name>` renders the lab you
    expect; `make check` passes; and a real run deploys, goes through its
    phases, writes its artifacts and undeploys. Only the real run proves what
    the containers receive.
11. **Document.** The scenario gets a page, `docs/scenario-<name>.md`, and an
    entry under *Scenarios* in the `nav` of `mkdocs.yml`. Run `make fmt` and
    commit on a branch.

If you used the guide, `tools/apply_scenario_edits.py` makes the edits of steps
6, 8, 9 (the two tables) and 11 (the nav) for you; the snapshots and `MIN_TESTS`
stay yours either way. [Contributing](contributing.md) explains the guardrails
these steps keep green.

## A worked variant: an attacker of its own

`cps-recon` is the cps lab with an attacker that derives its attack tree by
reconnaissance instead of being handed it. It is the smallest scenario in the
repository, and shows what a variant with more than options is made of.

**The package**, `cyberrange/scenarios/cps_recon/`:

| File | What it holds |
|---|---|
| `feature.py` | `Recon(Feature)`, with three hooks. `add_arguments` adds `--it-cidr` and `--scan-ports`. `extras` gives the attacker's node more guest files and another image (`kathara/redteam`), leaving every other node as cps has it. `attacker` returns the component that drives the attack, `attack.ReconAttacker`, in place of the cps one. |
| `scenario.py` | `CpsReconScenario(CpsScenario)`: `name`, `lab_name`, `features = (Recon(),)` and `panel_js`. Nothing else: the episode is the cps one. |
| `cli.py` | `main()` wrapping `core.cli.main`, so that `-m cyberrange.scenarios.cps_recon.cli` runs it. |
| `guest_files.py` | `RECON_FILES`: only what the variant adds to the attacker's node. The rest of the lab is staged by the cps manifests. |
| `panel.js` | The cps panel, with the attacker's belief drawn on the attack tree. |
| `__init__.py` | `SOURCES`, listing this directory only so that the shared lab is counted once, and `GUEST_MANIFESTS = ("RECON_FILES",)`. |

**Outside the package:**

- the attacker's software, `nodes/redteam/recon.py`, `belief_tree.py` and
  `red_recon_agent.py`: node software, so under `nodes/` and importing only the
  standard library and what the image installs;
- the image, `docker/redteam/Dockerfile` (nmap), built by `cps-recon-image`;
- the component, `ReconAttacker` in `cyberrange/planes/attack/components.py`. It
  takes the scan scope as arguments and knows nothing of this scenario;
- `make/cps-recon.mk`, which reuses the `CPS_*` variables, with
  `M_CPS_RECON_RUN` in `make/common.mk` and the include, `.PHONY` and help lines
  in the `Makefile`;
- the `cps-recon` line in `cyberrange/core/registry.py`;
- `tests/scenarios/cps_recon/`, the name in `tests/core/test_core.py`, the
  `attacker_recon` rows in `tests/core/test_guest_imports.py`, and
  `tests/snapshots/lab-cps-recon.json`;
- what the variant adds to the score, `tree_fidelity`, in
  `cyberrange/scenarios/cps/metrics.py`: computed from the belief tree the
  attacker leaves, and absent from a run without one;
- its page, [CPS recon](scenario-cps-recon.md), and its `nav` entry.

The rule that shapes all of it: the base must not know the variant exists. When
a variant needs something the cps scenario cannot yet be told, add a hook to
`Feature` (`cyberrange/scenarios/cps/feature.py`) rather than a test on the
scenario's name. [Architecture §2](platform.md#a-scenario-built-on-another)
lists the hooks.

## When the repository changes

The guide carries a copy of some facts of the repository: the scenario and lab
names in use, the make targets, the guest modules, and what each node image
installs. Adding a scenario, a target, a guest module or a package to an image
makes that copy stale, and the test above goes red until the guide is brought
along:

```bash
UPDATE_GUIDE_CONTRACT=1 .venv/bin/python -m pytest tests/core/test_scenario_guide.py -q
```

The same holds for the plane components, whose constructors and guest files
the guide also copies. That rewrites one block of the page,
`#guide-contract-derived`, from the repository; read the page's diff before committing, as it should show only what
you changed. The switch updates facts and nothing else: if the test is red
because the skeleton no longer runs, the guide's templates need fixing.

## Opening it locally

The guide is a single page, `docs/scenario-guide.html`. You can open it in
either of two ways:

- **from the documentation site:** run `make docs-serve`, then open
  <http://127.0.0.1:8000/scenario-guide.html>;
- **from the file:** open `docs/scenario-guide.html` in a browser.

It loads its libraries (code highlighting, the topology graph, the zip) from a
CDN. Without an internet connection it still works, without highlighting or the
graph, and you save the files one by one instead of as a zip.

## Choosing components

The step that writes the episode (for a variant, the step that says what it
adds) offers every component of `cyberrange/planes/*/components.py`, with its
constructor as it is in the code. You fill in its arguments as Python
expressions, and the guide writes the call, stages the guest files the component
launches together with the modules they import, and checks the packages they
need against the node's image. [Components](components.md) says what each one
does. System tools and configuration a component relies on (tcpdump, ttyd, a
Wazuh agent) are the image's, and the guide does not check them.

## Not covered by the guide

The guide writes a variant's `Feature` with three hooks: options, files on a
host, and services. A variant that brings its own attacker, adds nodes to the
lab, or changes the lab or the plant uses the other hooks, which the guide
explains and points to but does not generate:
[the worked variant above](#a-worked-variant-an-attacker-of-its-own) shows one.
A variant gets no campaign or panel stub: it has the cps ones.
[Extending the platform](extending.md) covers the CPS family, and
[Architecture](platform.md) gives the full scenario contract.
