# Working in this repository

A cyber range for smart-grid security: scenarios run as emulated labs (Kathará
containers), attacks and defenses are composed from reusable plane components,
and every run is seeded, scored and recorded. Three scenarios live here today —
`mqtt-mtd` (the paper's), `cps` (OT/Modbus) and `cps-advisor` (the `cps` lab
with a SOC that advises an operator instead of acting).

```
cyberrange/core/       the platform: topology, lifecycle, context, campaigns, ledger, dashboard
cyberrange/planes/     traffic | attack | defense | monitor — components.py + agents/ (guest code)
cyberrange/scenarios/  mqtt_mtd/, cps/ and cps_advisor/ — one directory per experiment, whole
nodes/                 software of the lab's nodes that is not the platform's (Wazuh set-up, rules, responses)
make/ scripts/ tools/ tests/ docs/
```

## Rules that are not negotiable

1. **Imports point one way: `core ← planes ← scenarios`, and `nodes/` imports
   neither.** A plane that imports a scenario can only ever serve that scenario.
   Pass the scenario-specific part in as a constructor argument instead (see
   `PlannedAttacker`, which takes its attack tree as an argument). Enforced by
   `tests/core/test_layering.py`.
2. **A guest path is a contract; a host path is free.** Files copied into
   containers are flat modules importing each other bare, so `/ot_registers.py`
   must keep that name forever — while the file it comes from may live anywhere.
   Manifests: `cyberrange/scenarios/<name>/guest_files.py`.
3. **Guest agents import only the stdlib and what their node image installs**
   (`docker/<scenario>/Dockerfile`), and never `cyberrange.*`. They run where
   this repo and its virtualenv do not exist. Enforced by
   `tests/core/test_guest_imports.py`, which also keeps the images pinned to
   `requirements.txt`.
4. **`SOURCES` categories stay disjoint** (one directory each). `make platform-loc`
   sums each category, so a file matched twice is counted twice and the paper's
   table silently lies.
5. **Never make a guardrail green without understanding it.** Do not edit a file
   under `tests/snapshots/` by hand, do not run `UPDATE_SNAPSHOTS=1` reflexively,
   do not lower `MIN_TESTS` in `tests/conftest.py`. All three are deliberate acts
   that need a reason — ask if there isn't one.
6. **`make` target names and `-m` module paths are internal API.** Campaigns shell
   out to the targets and tests parse them; renaming one breaks a run hours in.
7. **No new top-level directories, and never `pip install -e .`.** The repo runs
   from its root; an installed copy would shadow the sources and make tests pass
   for the wrong reason.
8. **`nodes/` and `cyberrange/` never import each other.** The platform deploys,
   observes and scores; what a node *does* at run time — the tools it runs, their
   configuration, the logic that decides and acts — is node software. Prefer an
   existing open-source tool, installed by the node image and configured from
   `nodes/`, to code of our own; a component only stages and launches it. Python
   under `nodes/` obeys rule 3. Enforced by `tests/core/test_layering.py`.

## Commands

```sh
.venv/bin/python -m pytest tests -q      # the suite (make selftest)
make selftest-fast                       # same without the heavy tests
make fmt                                 # ruff format: layout only, never logic
make lint                                # what fmt cannot fix: dead imports, long lines
make help                                # every target, with what it writes where
```

Before saying a change is done, run the suite **and** dry-run every target:

```sh
for t in $(grep -hoE '^[a-zA-Z0-9_.-]+:' Makefile make/*.mk | tr -d ':' | sort -u); do
    make -n "$t" >/dev/null 2>&1 || echo "BROKEN: $t"
done
```

## Style

Layout is not a decision: `ruff format` owns it (100 columns, double quotes,
configured in `pyproject.toml`), and `tests/core/test_formatting.py` fails if the
repo drifts. Run `make fmt` before committing. What the formatter cannot decide:

- Module docstring opens with `name.py — what it is`, then *why it exists*.
- Guest agents additionally open with `#!/usr/bin/env python3` and state the
  deploy fact ("Copied flat onto the sensor machine…, stdlib + numpy only" — or
  whichever of the image's packages it needs).
- Type annotations at boundaries, not everywhere.
- **Comments describe the present.** What the code does now and why it is this
  way — never what it used to be, which release changed it, or which refactor
  moved it. Version control holds the history. A constraint that still binds is
  not history: "pinned to the stable datastore API (3.16.x churned it)" explains
  today's pin and stays.
- **Comment form follows position.** On its own line: a sentence, capitalised,
  ending with a period. On the same line as code: a lowercase fragment, no
  period.
- Comments name the failure they prevent; assert messages state the consequence,
  not just the mismatch.
- An import that must stay out of order (a backend set before it is imported, a
  path fixed before a flat guest import) carries `# noqa: E402` **with the
  reason on the same line**.

## Where the rest is

`docs/structure.md` (where a file goes and why) · `docs/platform.md` (the scenario
contract) · `docs/components.md` (every component) · `docs/playground-red-vs-blue.md`
(the red-vs-blue playground, for the people playing it) · the `cyberrange-*` skills
for step-by-step work.
