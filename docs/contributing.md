# Contributing: rules and guardrails

What a change to this repository must respect, and what tells you when it does
not. The rules are few and each is enforced by a test; the guardrails are those
tests, read as information rather than as obstacles. For *where* a new file goes
see [Where files go](structure.md); for *how* to add a component, a scenario or a
metric see [Extending the platform](extending.md).

## The rules that are not negotiable

Other pages cite these by name.

1. **One-way imports.** Imports point one way: `core ← planes ← scenarios`, and
   `nodes/` imports none of them. A plane that imports a scenario can only ever
   serve that scenario. Pass the scenario-specific part in as a constructor
   argument instead (`PlannedAttacker` takes its attack tree as an argument).
   Enforced by `tests/core/test_layering.py`.
2. **Guest paths are a contract.** A guest path is a contract; a host path is
   free. Files copied into containers are flat modules importing each other
   bare, so `/ot_registers.py` must keep that name forever — while the file it
   comes from may live anywhere. Each scenario lists what it stages in
   `cyberrange/scenarios/<name>/guest_files.py`.
3. **Guest imports.** Guest agents import only the standard library and what
   their node image installs (`docker/<image>/Dockerfile`), and never
   `cyberrange.*`. They run where this repository and its virtualenv do not
   exist. Enforced by `tests/core/test_guest_imports.py`, which also keeps the
   images pinned to `requirements.txt`.
4. **Disjoint `SOURCES`.** The categories of a scenario's `SOURCES` stay
   disjoint, one directory each. `make platform-loc` sums each category, so a
   file matched twice is counted twice and the code-size table silently lies.
5. **No blind green.** Never make a guardrail green without understanding it. Do
   not edit a file under `tests/snapshots/` by hand, do not run
   `UPDATE_SNAPSHOTS=1` reflexively, do not lower `MIN_TESTS` in
   `tests/conftest.py`. All three are deliberate acts that need a reason.
6. **Names are internal API.** `make` target names and `-m` module paths are
   internal API. Campaigns shell out to the targets and tests parse them;
   renaming one breaks a run hours in.
7. **Runs from the root.** No new top-level directories, and never
   `pip install -e .`. The repository runs from its root; an installed copy
   would shadow the sources and make tests pass for the wrong reason.
8. **Node software is not the platform.** `nodes/` and `cyberrange/` never
   import each other. The platform deploys, observes and scores; what a node
   *does* at run time — the tools it runs, their configuration, the logic that
   decides and acts — is node software. Prefer an existing open-source tool,
   installed by the node image and configured from `nodes/`, to code of your
   own; a component only stages and launches it. Python under `nodes/` obeys
   the *guest imports* rule. Enforced by `tests/core/test_layering.py`.

## The gate before a change is done

```bash
make fmt          # ruff format: layout only, never logic
make check        # lint, the whole suite, a dry run of every make target
```

`make check` runs three things in order:

- **`make lint`** — `ruff format --check` and `ruff check`: what the formatter
  cannot fix, such as dead imports and long lines;
- **the suite** — `.venv/bin/python -m pytest tests -q`, with no Kathará and no
  Docker (`make selftest` is the suite alone, `make selftest-fast` leaves out
  the heavy tests);
- **a dry run of every target** — `make -n` on each one. Campaigns shell out to
  the targets, so one that no longer expands is otherwise found hours into a
  run.

The suite never deploys a real lab. If a change touched guest paths, startup
commands or guest files, also render the labs (`make lab-conf SCENARIO=<name>`)
and do a real run (`make cps-lab`, for instance): the snapshot gets close, but it
executes nothing.

## The guardrails, and what each one freezes

A red guardrail means one of the things below happened. The fix is almost never
"make it green".

| Guardrail | Freezes | Red means |
|---|---|---|
| `tests/core/test_deploy_contract.py` | `tests/snapshots/lab-<scenario>.json`: every node's interfaces, image, guest paths and startup commands; and no two interfaces with one address on a link | what a container receives changed, or a lab clashes |
| `tests/nodes/test_tree_snapshot.py` | `tests/snapshots/tree-cps.json`: the attack tree and countermeasures generated for the CPS lab and its variants | the SOC would reason, and the attacker plan, on another tree |
| `tests/core/test_entry_points.py` | every `-m <module>` that `make -n` prints, those in scripts and campaigns, and every `make` target they call | a module path or target name went stale |
| `tests/core/test_layering.py` | `core` imports no plane and no scenario; a plane imports no scenario; `nodes/` and `cyberrange/` do not import each other | an import points backwards |
| `tests/core/test_guest_imports.py` | every guest module's imports against the image of the node it is staged on; image packages pinned to `requirements.txt` | a container would fail on import, or an image drifted from the host |
| `tests/core/test_loc_coverage.py` | `tests/snapshots/loc-totals.json`; every `SOURCES` pattern matching a file, no file counted twice, no source counted by nobody | the code-size table moved |
| `tests/core/test_dashboard.py`, `tests/core/test_panels.py` | the dashboard's vendored libraries against `cyberrange/core/vendor/VENDOR.json`; what each panel draws for a run | a vendored file is not the release named, or a view shows something the ledger does not record |
| `tests/core/test_scenario_guide.py` | the facts the [interactive scenario guide](new-scenario.md) copies from the repository, and the skeleton it writes | the guide is stale, or writes code that no longer runs |
| `tests/core/test_formatting.py` | the layout `ruff format` produces | a file was not formatted |
| `MIN_TESTS` in `tests/conftest.py` | how many tests a full run collects | tests went missing instead of failing |

### Reading a red one

**Deploy contract.** If you only moved files on the host, the snapshot must not
change: its frozen half is the guest side. If it does, you changed a guest path,
a startup command, an interface or an image. The same module also fails when a
manifest points at a file that does not exist (or exists twice, after an
unfinished move), and when a component launches `python3 X.py` that no manifest
stages — the container would start it and die.

**Entry points.** Something invokes a module or target that no longer exists.
`make -n` prints such a line happily, so this test is what stands between you
and a campaign dying at step 4 of 9. If a module really moved, update its `M_*`
variable in `make/common.mk`, where every entry point is named once.

**Layering.** A plane or the core imports something above it, usually a lazy
import inside a method added "just to make it work". Take the dependency as a
constructor argument, or, for the dashboard, declare it on the scenario
(`panel_js`, `structure`) and let the registry resolve it. The test's `ALLOWED`
set is empty and should stay empty.

**Code size.** A total that *fell* usually means a `SOURCES` glob went stale and
code vanished from the table; one that *rose* usually means you wrote code. A
new source file that belongs to no category fails too: add it to one, or to
`EXEMPT` with a reason.

**The test-count floor.** Nothing failed: tests disappeared, almost always a
directory no longer collected or an import error swallowed at collection. Fix
the collection.

### Regenerating on purpose

```bash
UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/core/test_deploy_contract.py -q
UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/core/test_loc_coverage.py -q
```

Before running either, all three must hold:

1. you can say in one sentence what changed and why it should change;
2. the change is the one you intended, not a side effect you have not explained;
3. the change was asked for. Regenerating a snapshot to make a red test green is
   not a fix.

Never edit a file under `tests/snapshots/` by hand, and never delete one so that
the test writes it again: deletion is how the guarantee is lost without trace.

Two switches are of a different kind:

- **`UPDATE_GUIDE_CONTRACT=1`** rewrites one block of `docs/scenario-guide.html`
  (`#guide-contract-derived`) from the repository. That block is a copy of
  facts, not a frozen contract: adding a scenario, a make target, a guest module
  or a package to an image makes it stale, and the same change should bring it
  along. Read the page's diff afterwards; it must show only what you changed.

    ```bash
    UPDATE_GUIDE_CONTRACT=1 .venv/bin/python -m pytest tests/core/test_scenario_guide.py -q
    ```

- **`MIN_TESTS`** is raised by hand, in the same change that adds tests, and
  lowered only when tests were removed on purpose.

## Writing a test

- Put it in the area it belongs to: `tests/core/`, `tests/planes/`,
  `tests/nodes/` or `tests/scenarios/<name>/`. Shared fixtures go in
  `tests/helpers/`; never import one test module from another.
- **No Docker, no Kathará.** The helpers run a whole lifecycle in-process:

    | Helper | What it gives |
    |---|---|
    | `tests/helpers/kathara.py` | `FakeManager`, a fake Kathará manager that records every call and answers `exec` from canned data, and `fake_downloads`, which serves artifacts |
    | `tests/helpers/guest_paths.py` | the host directories that hold guest modules, for tests that emulate a container's flat imports |
    | `tests/helpers/manifests.py` | the deploy manifests of every registered scenario, resolved through the registry |
    | `tests/helpers/soar.py` | synthetic findings shaped like the OT sensor's output, for the SOAR tests |
    | `tests/helpers/guide_contract.py` | what the scenario guide's derived block must say, computed from the repository |

- Mark a heavy test by adding its module name to `SLOW_MODULES` in
  `tests/conftest.py`, so that `make selftest-fast` skips it.
- Assert messages state the consequence, not the mismatch: "the container would
  come up without it", not "paths differ".
- Raise `MIN_TESTS` in the same change.

## Style

Layout is not a decision: `ruff format` owns it (100 columns, double quotes,
configured in `pyproject.toml`), and `tests/core/test_formatting.py` fails if the
repository drifts. Run `make fmt` before committing. What the formatter cannot
decide:

- A module docstring opens with `name.py — what it is`, then *why it exists*.
- Guest agents additionally open with `#!/usr/bin/env python3` and state the
  deploy fact ("Copied flat onto the sensor machine…, stdlib + numpy only", or
  whichever of the image's packages it needs).
- Type annotations at boundaries, not everywhere.
- **Comments describe the present**: what the code does now and why it is this
  way, never what it used to be or which change moved it. Version control holds
  the history. A constraint that still binds is not history and stays.
- **Comment form follows position.** On its own line: a sentence, capitalised,
  ending with a period. On the same line as code: a lowercase fragment, no
  period.
- Comments name the failure they prevent.
- An import that must stay out of order (a backend set before it is imported, a
  path fixed before a flat guest import) carries `# noqa: E402` with the reason
  on the same line.

## Documentation

Everything under `docs/` is published as this site (`mkdocs.yml`; `make
docs-serve` to read it locally) and is written in English. A new page goes in
the `nav` there. Shared plans and dated audits go in `docs/internal/`, which the
site excludes.
