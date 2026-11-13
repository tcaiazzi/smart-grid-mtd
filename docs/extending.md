# Extending the platform

How to add to the cyber range without breaking it. This is a map, not a tutorial:
the reference is [Architecture](platform.md) (the scenario contract),
[Components](components.md) (every building block) and [Where files go](structure.md)
(the layering). Inside the repository, the `cyberrange-*` skills walk through each
task step by step.

## The rules that are not negotiable

These are enforced by tests under `tests/core/`; a change that breaks one fails the
suite.

1. **Imports point one way: `core ← planes ← scenarios`, and `nodes/` imports none
   of them.** A plane must not import a scenario — a plane that does can only ever
   serve that one scenario. Pass the scenario-specific part in as a constructor
   argument instead (see `PlannedAttacker`, which takes its attack tree as an
   argument).
2. **A guest path is a contract; a host path is free.** Files copied into
   containers are flat modules that import each other bare, so a guest filename
   (`/ot_registers.py`) must keep that name forever — while the host file it comes
   from may live anywhere. Each scenario lists what it stages in its own
   `guest_files.py`.
3. **Guest agents import only the stdlib and what their node image installs**
   (`docker/<scenario>/Dockerfile`), and never `cyberrange.*`. They run where this
   repository and its virtualenv do not exist.
4. **`nodes/` and `cyberrange/` never import each other.** The platform deploys,
   observes and scores; what a node *does* at run time is node software. Prefer an
   existing open-source tool, installed by the node image and configured from
   `nodes/`, to code of your own — a component only stages and launches it.
5. **No new top-level directories, and never `pip install -e .`.** The repo runs
   from its root; an installed copy would shadow the sources.
6. **`make` target names and `-m` module paths are internal API.** Campaigns shell
   out to the targets and tests parse them; renaming one breaks a run hours in.

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
is a constructor argument. See [Components](components.md) for the hooks
(`artifacts`, `poll`, `mirror`, telemetry) and the `cyberrange-components` skill for
the step-by-step.

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

[Architecture](platform.md) is the full contract; the `cyberrange-scenario` skill
walks through it.

## The gate before a change is done

```bash
make fmt          # ruff format: layout only, never logic (the formatter owns layout)
make lint         # dead imports, long lines — what fmt cannot fix
make selftest     # the whole suite (no Kathará, no Docker)
```

And dry-run every target, because campaigns shell out to them:

```bash
for t in $(grep -hoE '^[a-zA-Z0-9_.-]+:' Makefile make/*.mk | tr -d ':' | sort -u); do
    make -n "$t" >/dev/null 2>&1 || echo "BROKEN: $t"
done
```

## Guardrails you will meet

Some tests are deliberate tripwires, not puzzles to silence: the frozen deploy and
code-size snapshots under `tests/snapshots/`, the layering / entry-point /
guest-import checks under `tests/core/`, and the floor on the number of collected
tests. **Never make one green without understanding why it went red** — do not edit
a snapshot by hand, do not run `UPDATE_SNAPSHOTS=1` reflexively, do not lower
`MIN_TESTS`. If a snapshot changed on purpose, update it on purpose; if it did not,
you have found a real regression. The `cyberrange-guardrails` skill explains each
one.

## Style in one breath

`ruff format` owns layout (100 columns, double quotes). Module docstrings open with
`name.py — what it is`, then *why it exists*; guest agents add `#!/usr/bin/env
python3` and state the deploy fact. Comments describe the present and name the
failure they prevent; assert messages state the consequence. The full list is in
`CLAUDE.md` and is checked by `tests/core/test_formatting.py`.
