---
name: cyberrange-conventions
description: "Check Python written in this repository against its measured house style: module docstring form, guest-agent headers, line budget, where type annotations belong, section separators, comments that name the failure mode avoided, and assert messages that state the consequence. Use when: reviewing a diff before committing, cleaning up a module just written under cyberrange/ or tests/, asked whether code matches this repo's conventions, or starting a new module or guest agent from scratch."
argument-hint: "The file or diff to check, or the module you are about to start"
user-invocable: true
---

# House style of this repository

Layout is settled: `ruff format` owns it, `make fmt` applies it, and
`tests/core/test_formatting.py` fails when the repo drifts. **Start the review by
running `make fmt` and `make lint`** — then everything below is what neither can
decide for you.

Run this pass over a diff before committing, or over a module you just wrote.

## The numbers (measured, not aspirational)

| Convention | What the code actually does |
|---|---|
| Line length | 100 columns, enforced. Median 33, p95 84, p99 96 |
| Module docstrings | first line `name.py — what it is`, then *why it exists* |
| Guest agents | **19 of 19** open with `#!/usr/bin/env python3`, then that docstring, then the deploy fact |
| Type annotations | 279 of 1278 functions (~22%) — at boundaries, not everywhere |
| Section separators | `# ── Title ─────` inside 40 files |
| Standalone comments | a sentence: capitalised, ending with a period |
| Trailing comments | **516 of 553** are lowercase fragments with no period |
| Comments | explain the *why*, and name the failure mode avoided |
| Assert messages | state the consequence, not the mismatch |

## Module docstrings

Open with the file name, an em dash, and what the thing *is*. Then explain what
the reader cannot infer from the code: why it exists, what it is kept apart
from, what breaks without it.

**Good** (`cyberrange/planes/defense/agents/ot_model.py`):

```python
#!/usr/bin/env python3
"""ot_model.py — the learned half of the OT sensor: a per-window behavioural
featurizer over the observed Modbus traffic + process state, and a robust
anomaly model calibrated online on the normal phase.

Copied flat onto the sensor machine next to ot_sensor.py (see the scenario's
guest_files.py). Stdlib + numpy only, unit-testable off-wire.

Why a model next to the rules: the rules encode the plant contract — who may
write what, which values are in range. A stealthy attacker that writes
legitimate values from an allowed host passes every write-time rule and is only
caught once the physics moves.
"""
```

**Bad** — true, and worth nothing:

```python
"""Module for the OT model. Contains the OtModel class."""
```

A guest agent's docstring must additionally state the **deploy fact** — which
machine it is copied onto, and that it is stdlib (+ numpy) only. That line is
what stops the next person adding pandas to a file that runs in a container.

## Comments

Three rules, in order of how often they are broken.

**They describe the present.** A comment says what the code does now and why it
is this way. Not what it used to do, not which refactor moved it, not which
version changed it — git holds that, and a comment that narrates the past rots
the moment someone reads it as current. The distinction worth making: a
constraint that still binds is not history. `pymodbus==3.6.9  # pinned to the
stable classic datastore API (3.16.x churned it)` explains today's pin; "bumped
from 2.2.2" explains nothing.

**Their form follows their position.** On its own line, a comment is a sentence:
capitalised, ending with a period. On the same line as code, it is a lowercase
fragment with no period — which is what 516 of the 553 trailing comments already
do. The exception is a first word that names code (`ot_registers is the shared
contract…`): leave that lowercase, it is a quotation, not a sentence opening.

**They earn their place** by saying something the code cannot — which in this
repo usually means **naming the failure they prevent**.

**Good** (`cyberrange/core/topology.py`):

```python
# Manifest host paths are repo-relative; resolve them against the repo
# rather than the process CWD, so a run started from anywhere stages the
# same files instead of silently staging none.
```

**Bad**:

```python
# resolve the path
```

Where a module has distinct parts, separate them with
`# ── Guest helpers ──────────` rather than blank lines alone.

## Type annotations

About a third of the functions have them, and not at random: annotate where a
value crosses a boundary and its shape is the contract — `compute_metrics(run_dir: str) -> dict`,
parsers, things that go into a snapshot. Inside a module, where the types are
obvious from two lines of context, leave them off rather than decorate
everything. Do not add annotations to existing untyped code as a side errand.

## Tests

- A test class's docstring says **which defect it catches**, not what it calls:
  "A move that leaves a copy behind passes every other check: the manifest points
  at a file that exists, and the lab quietly runs the old code."
- Assertion messages state the consequence:

  ```python
  self.assertTrue(
      (REPO_ROOT / host_path).is_file(),
      f"{manifest} stages {guest} from {host_path}, which does not exist: "
      f"the container would come up without it.",
  )
  ```

  not `assert path.exists()`.
- Use `subTest` when looping, so one failure names the item instead of stopping
  at the first.

## Naming

- Modules: short, lower case, what the thing *is* (`topology.py`, `responder.py`,
  `guest_files.py`). A scenario's files are named by role, not by scenario — the
  directory already says which scenario it is (`cps/metrics.py`, never
  `cps/cps_metrics.py`).
- Guest module names are a deploy contract: see **cyberrange-components** before
  renaming one.
- Constants that other modules rely on go near the top, upper case, with a
  comment on what depends on them.

## Review checklist

0. `make fmt` then `make lint`: clean, before reading anything else.
1. Does every new module open with `name.py — …` and say why it exists?
2. If it runs in a container: shebang, deploy fact, stdlib + numpy only?
3. Does any comment narrate the past instead of describing the present?
4. Standalone comments: sentences. Trailing comments: lowercase fragments.
5. Does each new comment say something the code does not, and do new assertions
   state a consequence?
6. Are annotations at the boundaries, and absent from the obvious places?
7. Did the diff pick up anything unrelated — a reformat, a stray import, a
   snapshot regenerated in passing?
8. Does it read like the file around it?

Then the gate in `CLAUDE.md`: the suite, and `make -n` over every target.
