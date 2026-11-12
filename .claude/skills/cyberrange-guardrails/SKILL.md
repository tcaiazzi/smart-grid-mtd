---
name: cyberrange-guardrails
description: "The repository's automated guardrails and what a red one means: the frozen deploy and code-size snapshots in tests/snapshots/, the layering, entry-point and guest-import tests, and the floor on the number of collected tests. Use when: a test under tests/core/ fails, a change touches guest paths, startup commands, SOURCES globs or imports across core/planes/scenarios, before declaring a change finished, when tempted to set UPDATE_SNAPSHOTS=1 or lower MIN_TESTS, or when writing tests with the in-process lab fakes in tests/helpers/."
argument-hint: "Which guardrail is red, and what you changed just before"
user-invocable: true
---

# Guardrails: reading a red one

Most of what can break in this repo breaks **silently**: a lab that deploys
without a file, a module path nothing resolves any more, a code-size table that
quietly understates a scenario. These five tests exist to turn those into
failures. A red guardrail is information, not an obstacle — the fix is almost
never "make it green".

## The five, and what each one freezes

| Guardrail | Freezes | Red means |
|---|---|---|
| `tests/core/test_deploy_contract.py` | `tests/snapshots/lab-<scenario>.json`: every node's interfaces, image, **guest paths** and startup commands | what a container receives changed |
| `tests/core/test_entry_points.py` | every `-m <module>` that `make -n` prints, plus the ones in scripts and campaigns, and every `make` target they call | a module path or target name went stale |
| `tests/core/test_layering.py` | `core` imports no plane and no scenario; a plane imports no scenario | an import points backwards |
| `tests/core/test_loc_coverage.py` | `tests/snapshots/loc-totals.json` + every `SOURCES`/`CORE` pattern matching ≥1 file, no file counted twice, no tracked source counted by nobody | the paper's code-size table moved |
| `MIN_TESTS` in `tests/conftest.py` (now 319) | how many tests a full run collects | tests went missing instead of failing |

## Diagnosing each

### Deploy contract

Three distinct failures, and they mean different things:

- **`DeployContractFrozen`** — the snapshot differs. If you only *moved* files on
  the host, this must not fire: the frozen half is the guest side. If it fires,
  you changed a guest path, a startup command, an interface or an image.
  *Legitimate:* you meant to change the lab → regenerate deliberately (below).
  *Forbidden:* regenerating to silence a guest path you renamed by accident —
  every agent importing that module will break in a real lab only.
- **`HostPathsResolve`** — a manifest points at a file that does not exist, or
  one that exists in two places (a stale twin left by a move). Fix the manifest
  or finish the move; never relax the test.
- **`LaunchNamesMatchTheManifest`** — `components.py` launches `python3 X.py` but
  no manifest stages `/X.py`. The container would start it and die. Fix the
  manifest or the command.

### Entry points

Something invokes a module or target that no longer exists. `make -n` prints such
a line happily, so this test is the only thing between you and a campaign dying
at step 4 of 9. Fix the reference; if a module genuinely moved, update the `M_*`
variable in `make/common.mk`, which is where every entry point is named once.

### Layering

A plane or the core imports something above it — usually a lazy import inside a
method, added "just to make it work". *Legitimate fix:* take the dependency as a
constructor argument, the way `PlannedAttacker` receives its attack tree and
`DeliveryAttack` its fault injector; or, for the dashboard, declare it on the
scenario (`panel_js`, `structure`) and let the registry resolve it.
*Forbidden:* adding it to the `ALLOWED` set to move on. That set is empty and
should stay empty; an entry in it is a debt with no due date.

### Code-size coverage

- **`PatternsStillMatch`** — a `SOURCES` glob matches nothing: a path moved and
  the accounting did not follow. The code is now invisible to the paper's table.
- **`CategoriesAreDisjoint`** — one file matched by two categories of the same
  scenario (or of `CORE`): its lines are counted twice. Make the categories
  follow directories, one each.
- **`EveryFileIsCounted`** — a new source file belongs to nobody. Add it to a
  `SOURCES` category, or to `EXEMPT` **with a reason**.
- **`TotalsAreStable`** — the headline totals moved. Ask which: a total that
  *fell* usually means a glob went stale; one that *rose* usually means you wrote
  code, which is fine. Only then update the snapshot.

### The test-count floor

A full run collected fewer tests than the floor. Nothing failed — tests
disappeared. Almost always a directory that is no longer collected, or an import
error swallowed at collection. Fix the collection. Raise `MIN_TESTS` only when
you deliberately added tests, and in the same change that adds them.

## Regenerating a snapshot

```sh
UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/core/test_deploy_contract.py -q
UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/core/test_loc_coverage.py -q
```

Three conditions, all of them, before you run either:

1. you can say in one sentence **what changed and why** it should change;
2. the change is the one you intended — not a side effect you have not explained;
3. the user asked for the change, or would obviously want it. **Regenerating a
   snapshot to make a red test green is not a fix**; if you are unsure, ask
   rather than regenerate.

Never edit a file under `tests/snapshots/` by hand, and never delete one to make
the test regenerate it: deletion is how the guarantee is lost without trace.

## Writing a test here

- Put it in the area it belongs to: `tests/core/`, `tests/planes/`,
  `tests/scenarios/<name>/`. Shared fixtures go in `tests/helpers/` — never
  import one test module from another.
- **No Docker, no Kathará.** `tests/helpers/kathara.py` gives `FakeManager`
  (records every command, serves canned `exec` output) and `fake_downloads`
  (serves artifacts), which together run a whole lifecycle in-process. See
  `tests/core/test_progress.py` and `tests/scenarios/mqtt_mtd/test_mqtt_scenario.py`.
- Mark a heavy test by adding its module name to `SLOW_MODULES` in
  `tests/conftest.py`, so `make selftest-fast` can skip it.
- **Assertion messages state the consequence**, not the mismatch: "the container
  would come up without it", not "paths differ".
- Adding tests? Raise `MIN_TESTS` in the same change.

## The gate before saying a change is done

```sh
.venv/bin/python -m pytest tests -q
for t in $(grep -hoE '^[a-zA-Z0-9_.-]+:' Makefile make/*.mk | tr -d ':' | sort -u); do
    make -n "$t" >/dev/null 2>&1 || echo "BROKEN: $t"
done
make lab-conf SCENARIO=cps && make lab-conf SCENARIO=mqtt-mtd
```

The suite never deploys a real lab. If your change touched deploy paths, startup
commands or guest files, a real run (`make cps-lab`) is the only thing that
proves it — the snapshot gets close, but it executes nothing.
