---
name: cyberrange-components
description: "Add or change the building blocks a scenario runs: plane components in cyberrange/planes/<plane>/components.py and the guest agents they launch inside the containers. Use when: writing a Component or GuestAgent, adding or moving a script under planes/*/agents/, editing a scenario's guest_files.py manifest, changing the artifacts, telemetry, mirror or poll hooks, choosing a guest path or a guest-side import, or wiring a component into an episode with ctx.start, ctx.exec and ctx.role_seed."
argument-hint: "What the component should do, on which node, and what it must leave behind (artifacts, telemetry, ground truth)"
user-invocable: true
---

# Components and guest agents

Two kinds of code meet here, and the whole difficulty is keeping them apart:

| | Host side | Guest side |
|---|---|---|
| Where | `cyberrange/planes/<plane>/components.py` and the plane's own modules | `cyberrange/planes/<plane>/agents/*.py` |
| Runs | in this repo, with the venv | inside a container, where this repo does not exist |
| Imports | normal packages (`from cyberrange.core...`) | **flat and bare** (`from ot_registers import ...`) |
| May use | anything in `requirements.txt` | **the stdlib + what its node image installs** (`docker/<scenario>/Dockerfile`) |
| Named by | its path, freely | its **guest path**, which is a contract |

## Scope / Not this skill

| This skill | Elsewhere |
|---|---|
| What is in a manifest, what a file is called on the guest | Which node exists at all → **cyberrange-scenario** |
| `Component` / `GuestAgent` hooks, artifacts, telemetry | Running the lab → **cyberrange-runs-and-metrics** |
| Writing code that will satisfy the deploy guardrails | Diagnosing one that is already red → **cyberrange-guardrails** |

Not for driving Kathará directly. A component never calls
`Kathara.get_instance()`; it asks the run context (`ctx.exec`, `ctx.manager`).
The `kathara-api` skill is for generic Kathará work and for the adapter in
`cyberrange/core/topology.py`, not for components here.

## The component contract

From `cyberrange/core/component.py` — read that docstring, it is the source:

| Hook | When | Notes |
|---|---|---|
| `start(ctx)` | `ctx.start(c)` calls it and registers `c` | launch guest processes, or a host thread |
| `stop(ctx)` | episode end, reverse order | stop host-side work; guests die with the lab |
| `artifacts()` | after the episode | `[Artifact(node, guest_path, local_name, required)]` |
| `telemetry()` | while running | `[TelemetrySource(node, guest_path, name)]` |
| `poll(ctx)` | during `ctx.observe` | pull live state; **must never raise** |
| `mirror(ev)` | optional, duck-typed | maps one telemetry event onto a ledger event; `monitor.TelemetryMirror` looks for it with `getattr` and skips components without it |

`GuestAgent` is the common case — one process in one container, output captured:

```python
class PhysicalProcess(GuestAgent):
    """The plant: grid physics stepper + Modbus/TCP server exposing it."""

    def __init__(self, node, port, step_interval, seed=None):
        super().__init__(
            node,
            f"python3 modbus_engine.py --port {port} "
            f"--interval {step_interval}{seed_arg(seed)}",
            "engine.log", plane=PLANE, name="physical_process")
```

It already declares its console log as an artifact (`<node>.<console_log>`), so
a crash traceback survives the teardown. Extra files go in `artifacts=`.

## The deploy contract

A node's files come from the scenario's manifest, one tuple per file:

```python
SENSOR_FILES = [
    ("cyberrange/planes/defense/agents/ot_sensor.py", "/ot_sensor.py"),
    ("cyberrange/planes/defense/ot_registers.py",     "/ot_registers.py"),
]
```

Left column: where the file lives on the host — **free to move**. Right column:
where it lands in the container — **never changes**. Kathará unpacks staged files
at `/`, which is also the container's working directory and therefore
`sys.path[0]`, which is why guest modules import each other bare and why
`/ot_registers.py` must keep that exact name: seven other agents say
`import ot_registers`.

The full contract is documented once, in the docstring of
`cyberrange/core/topology.py`.

### Dual modules

Three modules are imported **both ways**: flat on the guest and as a package on
the host — `rl_policy.py`, `delivery_detector.py`, `ot_registers.py`. They live
at the root of their plane (not in `agents/`) and must stay importable both ways:
no package-relative imports, no dependency the guest cannot have.

## Writing one: the order that works

1. **Pick the plane by what the thing *is*,** not by which scenario wants it:
   traffic = the legitimate system doing its job; attack = anything adversarial;
   defense = detection and response; monitor = observation that only ever reads.
2. **Write the guest agent** under `planes/<plane>/agents/`, opening with
   `#!/usr/bin/env python3` and a docstring that says what it is, why it exists
   and the deploy fact ("Copied flat onto the sensor machine…, stdlib + numpy
   only"). Give it `--seed` if its behaviour is random.
3. **Add it to the manifest** of every node that runs it, in that scenario's
   `guest_files.py` — including the modules it imports flat.
4. **Add the component** to `planes/<plane>/components.py`, launching it by the
   **guest** name (`python3 ot_sensor.py …`), and declaring its artifacts and
   telemetry.
5. **Wire it in the episode**: `ctx.start(defense.OtSensor("sensor", …,
   seed=ctx.role_seed("sensor")))`.
6. **Run the guardrails** (below) before believing any of it.

## Common pitfalls

These are failure modes, not style notes. Most of them are silent.

- **The launch name and the manifest drift apart.** `components.py` says
  `python3 ot_sensor.py` but nothing stages `/ot_sensor.py`: the container comes
  up, the process dies instantly, and the node still looks deployed.
  `tests/core/test_deploy_contract.py` cross-checks the two lists — keep it green.
- **A guest agent importing `cyberrange.*`.** It works on your machine and fails
  in the container, where the package does not exist.
  `tests/core/test_guest_imports.py` imports every staged module in a subprocess
  with only that machine's files on `sys.path`, which is exactly the container's.
- **A dependency the image lacks.** A guest agent has the stdlib and what its
  node image installs, nothing else; `tests/core/test_guest_imports.py` fails on
  any other import made when the module loads. Add the package to the
  Dockerfile, pinned to `requirements.txt`, only if the agent really needs it
  in the container. Anything heavier (pandas, torch, sklearn, matplotlib)
  belongs host-side, in the plane or in a scenario's `training/`.
- **Renaming a guest path "to be consistent".** Every other agent that imports it
  breaks, and only in a real lab. Rename the host file instead; it is free.
- **Leaving a stale twin.** Moving a module but leaving a copy behind: the
  manifest points at a file that exists, every test passes, and the lab quietly
  runs the old code. Use `git mv` and let the deploy contract test check that
  each staged basename exists exactly once.
- **Importing a scenario from a component.** The lazy import inside a method is
  the tempting version. Take it as a constructor argument instead — `PlannedAttacker`
  receives its attack tree, `DeliveryAttack` receives its fault injector — and
  the component stays reusable.
  `tests/core/test_layering.py` enforces this.
- **Unseeded randomness.** `ctx.role_seed("<role>")` derives a distinct,
  reproducible seed per role from the run seed; `seed_arg(seed)` renders it onto
  a guest command line. Nothing fails if you skip it — the run is just not
  reproducible, which is the worst defect for a paper.
- **A `poll` that raises.** The core swallows and logs it, so the symptom is a
  dashboard that stops updating rather than an error. Keep `poll` total.
- **Writing into a container from a mirror.** Monitor components only read; a
  failed pull must never break a run.

## Ground truth vs telemetry

Two different streams, often confused:

- **Ground truth** (`ctx.open_ground_truth`, `ground_truth.jsonl`) is recorded
  **host-side** and says what really happened — what the attack did, when a block
  started. It is the reference an evaluation scores against, so it must not come
  from the component being evaluated.
- **Telemetry** (`telemetry.jsonl` on the guest, declared via `telemetry()`) is
  what a sensor *believed*. Mirroring it onto the ledger is for watching, not for
  scoring.

## Verify

```sh
.venv/bin/python -m pytest tests/core/test_guest_imports.py tests/core/test_deploy_contract.py -q
make lab-conf SCENARIO=<name>      # read the "# node: /guest <- host" lines it prints
.venv/bin/python -m pytest tests -q
```

A component is done when the lab deploys, the console log appears in the run
directory, declared artifacts arrive, and the deploy snapshot changed only in the
host column — never in the guest column.
