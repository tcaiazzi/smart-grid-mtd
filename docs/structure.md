# How the repository is laid out, and why

One rule decides where a file goes:

```
core  <-  planes  <-  scenarios  <-  analysis
```

Arrows point at what a layer may import. **Nothing points back.**
`tests/core/test_layering.py` enforces it by walking the imports, so this
document describes something that is checked rather than hoped for.

## The four layers

| Layer | Where | What belongs there |
|---|---|---|
| **core** | `cyberrange/core/` | Everything identical for every experiment: how a lab is declared, deployed, observed and torn down; how runs are repeated, scored and aggregated; the progress ledger and the dashboard that reads it. The core never names a scenario — the registry maps names to module paths as *strings*, which is its whole job. |
| **planes** | `cyberrange/planes/{traffic,attack,defense,monitor}/` | Reusable building blocks: `components.py` is the plane's contract, `agents/` is the code that runs inside containers, and the host-side domain logic sits beside them. A plane may import the core. It may **not** import a scenario. |
| **scenarios** | `cyberrange/scenarios/<name>/` | One directory per experiment, holding all of it: topology, episode, CLI, campaign, deploy manifest, metrics, figures, offline training. A scenario composes planes. |
| **analysis** | `cyberrange/scenarios/<name>/analysis/`, `training/`, `tools/` | What runs *after* a run, offline, on its artifacts. It may import anything below it, and nothing imports it. |

## Deciding where a new file goes

Ask what its lifecycle is:

- **Does it run inside a container?** → `planes/<plane>/agents/`, and add it to
  the scenario's `guest_files.py`. It must be a flat module (stdlib + numpy),
  because on the guest side there are no packages — see the deployment
  contract in `cyberrange/core/topology.py`.
- **Does it orchestrate a lab, for any scenario?** → `core/`.
- **Is it a capability a second scenario could reuse?** → the plane that owns
  it. The test for this is blunt: if `components.py` imports it, it is the
  plane's, even when only one scenario uses it today.
- **Does it describe one experiment?** → that scenario's directory.
- **Does it run after the fact, on the results?** → that scenario's
  `analysis/` or `training/`.

## The two rules that are easy to break quietly

**A plane that imports a scenario is no longer reusable.** It is also hard to
see: the import is usually lazy, inside a method, and everything passes. Two
components used to do this — `SoarResponder` reached for the CPS response loop,
`DeliveryAttack` for the MQTT fault injector. Both now take what they need as a
constructor argument, supplied by the scenario that builds them. The same
applies to the dashboard: a scenario declares its own panel and structure
(`Scenario.panel_js`, `Scenario.structure`) and the core asks the registry,
rather than importing one scenario's knowledge graph.

**A file counted twice is a false number in the paper.** `make platform-loc`
sums each category in `SOURCES` independently, so a file matched by two
patterns is counted twice, and a pattern that matches nothing disappears from
the table without an error. Categories therefore follow directories and stay
disjoint; `tests/core/test_loc_coverage.py` checks both, plus that every
tracked source file is counted by somebody.

## Where things are verified

| Question | Answer |
|---|---|
| Does the lab still deploy the same thing? | `tests/core/test_deploy_contract.py` freezes every scenario's guest paths and startup commands (`make lab-conf` renders them without Docker) |
| Do the entry points exist? | `tests/core/test_entry_points.py` resolves every `-m <module>` that the makefiles, scripts and campaigns invoke, and every `make` target they call |
| Is the layering intact? | `tests/core/test_layering.py` |
| Is the code-size table honest? | `tests/core/test_loc_coverage.py` |
| Did tests go missing instead of failing? | the floor in `tests/conftest.py` |
