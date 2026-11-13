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

## Beside the layers: `nodes/`

The layers above are the platform: they deploy a lab, observe it and score it.
What a node does at run time is a different thing, and it lives in `nodes/` —
outside the `cyberrange` package, imported by none of it and importing none of
it (`tests/core/test_layering.py` checks both directions, and that `nodes/` is
not a package).

| | Platform (`cyberrange/`) | Node software (`nodes/`) |
|---|---|---|
| Runs | on the host | inside the containers |
| Is | orchestration, observation, scoring | the tools of the scenario's nodes: configuration of third-party software, set-up scripts, the glue around them |
| Reaches a node | — | through a scenario's manifest (`guest_files.py`), like any guest file |
| Third-party software | — | installed by the node image (`docker/<image>/Dockerfile`), pinned |

The preference is to **use an existing open-source tool** and keep in `nodes/`
only what configures it. Today that is Wazuh on the CPS management network:
`nodes/wazuh/manager/` (set-up, rules) and `nodes/wazuh/agent/` (set-up,
profile, the active response that applies a countermeasure). The components
that launch them (`WazuhManager`, `WazuhAgent`) contain no node logic.

Next to it: `nodes/soc/` (the SOC's analytics and its operator console),
`nodes/redteam/` (the attacker node's brains: the autonomous tree-guided
attacker `red_agent.py` with its planner, and the red team's console) and
`nodes/common/` (what any host a person works on needs: the web terminal and
SSH set-up around `ttyd` and OpenSSH, and the record of the commands typed).

The agents under `cyberrange/planes/*/agents/` predate this boundary: they are
node software too, and are meant to move here.

## Deciding where a new file goes

Ask what its lifecycle is:

- **Is it the configuration or glue of a tool a node runs?** → `nodes/<tool>/`,
  and add it to the scenario's `guest_files.py`.
- **Does it run inside a container?** → `planes/<plane>/agents/`, and add it to
  the scenario's `guest_files.py`. It must be a flat module that imports only the
  stdlib and what its node image installs (`docker/<scenario>/Dockerfile`),
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
components used to do this — `PlannedAttacker` reached for the CPS knowledge
graph, `DeliveryAttack` for the MQTT fault injector. Both now take what they need
as a constructor argument, supplied by the scenario that builds them. The same
applies to the dashboard: a scenario declares its own panel and structure
(`Scenario.panel_js`, `Scenario.structure`) and the core asks the registry,
rather than importing one scenario's knowledge graph.

**A scenario may build on another scenario, never the reverse.** `cps-advisor`
subclasses `CpsScenario` and deploys its lab under another name; `cps` knows
nothing of it. What the derived scenario needs to vary is a hook or a class
attribute on the base (`extra_services`, `engage`, `operator_api`,
`check_approval`, `DEFAULT_*`), not a test on the scenario's name. Its `SOURCES`
list only its own directory and its `GUEST_MANIFESTS` only the files it adds to
the nodes, so the shared lab is counted once, under `cps`.

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
| Is the layering intact, and the platform/node boundary? | `tests/core/test_layering.py` |
| Are the node tools pinned? | `tests/core/test_guest_imports.py` (pip pins against `requirements.txt`; apt pins of the Wazuh packages, agent and manager on one version) |
| Is the code-size table honest? | `tests/core/test_loc_coverage.py` |
| Did tests go missing instead of failing? | the floor in `tests/conftest.py` |
