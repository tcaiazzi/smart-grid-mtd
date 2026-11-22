# How the repository is laid out, and why

One rule decides where a file goes:

```
core  <-  planes  <-  scenarios
```

Arrows point at what a layer may import. **Nothing points back.**
`tests/core/test_layering.py` enforces it by walking the imports, so this
document describes something that is checked rather than hoped for.

## The three layers

| Layer | Where | What belongs there |
|---|---|---|
| **core** | `cyberrange/core/` | Everything identical for every experiment: how a lab is declared, deployed, observed and torn down; how runs are repeated, scored and aggregated; the progress ledger and the dashboard that reads it (the four libraries its page loads — D3, Observable Plot, Split.js and Tabulator — are vendored in `cyberrange/core/vendor/`, the only third-party code in the tree). The core never names a scenario — the registry maps names to module paths as *strings*, which is its whole job. |
| **planes** | `cyberrange/planes/{traffic,attack,defense,monitor}/` | Reusable building blocks: `components.py` is the plane's contract, `agents/` is the code that runs inside containers, and the host-side domain logic sits beside them. A plane may import the core. It may **not** import a scenario. |
| **scenarios** | `cyberrange/scenarios/<name>/` | One directory per experiment, holding all of it: topology, episode, CLI, campaign, deploy manifest, metrics, figures, offline training. A scenario composes planes. |

Inside a scenario, what runs *after* a run, offline, on its artifacts —
`analysis/` (figures) and `training/` (offline training) — sits at the end of
the same chain: it may import the scenario and everything below it, and nothing
imports it. The same holds for the top-level `tools/`, which holds tooling that
belongs to no single scenario.

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
only what configures it. Wazuh on the CPS management network is the model:
`nodes/wazuh/manager/` (set-up, rules) and `nodes/wazuh/agent/` (set-up,
profile, the active response that applies a countermeasure), and for `cps-soc`
`nodes/wazuh/indexer/` and `nodes/wazuh/dashboard/`. The components that launch
them (`WazuhManager`, `WazuhAgent`, `WazuhIndexer`, `WazuhDashboard`) contain
no node logic. DFIR-IRIS, nmap, Filebeat, `ttyd` and OpenSSH are used the same
way: installed by an image, configured from here.

Next to it: `nodes/soc/` (the SOC's analytics and its operator console),
`nodes/redteam/` (the attacker node's brains: the autonomous tree-guided
attacker `red_agent.py` with its planner, the recon that builds its own tree,
and the red team's console), `nodes/players/` (what runs on a player's node when
a harness sits at a team's seat: the seat's MCP adapter, the harnesses'
launchers, the node's firewall — see
[playing-with-agents.md](playing-with-agents.md)), `nodes/soar/` (DFIR-IRIS's
start-up and the SOC's module for it) and `nodes/common/`. The last holds what more than one kind of
node runs:

- what any host a person works on needs: the web terminal and SSH set-up around
  `ttyd` and OpenSSH, and the record of the commands typed;
- the knowledge graph, the attack tree's model and its generator
  (`soar_kg.py`, `soar_trees.py`, `techniques.py`, `attack_graph.py`), which the
  SOC runs on its inventory and the recon attacker on what it found.

The agents under `cyberrange/planes/*/agents/` are node software too, by this
definition: code of the platform's own that runs in a container, kept beside
the component that launches it. New node software goes under `nodes/`.

## Deciding where a new file goes

Ask what its lifecycle is:

- **Is it the configuration or glue of a tool a node runs?** → `nodes/<tool>/`,
  and add it to the scenario's `guest_files.py`.
- **Is it node software that more than one kind of node runs?** →
  `nodes/common/`, staged by each manifest that needs it (a scenario that lists
  it where another one does too counts it as shared in `make platform-loc`).
- **Does it run inside a container?** → `planes/<plane>/agents/`, and add it to
  the scenario's `guest_files.py`. It must be a flat module that imports only the
  stdlib and what its node image installs (`docker/<image>/Dockerfile`),
  because on the guest side there are no packages — see the deployment
  contract in `cyberrange/core/topology.py`.
- **Does it orchestrate a lab, for any scenario?** → `core/`.
- **Is it a capability a second scenario could reuse?** → the plane that owns
  it. The test for this is blunt: if `components.py` imports it, it is the
  plane's, even when only one scenario uses it today.
- **Does it describe one experiment?** → that scenario's directory.
- **Does it run after the fact, on the results?** → that scenario's
  `analysis/` or `training/`.

## The rules that are easy to break quietly

**A plane that imports a scenario is no longer reusable.** It is also hard to
see: the import is usually lazy, inside a method, and everything passes. A
component that needs something of a scenario's takes it as a constructor
argument, supplied by the scenario that builds it: `PlannedAttacker` is given
its attack tree, `DeliveryAttack` the MQTT fault injector. The same
applies to the dashboard: a scenario declares its own panel and structure
(`Scenario.panel_js`, `Scenario.structure`) and the core asks the registry,
rather than importing one scenario's knowledge graph.

**A scenario may build on another scenario, never the reverse.** `cps-advisor`,
`cps-soc` and `cps-recon` are `CpsScenario` with a tuple of features
(`cyberrange/scenarios/cps/feature.py`), deploying its lab under their own
names; `cps` knows nothing of them. What a scenario adds is a `Feature` in its
own directory (`People`, `SocTools`, `Recon`), not a test on the scenario's
name: `Recon` returns a `ReconAttacker` from its `attacker` hook and puts that
attacker on its own image through `extras`. A scenario's `SOURCES` list only its
own directory and its `GUEST_MANIFESTS` only the files it adds to the nodes, so
the shared lab is counted once, under `cps`. The lab itself is data
(`cyberrange/scenarios/cps/lab.py`, see [platform.md](platform.md)).

**A file counted twice is a false number in the paper.** `make platform-loc`
sums each category in `SOURCES` independently, so a file matched by two
patterns is counted twice, and a pattern that matches nothing disappears from
the table without an error. Categories therefore follow directories and stay
disjoint; `tests/core/test_loc_coverage.py` checks both, plus that every
tracked source file is counted by somebody.

## Where things are verified

[Contributing](contributing.md) has the rules in full, the gate to pass before a
change is done, and what to do when one of these turns red
([the guardrails](contributing.md#the-guardrails-and-what-each-one-freezes)).

| Question | Answer |
|---|---|
| Does the lab still deploy the same thing? | `tests/core/test_deploy_contract.py` freezes every scenario's guest paths and startup commands (`make lab-conf` renders them without Docker), and refuses a lab that gives one address to two NICs on a link |
| Does the SOC still reason on the same tree? | `tests/nodes/test_tree_snapshot.py` freezes the generated attack tree and countermeasures of the CPS lab and of two variants |
| Do the entry points exist? | `tests/core/test_entry_points.py` resolves every `-m <module>` that the makefiles, scripts and campaigns invoke, and every `make` target they call |
| Is the layering intact, and the platform/node boundary? | `tests/core/test_layering.py` |
| Are the node tools pinned? | `tests/core/test_guest_imports.py` (pip pins against `requirements.txt`; apt pins of the Wazuh packages, agent and manager on one version) |
| Is the code-size table honest? | `tests/core/test_loc_coverage.py` |
| Did tests go missing instead of failing? | the floor in `tests/conftest.py` |
