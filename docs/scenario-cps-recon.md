# The `cps-recon` scenario — an attacker that derives the attack tree

## 1. What it is for

Same lab and episode as [`cps`](scenario-cps.md), with one difference in *what the
attacker knows*. The `cps` planner driver is **handed** the attack tree the SOC
built from the inventory — perfect knowledge of the target. Here the attacker is
given only a **scan scope** (its own IT subnet and a port list) and must
**derive** the tree by reconnaissance. A run then also scores how close the
derived tree is to the true one.

Why a scenario of its own and not an option of `cps`: the attacker runs on a
different node image — its tools must not sit on the victim HMI — and under its
own lab name it can run side by side with `cps`.

## 2. The lab

The [`cps` topology](scenario-cps.md#2-architecture), node for node and address
for address, under the lab name `cps-recon`. One node differs: the attacker
runs on `kathara/redteam` instead of `kathara/cps`, and receives the recon
files listed in `cyberrange/scenarios/cps_recon/guest_files.py`. The victim
nodes stay on the `cps` image, unchanged.

## 3. What the attacker does

It reconnoitres in two stages, each matching what it can actually reach (the
attacker touches only the HMI's web app; everything OT is reached by pivoting
through the HMI), using **real tools**, never scanners of our own — node
software prefers an existing open-source tool to code written here
([Contributing](contributing.md)):

1. **IT scan — on the attacker's own box.** `nmap -sV` over the IT subnet finds
   the HMI and its vulnerable web app (the foothold). The attacker's box is a
   dedicated image, `kathara/redteam` (`docker/redteam/Dockerfile`: `nmap`), so
   the scanner never touches a victim.
2. **OT recon — living off the land on the HMI.** Through the foothold (the RCE
   tunnel `exploit_client.rce` already provides), it reads the HMI's
   `/proc/net/tcp` to learn the engine's address from the HMI's existing Modbus
   connections, then uses the HMI's **own pymodbus** to confirm the Modbus
   service and read the holding registers. No tool is dropped on the victim.

From the findings it builds a **belief tree** (`nodes/redteam/belief_tree.py`) in
the same document shape the planner consumes (`tree_doc`: `id/gate/children/
impact/feasible/attck`). The findings become an inventory of the lab as the
attacker knows it — the HMI it got a foothold on, the engine behind it, the
registers it read, a boundary inferred from the HMI talking to the engine — and
the tree is derived from it by **the same generator the SOC runs on its full
inventory** (`nodes/common/attack_graph.py`, on the attacker's image with
networkx). What recon did not find is absent or not feasible. It then plans and
executes on that tree, **reusing `red_agent.RedAgent` unchanged**.

Everything downstream is the `cps` chain: the planner, `tree_doc`, `steps`, the
exploit primitives (`exploit_client.py` / `ot_write.py`), the sensors and the
SOC. The ground-truth oracle stays off the lab — the host reconstructs it from
the agent's record (the `RedConsole` / `PlannedAttacker` contract), with the
recon findings added.

## 4. The pieces

| Where | What |
|---|---|
| `nodes/redteam/recon.py` | drives nmap + parses its XML; reads `/proc/net/tcp` and the HMI's pymodbus through the RCE tunnel |
| `nodes/redteam/belief_tree.py` | builds the belief attack tree from the findings |
| `nodes/redteam/red_recon_agent.py` | orchestrates recon → belief tree → `RedAgent` (plan + execute), in the lab |
| `ReconAttacker` (`cyberrange/planes/attack/components.py`) | host side: launches the agent (scan scope, not the tree) and reconstructs the ground truth; adds the `recon` events and the belief tree as an artifact |
| `docker/redteam/Dockerfile` | the attacker's own image (`kathara/redteam`): base + `nmap` |
| `CpsReconScenario` (`cyberrange/scenarios/cps_recon/`) | the `cps` scenario with `attacker()` → `ReconAttacker` and the attacker on the red-team image |

## 5. Running it

```bash
make cps-image            # the plant/SOC nodes (kathara/cps, kathara/soc)
make cps-recon-image      # the attacker's box (kathara/redteam: nmap, networkx)
make cps-recon            # attack the lab with the recon-driven attacker
make cps-metrics CPS_RUN=output/cps-recon/latest   # score it
make cps-recon-dashboard  # the dashboard restricted to cps-recon runs
```

`make cps-recon-lab` deploys the same lab for normal operation only, with no
attack; `PLAYGROUND=1` on either target keeps the lab up after the episode,
until Ctrl-C.

Or directly:

```bash
.venv/bin/python -m cyberrange.scenarios.cps_recon.cli --attack \
    --attacker-profile opportunistic --seed 1
```

| Variable | Default | |
|---|---|---|
| `CPS_RECON_OUT` | a new one per run, under `output/cps-recon/runs/` | run directory |
| `CPS_PROFILE` | `opportunistic` | how the attacker chooses its next step on the tree it built: `opportunistic`, `targeted` or `stealthy` |
| `CPS_GOAL` | — | the impact leaf a `targeted` attacker aims for |
| `CPS_DWELL` | `0` | seconds between the attacker's steps: the defender's window |
| `CPS_NORMAL`, `CPS_LEARN`, `CPS_POST`, `CPS_STEP`, `CPS_DETECTORS` | as in `cps` | durations, the simulation step and the detectors |
| `CPS_RESPOND`, `CPS_APPROVAL` | `off`, `auto` | the SOC's response policy, as in `cps` |
| `CPS_IT` | — | `1` adds the IT-side telemetry |
| `SEED` | — | seeds the run |

`CPS_ATTACK_DRIVER` and `CPS_ATTACK_MODE` have no effect here: the scenario
supplies the attacker, whatever the driver asked for. The variables shared with
`cps` are described in [CPS, §7](scenario-cps.md#7-running-an-experiment), and
all of them are in the [reference](reference.md).

Two options exist on the command line only:

| Flag | Default | |
|---|---|---|
| `--it-cidr` | the lab's IT subnet | the subnet the attacker scans: its own, not a map of the target |
| `--scan-ports` | `22,80,502,5020,8080` | the ports nmap probes on the IT scan |

## 6. Phases

The episode is the `cps` one: **deploy → services → normal → attack →
post_attack → download → undeploy**
([CPS, §7](scenario-cps.md#7-running-an-experiment)). Reconnaissance is part of
the **attack** phase: the agent scans, builds its belief tree and puts it on
the record, then plans and acts on it.

## 7. What is recorded

A `cps` run's artifacts, and from the attacker:

| File | What it is |
|---|---|
| `attacker.belief_tree.json` | the attack tree the attacker derived |
| `attacker.red_actions.jsonl` | the agent's own record: what it found, planned and did |
| `attacker.red_agent.log` | the agent's log |

On the ledger (`progress.jsonl`) the run adds a `recon` event per finding —
hosts and ports, the foothold, the engine, the registers read — and an
`attacker_belief` event carrying the tree as soon as it is built. The findings
are in `ground_truth.jsonl` too, as `recon` records. `tree.json`, recorded at
deploy, is the true tree the belief is compared with.

## 8. What is scored: tree fidelity

`cyberrange/scenarios/cps/metrics.py` adds `tree_fidelity` (only when a belief tree is present, so `cps` /
`cps-advisor` are unaffected): it compares the leaves an attacker can reach on
the belief tree (feasible, with every step before them feasible)
against the true `tree.json` recorded at deploy and reports **precision** (of what
the attacker believed feasible, how much is real), **recall** (of what is really
feasible, how much it found), and the id lists `discovered` / `missing` /
`extra`.

The score is in `metrics.json` alongside the planner's fields (`stage_reached`,
`attack_succeeded`) and everything a `cps` run measures. There is no campaign
for this scenario: runs are single, one per seed.

## 9. Dashboard

The dashboard shows the same comparison live, without waiting for the score: the
agent puts its belief tree on the record as soon as it has built it, and the
attack-tree view frames in red (dashed) the real nodes the attacker does not
know, naming in the legend the ones it believes in that are not real. A run
recorded without the belief on the ledger falls back to the leaves its
`tree_fidelity` lists. The Attacker · Defender card shows what recon found:
hosts and ports, the foothold, the engine and the registers read. Everything
else is the `cps` panel ([The dashboard](dashboard.md#6-what-each-scenario-adds)).

## 10. Limits

- **One way in and one feeder.** The reconnaissance stops at the first of
  each: on a lab with several HMIs or feeders the belief tree has one branch
  where the true tree has several, and recall says so.
- **The IT scan is bounded by its scope.** What is outside `--it-cidr` and
  `--scan-ports` is not found.
- **The OT side is seen through the HMI only.** The engine is learned from the
  HMI's existing Modbus connections; a host on the plant's network that the HMI
  does not talk to is not discovered.
- **No campaign.** Tree fidelity is not aggregated across seeds by a campaign
  of its own.

## 11. Quick reference

| What | Where |
|---|---|
| Scenario and feature | `cyberrange/scenarios/cps_recon/{scenario,feature}.py` |
| Command line of one run | `cyberrange/scenarios/cps_recon/cli.py` |
| Deploy manifest | `cyberrange/scenarios/cps_recon/guest_files.py` |
| Dashboard panel | `cyberrange/scenarios/cps_recon/panel.js` |
| The attacker, host side | `ReconAttacker` in `cyberrange/planes/attack/components.py` |
| The attacker, in the lab | `nodes/redteam/{recon,belief_tree,red_recon_agent}.py` |
| Its image | `docker/redteam/Dockerfile` (`make cps-recon-image`) |
| Tree fidelity | `_tree_fidelity` in `cyberrange/scenarios/cps/metrics.py` |
| Make targets | `make/cps-recon.mk` |
| The lab, episode and metrics it builds on | [CPS](scenario-cps.md) |
| The tree generator | [KG & attack trees](kg-and-attack-trees.md) |
