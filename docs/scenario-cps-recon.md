# The `cps-recon` scenario — an attacker that derives the attack tree

Same lab and episode as [`cps`](scenario-cps.md), with one difference in *what the
attacker knows*. The `cps` planner driver is **handed** the attack tree the SOC
built from the inventory — perfect knowledge of the target. Here the attacker is
given only a **scan scope** (its own IT subnet and a port list) and must
**derive** the tree by reconnaissance. A run then also scores how close the
derived tree is to the true one.

Why a scenario of its own and not an option of `cps`: the attacker runs on a
different node image — its tools must not sit on the victim HMI — and under its
own lab name it can run side by side with `cps`.

## What the attacker does

It reconnoitres in two stages, each matching what it can actually reach
([`cps` topology](scenario-cps.md): the attacker touches only the HMI's web app;
everything OT is reached by pivoting through the HMI), using **real tools**, never
scanners of our own (CLAUDE.md rule 8):

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
impact/feasible/attck`): the structure is the attacker's knowledge of the generic
CPS pattern (exploit the web app → pivot → write registers), and recon only sets
which parts are `feasible` on this target and which impacts the discovered
registers allow. It then plans and executes on that tree, **reusing
`red_agent.RedAgent` unchanged**.

Everything downstream is the `cps` chain: the planner, `tree_doc`, `steps`, the
exploit primitives (`exploit_client.py` / `ot_write.py`), the sensors and the
SOC. The ground-truth oracle stays off the lab — the host reconstructs it from
the agent's record (the `RedConsole` / `PlannedAttacker` contract), with the
recon findings added.

## The pieces

| Where | What |
|---|---|
| `nodes/redteam/recon.py` | drives nmap + parses its XML; reads `/proc/net/tcp` and the HMI's pymodbus through the RCE tunnel |
| `nodes/redteam/belief_tree.py` | builds the belief attack tree from the findings |
| `nodes/redteam/red_recon_agent.py` | orchestrates recon → belief tree → `RedAgent` (plan + execute), in the lab |
| `ReconAttacker` (`cyberrange/planes/attack/components.py`) | host side: launches the agent (scan scope, not the tree) and reconstructs the ground truth; adds the `recon` events and the belief tree as an artifact |
| `docker/redteam/Dockerfile` | the attacker's own image (`kathara/redteam`): base + `nmap` |
| `CpsReconScenario` (`cyberrange/scenarios/cps_recon/`) | the `cps` scenario with `attacker()` → `ReconAttacker` and the attacker on the red-team image |

## Scoring: tree fidelity

`metrics.py` adds `tree_fidelity` (only when a belief tree is present, so `cps` /
`cps-advisor` are unaffected): it compares the feasible leaves of the belief tree
against the true `tree.json` recorded at deploy and reports **precision** (of what
the attacker believed feasible, how much is real), **recall** (of what is really
feasible, how much it found), and the id lists `discovered` / `missing` /
`extra`.

The dashboard shows the same comparison live, without waiting for the score: the
agent puts its belief tree on the record as soon as it has built it, and the
attack-tree view frames in red (dashed) the real nodes the attacker does not
know, naming in the legend the ones it believes in that are not real. A run
recorded before the belief reached the ledger falls back to the leaves its
`tree_fidelity` lists. The Attacker · Defender card shows what recon found:
hosts and ports, the foothold, the engine and the registers read.

## Run it

```bash
make cps-image          # the plant/SOC nodes (kathara/cps, kathara/soc)
make cps-recon-image    # the attacker's box (kathara/redteam: nmap)
make cps-recon          # attack the lab with the recon-driven attacker
make cps-recon-dashboard # the dashboard restricted to cps-recon runs
```

Or directly:

```bash
.venv/bin/python -m cyberrange.scenarios.cps_recon --attack \
    --attacker-profile opportunistic --out-dir output/cps-recon/run-1 --seed 1
```

The run leaves `attacker.belief_tree.json` among the artifacts and a
`metrics.json` with `tree_fidelity` alongside the usual planner fields
(`stage_reached`, `attack_succeeded`).
