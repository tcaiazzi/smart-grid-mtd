# The knowledge graph and the attack tree

How the SOAR prototype of the CPS scenario represents the lab and the attacks
against it, how those structures are built, and what happens to them while a run
is going: the defender turns sensor findings into a belief over the tree and
picks countermeasures from it, and the tree-guided attacker picks its next step
from the same tree.

[scenario-cps.md §10](scenario-cps.md#10-response-the-soar-prototype) is the
overview; this document is the detail behind it. Everything described here runs
on the host. No guest agent imports it, so it may use networkx.

| File | What it holds |
|---|---|
| [nodes/soc/soar_kg.py](../nodes/soc/soar_kg.py) | the knowledge graph: construction from the SOC's inventory, queries, JSON |
| [cyberrange/scenarios/cps/inventory.py](../cyberrange/scenarios/cps/inventory.py) | the CPS binding: the lab as the SOC's inventory (topology, services, roles, rules) |
| [nodes/soc/soar_trees.py](../nodes/soc/soar_trees.py) | the tree model and its operations, the CPS attack tree, the countermeasures |
| [nodes/soc/soar_mapping.py](../nodes/soc/soar_mapping.py) | findings → evidence on tree nodes → belief (`CampaignState`) |
| [nodes/soc/soar_policy.py](../nodes/soc/soar_policy.py) | belief → decisions: the rules playbook and the solver |
| [nodes/soc/soc_analytics.py](../nodes/soc/soc_analytics.py) | the SOC node's runtime loop (decision + requests); its engine, offline, is the replay |
| [cyberrange/planes/attack/planner/](../cyberrange/planes/attack/planner/) | the attacker that walks the same tree, read from `tree.json` |

## 1. The pipeline

```
 Topology (scenarios/cps/topology.py)
   │  inventory(args) → hosts, roles, addresses, services, boundary rules   (inventory.py)
   ▼
 Knowledge graph  ──────────────┐  build_kg(inventory)                      (soar_kg.py)
   │                            │
   │ cps_context(g)             │ cps_context(g)
   ▼                            ▼
 Attack tree  ◄── annotated ── Countermeasures (prevents / restores tree nodes)
   │      ▲
   │      └── AttackPlanner: feasible goals, prerequisite steps   (attacker side)
   ▼
 CampaignState: findings → evidence → belief per node           (mapping.py)
   ▼
 Policy: belief → Decision (actions + justification)            (policy.py)
   ▼
 SOC analytics: asks the Wazuh manager for each action; the     (soc_analytics.py,
 agent on the target host runs its allowlisted commands          cps_response.py)
```

The graph describes **what the lab is**. The tree describes **how it can be
attacked**. The countermeasures describe **what the defender can do about each
step**. The belief describes **where the attack is believed to be right now**.
Only the belief changes during a run. The other three are built once, from the
lab being deployed, and stay fixed until the run ends (§4).

## 2. The knowledge graph

### 2.1 Inputs

`build_kg(inventory)` is generic: it turns any described lab into a graph and
knows nothing about the CPS scenario. The scenario supplies the inventory, one
JSON-serialisable document, in
[scenarios/cps/inventory.py](../cyberrange/scenarios/cps/inventory.py):

| Inventory key | Source | Becomes |
|---|---|---|
| `hosts` | the declared `Topology`: each `Node`'s name, `role`, image and interfaces (`name`, `zone`, `cidr`) | hosts, zones, addresses; the `role` attribute of each host, `may_write` edges |
| `boundary` | the boundary host and `topology.firewall_rules()`, the iptables commands its startup runs | `flow_rule` nodes |
| `services` | `topology.services()`: `{host: [(name, proto, port, app)]}` | `service` nodes |
| `plant_service` | `("engine", "modbus")` | which service exposes the registers |

The registers and the access policy are not inputs: they come from the plant
contract [planes/defense/ot_registers.py](../cyberrange/planes/defense/ot_registers.py)
(`ACTUATOR_REGISTERS`, `SENSOR_REGISTERS`, `SENSITIVE_ACTUATORS`,
`ROLE_POLICY`), which the PLC, the engine and the DPI sensor share. The graph
therefore describes the same contract that the sensor enforces.

Addresses come from the `addresses` meta that `core.topology.build_lab` sets on
every Kathará machine (`{"eth0": "10.10.0.20/24"}`). A machine without it gets
no `ip` nodes, so no zone can be inferred from its addresses (only from its
interfaces). The DPI sensor's passive tap is an example of a link that has no
address.

### 2.2 Schema

Node ids are typed by prefix, and every node carries a `type` attribute:

| Node | Id | Attributes |
|---|---|---|
| zone | `zone:<collision domain>` | `name` |
| host | `host:<machine>` | `image`, `role`; the boundary also has `forward_default` |
| ip | `ip:<addr>` | `addr`, `prefix`, `network`, `iface`, `host` |
| service | `svc:<host>/<name>` | `proto`, `port`, `app`, `host` |
| register | `reg:hr:<addr>` / `reg:ir:<addr>` | `name`, `kind` (holding/input), `scale`, `lo`/`hi` or `unit`, `sensitive` |
| flow_rule | `rule:<firewall>:<n>` | `order`, `action`, `src`, `dst`, `proto`, `dport` |

It is a networkx `MultiDiGraph`. Each edge's key equals its `rel` attribute, so
two nodes can be linked by more than one relation:

| Relation | From → to | Meaning |
|---|---|---|
| `in_zone` | host → zone (attr `iface`), ip → zone | the host has an interface on that collision domain |
| `has_ip` | host → ip | the host owns the address |
| `runs` | host → service | the host exposes the service |
| `exposes` | service → register | the Modbus server serves the register |
| `may_write` | host → register | the host's role may write it (`ROLE_POLICY`) |
| `enforces` | firewall host → rule | the boundary applies the rule |
| `src` | rule → host | the rule matches traffic from that host |
| `dst` | rule → service | the rule matches traffic to that service |

The CPS lab as built gives 32 nodes and 48 edges:

| Type | Count | |
|---|---|---|
| host | 7 | attacker (`it-host`), hmi (`hmi`), firewall (`boundary`), engine (`plant`), plc (`plc`), sensor (`sensor`), soc (`soc`) |
| zone | 3 | IT, OT, MGMT |
| ip | 10 | the firewall has one in each zone, the hmi one in IT and one in MGMT |
| service | 2 | `svc:hmi/diag-http` (tcp/8080), `svc:engine/modbus` (tcp/5020) |
| register | 9 | 3 holding (setpoint, breaker, control mode), all sensitive; 6 input |
| flow_rule | 1 | `rule:firewall:0`: ACCEPT 10.10.0.20 → 10.20.0.20 tcp/5020 |

The single rule links `host:hmi` (`src`) to `svc:engine/modbus` (`dst`). This
is the sanctioned flow that the whole attack chain goes through.

### 2.3 Construction

`build_kg` builds the graph in a fixed order, and each step relies on the
previous ones:

1. **Hosts, zones, addresses, services**, machine by machine in name order.
2. **Registers** from the plant contract. If `plant_service` names a service
   that exists, that service gets an `exposes` edge to every register.
3. **Role permissions.** For every host whose role has an entry in
   `ROLE_POLICY`, one `may_write` edge per writable holding register. In the
   lab, the PLC may write the setpoint and the HMI may write the setpoint and
   the control mode. Nobody may write the breaker.
4. **Boundary rules.** `parse_forward_rules` reads the iptables strings:
   - it keeps the FORWARD default policy (`-P FORWARD DROP`) and every
     `-A FORWARD … -j` rule;
   - it skips the `ESTABLISHED,RELATED` accept, which is a return-path rule and
     never starts a new flow.

   The firewall host gets `role=boundary` and `forward_default`. Each rule's
   `-s` address is resolved to a host (`src` edge), and its `-d` address and
   port to the matching services (`dst` edges).

Steps 2–4 only add edges between nodes that exist: a rule naming an unknown
address gets no `src`/`dst` edge, and a role with no policy gets no permission.

### 2.4 Queries

The graph is read through a few functions, never by walking it directly:
`hosts`, `registers`, `addresses(g, host) -> [(ip, zone)]`, `host_of_ip`,
`services_of`, `service(g, host, port, proto)` and `flow_rules`.

The question the tree asks most is **`reachable(g, src, dst, port, proto)`**:
can host `src` open a connection to `port` on host `dst`?

1. False if `dst` does not run a service on that port and protocol.
2. True if the two hosts have addresses in a common zone.
3. Otherwise, for every boundary host with addresses in both zones, the first
   matching FORWARD rule decides, or the chain's default policy if no rule
   matches. ACCEPT means reachable.

In the lab, `reachable(hmi → engine:5020)` is true through the rule,
`reachable(attacker → engine:5020)` is false (default DROP), and
`reachable(plc → engine:5020)` is true because both are in OT.
`reachable(soc → engine:5020)` is false: the boundary has an address in MGMT
but no rule forwards from it.

What `reachable` does not model:
- host firewalls (`block_web_src` is an INPUT rule on the HMI and is invisible
  to it);
- connection state;
- any route other than through a host whose role is `boundary`.

### 2.5 Layering

The graph is node software now ([nodes/soc/soar_kg.py](../nodes/soc/soar_kg.py)),
and node software imports no scenario (rule 8 of [CLAUDE.md](../CLAUDE.md)). So it
builds the graph from an **inventory** the scenario provides
([cps.inventory](../cyberrange/scenarios/cps/inventory.py), derived from the
topology): the SOC analytics does this on its node, and the host does it offline
through `soc_tool` (a subprocess, no import). `PlannedAttacker` does not build a
graph at all — it reads the recorded `tree.json`, where each node already says
whether it is feasible. A second scenario reuses all of this by providing its own
inventory and tree.

### 2.6 Serialisation

`kg.save(g, path)` writes networkx node-link JSON (`nodes`, `links`, each link
with its `key`/`rel`). `kg.from_json` reads it back into a `MultiDiGraph`; the
round trip is tested but nothing in the code calls it. The dashboard reads
`kg.json` as plain JSON.

## 3. The attack tree

### 3.1 The node model

A tree is made of `trees.Node` objects:

| Field | Meaning |
|---|---|
| `id`, `label` | stable id (used everywhere: evidence, policies, planner, dashboard) and a description |
| `gate` | `AND` (ordered steps that must all succeed), `OR` (alternatives) or `LEAF` |
| `children` | the sub-nodes, in order. For an AND gate the order is the order of the steps |
| `attck`, `attck_name` | ATT&CK (Enterprise or ICS) technique |
| `targets` | knowledge-graph node ids the step acts on |
| `impact` | loss weight if the node is achieved, 0..1. Only the impact leaves have one |
| `observable` | whether the OT sensor can see the step. Shown on the dashboard, not used in reasoning (§10) |
| `review` | an open question on the mapping, kept next to it |
| `precondition` | `g -> bool`, checked on the knowledge graph |

### 3.2 The CPS tree

`cps_attack_tree(g)` returns 12 nodes, 8 of them leaves:

```
impact  OR  Physical impact on the feeder
├── via_hmi  AND  Through the HMI (the only host allowed across the boundary)
│   ├── it_access      T1190 Exploit Public-Facing Application   → svc:hmi/diag-http
│   ├── it_exec        T1059 Command and Scripting Interpreter   → host:hmi
│   ├── pivot          (ATT&CK id under review)                  → svc:engine/modbus, rule:firewall:0
│   │                  precondition: reachable(hmi → engine:5020)
│   └── ot_action  OR  Manipulate the plant over Modbus
│       ├── setpoint_oor   T0855  impact 0.6   → reg:hr:0   setpoint outside its envelope
│       ├── breaker_open   T0855  impact 1.0   → reg:hr:1   feeder breaker opened
│       └── mode_hijack    T0831  impact 0.9   → reg:hr:2, reg:hr:0   MANUAL taken, in-range unsafe dispatch
└── direct_ot  AND  From a host without a Modbus role
    ├── ot_foothold        precondition: a host outside the Modbus roles reaches engine:5020
    └── ot_write_unknown   T0855  impact 0.6   → svc:engine/modbus
```

The tree has two branches:
- `via_hmi` is the chain the lab's attacks follow: exploit the HMI's web app,
  execute on it, use the one flow the firewall allows, then write to the plant.
- `direct_ot` is **infeasible in the lab as built**, because no host outside
  the Modbus roles reaches the plant. It is kept because the sensor's
  `unauthorized_*` findings need a node to land on, and because it becomes
  feasible as soon as the graph says so (for example if a rule lets the
  attacker through).

### 3.3 Grounding on the graph

The tree is hand-written but **graph-grounded**:

- **Every address, port and id it uses is read off the graph** by
  `cps_context(g)`:
  - hosts by role (`hmi`, `plant`, `boundary`, the first `it-host` as attacker);
  - their addresses;
  - the Modbus and HMI services and their ports;
  - the firewall's address in the HMI's zone.

  Nothing in the tree or in the countermeasures hard-codes `10.10.0.20` or
  `5020`. `cps_context` takes the first host of each role, so it assumes one
  HMI, one plant and one boundary.
- **Preconditions are graph queries.** `pivot` holds only while
  `reachable(hmi → engine:5020)` is true; `ot_foothold` holds only if some host
  without a Modbus role reaches the plant.
- **`feasible(node, g)`** propagates the preconditions up the tree:
  - a leaf is feasible when its precondition holds (or it has none);
  - an AND node when all its children are feasible;
  - an OR node when any of its children is.

  If you drop the allow rule from `firewall_rules()`, `pivot` becomes
  infeasible, `via_hmi` with it, and with `direct_ot` already infeasible so does
  the root. `test_rule_removal_cuts_the_path` and
  `test_without_allow_rule_the_pivot_is_infeasible` check exactly this.

### 3.4 Operations on a tree

| Function | Returns | Used by |
|---|---|---|
| `index(root)` | `{id: Node}` | everything |
| `parents(root)` | `{child id: parent Node}` | mapping (`next` steps) |
| `leaves(root)` | the leaf nodes | tests |
| `feasible(node, g)` | whether the node is achievable on `g` | the planner |
| `prerequisites(root, id)` | the earlier siblings, with their subtrees, in every AND ancestor | mapping (inference), solver (causal pairing), planner (step sequence) |
| `ancestors(root, id)` | the chain up to the root | nothing yet |

`prerequisites` is what makes the tree more than a list. For example,
`prerequisites(tree, "mode_hijack")` is `[it_access, it_exec, pivot]`: whoever
manipulated the plant through the HMI has already done those three steps.

### 3.5 Countermeasures: the defence annotation

`cps_countermeasures(g, it=False)` returns the actions available in the lab.
Each one says which tree nodes it acts on, in two different ways:

- **`prevents`**: the nodes the action stops from happening or happening again
  (for example, blocking a flow);
- **`restores`**: the impact nodes the action undoes (for example, returning
  control to AUTO).

A response has two jobs, stopping the attacker and repairing the plant, and the
two lists keep them apart. The solver depends on the difference (§6.2).

| Id | Runs on | Prevents | Restores | t (s) | op | energy | Approval | Order |
|---|---|---|---|---|---|---|---|---|
| `notify` | — | — | — | 0 | 0 | 0 | | 90 |
| `block_flow` | firewall | pivot + the 3 impact leaves | — | 0.5 | 0.5 | 0.01 | | 10 |
| `isolate_hmi` | hmi | it_access, it_exec, pivot + leaves | — | 0.5 | 0.8 | 0.01 | **yes** | 20 |
| `force_auto` | firewall | — | mode_hijack, setpoint_oor | 1.0 | 0.1 | 0.02 | | 30 |
| `restore_breaker` | firewall | — | breaker_open | 1.0 | 0.1 | 0.02 | | 40 |
| `kill_proc_tree` *(IT)* | hmi | it_exec, pivot + leaves | — | 0.3 | 0.15 | 0.01 | | 5 |
| `block_web_src` *(IT)* | hmi | it_access, it_exec, pivot + leaves | — | 0.4 | 0.2 | 0.01 | | 6 |

Notes on the table:

- **Commands.** Each countermeasure carries the shell commands it runs on
  `machine` (`apply`), and the commands that would undo it (`revert`). The
  commands are built from `cps_context`, so they follow the graph like the tree
  does. `force_auto` and `restore_breaker` write over Modbus to the engine from
  the boundary firewall, which already stands on the OT link: the plant holds
  no agent and no new path is opened towards it. The DPI sensor knows that
  address as the `responder` role (`ROLE_POLICY`), so it reports the writes as
  `ot_response_write` events rather than findings, and the model leaves them out
  of its features. Modbus has no authentication, so the role is an address:
  whoever controls the firewall writes to the plant unseen. From IT that address
  cannot be used — the FORWARD chain passes the HMI's source only.
- **Costs.** `time_to_effect_s`, `op_cost` (operational disruption, 0..1) and
  `energy_cost` are nominal values that the solver weighs. `block_flow` costs
  0.5 because it also cuts the operator's legitimate HMI control.
- **IT-side actions.** They exist only with `it=True`, that is with the IT
  sensor running. Without it the early steps are never observed, so nothing
  could justify acting on them.
- **The direct branch.** No countermeasure prevents `ot_write_unknown`. The
  infeasible branch has no defence modelled.
- **Order.** `order` sets the execution order within a decision: preventive
  actions first, then restoration, then notification.

### 3.6 `tree.json`

`trees.to_json(tree, countermeasures)` produces the attack-defence tree as one
document:

```json
{
  "attack_tree":     { "id": "impact", "gate": "OR", "children": [ … ], … },
  "defense":         { "<node id>": { "prevented_by": [ … ], "restored_by": [ … ] } },
  "countermeasures": [ { "id": "block_flow", "apply": [ … ], "prevents": [ … ], … } ]
}
```

Preconditions are functions, so they are not serialised. A reader of
`tree.json` sees the tree as it was built from that run's graph, not the rule
that would make a branch infeasible.

## 4. Where they are built during a run

The graph and the tree are rebuilt from scratch every time, from the lab being
deployed. There is no stored copy that could drift from the lab.

| When | Who | What |
|---|---|---|
| before deploy | `core.lifecycle` → `CpsScenario.write_structure(ctx)` | `kg.json` and `tree.json` in the run directory, from the inventory (via `soc_tool`, a subprocess). The countermeasures include the IT ones when `--it-telemetry` is on |
| SOC analytics start | `SocAnalytics` → `soc_analytics.py` on the node | its own graph from the inventory, the tree, the countermeasures, an empty `CampaignState`; it writes `kg.json`/`tree.json` on the node |
| attack phase with `--attack-driver planner` | `PlannedAttacker.attack` → `drive_attack_planned` | the tree document the run recorded (`tree.json`) |
| dashboard, for a run without `kg.json` | `CpsScenario.structure()` → `soc_tool` | rebuilt from today's inventory, in a subprocess; the card says "rebuilt" |
| offline | `python -m cyberrange.scenarios.cps.responder --replay <run>` | rebuilt from the declared topology |

`write_structure` failing does not fail the run: the lifecycle logs a warning
and goes on, and the dashboard falls back to the rebuilt structure.

**Nothing updates the graph or the tree during a run.** When `block_flow`
inserts its DROP rule, the firewall changes but the graph does not: `reachable`
still says the HMI reaches the plant, and `feasible` still says `pivot` is
achievable. Two consequences:
- the defender's record of what it has done lives in the policy (its `applied`
  set), not in the graph;
- the attacker learns that a path is closed from the failed step, not from the
  graph (§7).

## 5. The belief: from findings to tree nodes

`mapping.CampaignState(tree, g)` holds what the defender believes about the
attack. It starts empty and absorbs telemetry events one at a time with
`update(finding)`. Only events of kind `ot_finding` count, and the IT sensor
emits its findings in the same shape.

### 5.1 One finding → evidence

`evidence_from_finding(f, g)` turns a finding into a list of
`(node, weight, kind)`. The weight is the finding's confidence. The graph
resolves the source address to a host and its role. `kind` separates two kinds
of evidence:

- **command**: the write itself is wrong (out of range, policy violation,
  unknown writer, or an IT step observed directly);
- **consequence**: inferred from the voltage leaving its band. An open breaker
  also makes the operator's routine dispatch "unsafe", so this kind of evidence
  can point at the wrong leaf.

| Finding | Detector | Evidence |
|---|---|---|
| `web_injection_pattern` / `web_child_process` / `unexpected_modbus_client` | it | `it_access` / `it_exec` / `pivot`, command |
| `out_of_range_command` | rules | `breaker_open` if the register is `switch_cmd`, else `setpoint_oor`; command |
| `policy_violation` on `switch_cmd` | rules | `breaker_open`, command (other registers: `ot_action`) |
| `unauthorized_write*` / `unauthorized_read` | rules | `ot_write_unknown`, command (reads at half weight) |
| `unsafe_command` from the PLC | rules | **nothing**: the regulator reacting to an excursion is a symptom, not a step |
| `unsafe_command` on `dg_setpoint` | rules | inside the envelope → `mode_hijack`, outside → `setpoint_oor`; consequence |
| `unsafe_command` on `switch_cmd` / `ctrl_mode` | rules | `breaker_open` / `mode_hijack`; consequence |
| `manual_mode_excursion` | rules | `mode_hijack`; consequence |
| `behavioral_anomaly` | model | the leaves its top features hint at, at **half** weight (`MODEL_WEIGHT`) |

For a node, each kind keeps the strongest evidence seen so far. Evidence never
decreases within a run.

Two details of the model mapping prevent known misreadings:
- the voltage features `v_min`/`v_max` count as consequence evidence;
- z-scores are absolute values and an overvoltage also moves `v_min`, so `v_min`
  is read as an undervoltage (that is, as `breaker_open`) only when it is more
  than four times `v_max`.

### 5.2 Evidence → scores

`scores()` derives one score per node in four steps:

1. **Explaining away.** Once an impact leaf has command evidence of at least
   `CONFIRM_AT`, the consequence evidence on the *other* impact leaves is
   multiplied by `EXPLAINED_AWAY` (0.4). An open breaker with a confirmed write
   does not also make the operator's dispatch look like a hijack.
2. **Inference backwards.** Every node observed at `SUSPECT_AT` or more passes
   its score to its `prerequisites`. A manipulation through the HMI implies that
   the HMI was accessed, exploited and used as a pivot, even though the OT
   sensor saw none of those steps.
3. **Inference forwards.** A confirmed `it_access` or `it_exec` raises `pivot`
   to `FORWARD_WEIGHT` × its score, capped just below `CONFIRM_AT`: the chain is
   under way and the pivot is the next step. The cap keeps a forward belief from
   ever counting as confirmed, while still letting the solver see the risk and
   act before the plant is touched.
4. **Gates.** Each AND and OR node takes the maximum of its own score and its
   children's. For AND gates this is deliberately not a product: the sensor
   sees steps at the end of the chain, so a missing early step does not lower
   the belief.

| Threshold | Value | Effect |
|---|---|---|
| `CONFIRM_AT` | 0.75 | `confirmed` (or `inferred`), which is what the rules playbook fires on |
| `SUSPECT_AT` | 0.30 | `suspected`: the node is active and its prerequisites are inferred |
| `MODEL_WEIGHT` | 0.5 | the behavioural model alone never confirms a step |
| `EXPLAINED_AWAY` | 0.4 | discount on consequence evidence for the leaves not confirmed |
| `FORWARD_WEIGHT` | 0.5 | forward belief on `pivot` |

### 5.3 The snapshot

`snapshot(t)` is what the policy receives, and the interface between detection
(WP2) and response (WP3):

```python
{
  "t": …, "findings": n,
  "nodes": { id: {"score", "state", "classes", "first_seen", "last_seen"} },  # score > 0 only
  "active_impacts": [impact leaves at ≥ SUSPECT_AT],
  "hosts_implicated": [sources other than the PLC and the plant, plus the HMI once it_exec/pivot is believed],
  "next": [impact leaves on the active branch not seen yet],
}
```

A node's `state` is one of:
- `confirmed` or `suspected`, by threshold;
- `inferred` when its score comes from inference and is higher than what was
  observed on it directly;
- `unknown` otherwise.

The run's `progress.jsonl` gets a compact form of the snapshot (`tree_state`),
and only when some node changes state.

### 5.4 A worked example

The output below comes from replaying the policies on a recorded run
(`output/cps/v2b-manual-hijack`, OT sensor only, attack `manual-hijack`):

```
python -m cyberrange.scenarios.cps.responder --replay output/cps/v2b-manual-hijack --policy rules
```

| After | Belief |
|---|---|
| first finding: `behavioral_anomaly` (model, confidence 0.926 → weight 0.463) | `setpoint_oor` and `mode_hijack` suspected at 0.463; `it_access`, `it_exec`, `pivot` inferred at 0.463; the gates up to `impact` suspected |
| two `unsafe_command` (confidence 0.85): `ctrl_mode` set to MANUAL, and a 60 kW setpoint, the top of its envelope, so inside it | `mode_hijack` **confirmed** at 0.85; the prerequisites inferred at 0.85; `setpoint_oor` stays suspected |

- The **rules** policy notifies the operator on the first finding (+0.018 s
  from the first malicious write). Once `mode_hijack` is confirmed (+1.203 s)
  it fires its playbook: `block_flow`, then `force_auto`.
- The **solver** acts on the first finding already, with the same two actions
  (§6.2).

## 6. From belief to decisions

Both policies have the same interface, `decide(snapshot, t) -> Decision | None`.
A `Decision` lists:
- the actions, in execution order;
- for each action, the nodes it covers (`prevents`/`restores`);
- the cost terms;
- a rationale in words.

`Decision.explained` is true when every action except `notify` covers at least
one node and a rationale is given. The "explainable decision coverage" KPI
counts these (`explained_coverage` in `scenarios/cps/metrics.py`, which applies
the same test to the recorded decisions). An impact leaf that has not been seen yet still counts as
covered, so a block before the plant is touched is explained by what it
prevents.

Policies only add actions. Once an action is applied it stays in effect, and
the policy will not choose it again. `revert` commands exist on every
countermeasure, but nothing runs them: reverting is left to the operator.

### 6.1 Rules (the baseline)

A fixed playbook keyed on **confirmed** nodes:

| Confirmed | Actions |
|---|---|
| `it_access` | `block_web_src` |
| `it_exec` | `kill_proc_tree`, `block_flow` |
| `setpoint_oor` | `block_flow` (the PLC rejects the value and recovers on its own) |
| `breaker_open` | `block_flow`, `restore_breaker` |
| `mode_hijack` | `block_flow`, `force_auto` |

If nothing is confirmed and nothing has been applied yet, the policy notifies
the operator once and does nothing else.

### 6.2 Solver

The solver tries every subset of the allowed, not-yet-applied countermeasures
(`notify` excluded; at most 2⁶ = 64 subsets with the IT actions) and keeps the
one with the lowest cost:

```
J(A) = residual + future + 1.0·op + 0.05·time + 0.5·energy

residual = Σ over impact leaves NOT restored by A        score(leaf) · impact(leaf)
future   = 0 if A prevents pivot, else score(pivot) · max impact of the leaves A does not prevent
op, energy = sums over the new actions;  time = the slowest new action's time_to_effect_s
```

- **What it trades off.** `residual` is the damage under way that nothing
  undoes. `future` is what the attacker can still do while holding the path.
  The other terms are the price of acting. Ties go to the smaller subset.
- **Causal pairing.** A subset that restores a believed impact leaf must also
  prevent that leaf or one of its prerequisites, whenever some allowed action
  could. Restoring alone repairs the effect and leaves the attacker in place.
  It also hides the voltage evidence that would raise the belief in the path
  later, so the path would never be cut.
- **Pareto front.** The decision also returns the front over (risk, op,
  energy), for inspection.

In the example above, the solver's first decision does the following:
- **No action:** J = 1.158. `residual` = 0.463·0.6 + 0.463·0.9 = 0.695, and
  `future` = 0.463·1.0 = 0.463.
- **`force_auto` alone** would be cheapest, at J = 0.623, but it is excluded by
  causal pairing.
- **Chosen:** `block_flow` + `force_auto`, J = 0.665 (op 0.6, time 1.0 s,
  energy 0.03).

### 6.3 Approval

`isolate_hmi` is the only countermeasure that needs an operator's approval.
`--approval` controls it:
- `auto` applies it;
- `deny` removes it from what the policies may choose;
- `delay:<s>` queues it, and the SOC requests it after the delay.

`operator:<s>` is a different regime, the one of the `cps-advisor` scenario
(`docs/scenario-cps-advisor.md`): **every** countermeasure, not only
`isolate_hmi`, is put to a person and runs only if approved. A rejected one is
removed from what the policy may choose and the policy decides again on the
same belief, so the solver offers its next-best set; one left unanswered for
`<s>` seconds expires unapplied and may be proposed again on new evidence.

## 7. The attacker walks the same tree

`AttackPlanner` ([planes/attack/planner/planner.py](../cyberrange/planes/attack/planner/planner.py))
uses the tree as a plan:

1. **Candidate goals.** The impact leaves that are `feasible` on the graph,
   ordered by profile:
   - *opportunistic*: the biggest `impact` first;
   - *targeted*: only `--attack-goal`;
   - *stealthy*: the lowest `DETECTABILITY` first
     ([steps.py](../cyberrange/planes/attack/planner/steps.py)).
2. **Steps.** For a goal: its `prerequisites` in stage order
   (`it_access → it_exec → pivot`), then the leaf. Each step is one
   `exploit_client.py --step …` run on the attacker container.
3. **Re-planning.** A step that fails (a countermeasure closed the path) marks
   that path as blocked. The planner moves on to the next feasible goal that
   does not need a failed step, or stops: the episode ends as *defended*.

The planner reads the graph only through `feasible`, and the graph is not
updated during the run (§4), so it learns about the defence **only from
outcomes**. That is the realistic case: an attacker does not see the
defender's firewall, only its effect. Given the same seed, the run is
reproducible.

The attacker and the defender share the tree's node ids. That is why the
ground truth (`plan_step` with `node`, `attck`, `ok`) can be scored directly
against the defender's belief and decisions.

## 8. What is recorded

| File | Written by | Holds |
|---|---|---|
| `kg.json` | `write_structure` | the graph (node-link JSON) |
| `tree.json` | `write_structure` | attack tree, `defense` index, countermeasures with their commands |
| `response.jsonl` | the SOC analytics, on its node; downloaded with the run | `response_up`, `tree_state` (full snapshot, on change), `decision`, `approval`, `action` (per command: `rc`, output tail, issued/done times) |
| `progress.jsonl` | `SocAnalytics.mirror`, through the `TelemetryMirror` | compact `tree_state`, `decision`, `action`: what the dashboard replays |
| `ground_truth.jsonl` | the attacker | `attack_start`, `plan_step`, `rce`, `modbus_write`, `attack_end` |

`make cps-metrics` (`scenarios/cps/metrics.py`) scores the response against
what the attacker actually wrote:
- expected versus applied countermeasures, and over-response;
- responses fired before any attack (false responses);
- time to mitigation;
- how long the operator's HMI was cut off.

The dashboard draws the graph, the tree and the response over time from
`kg.json`, `tree.json` and the ledger
([scenario-cps.md §8](scenario-cps.md#8-campaigns-and-the-progress-dashboard)).

## 9. Changing them

**Changing the lab.** Edit `scenarios/cps/topology.py` (nodes, addresses,
`firewall_rules()`, `services()`, roles). The graph, the tree's addresses and
the countermeasure commands all follow on the next run. No other file needs to
change unless a role, a service or a rule that the tree relies on disappears:
`cps_context` looks them up by role and fails loudly if one is missing.

**Adding a node type or relation to the graph.** Add it in `build_kg` after the
nodes it links to, give it a typed id prefix, add a query function rather than
letting callers walk the graph, and extend `test_soar_kg.py`.

**Adding a step or an impact to the tree.** The node id is a contract shared by
several modules. A new impact leaf touches all of these:

| Where | What |
|---|---|
| `trees.cps_attack_tree` | the `Node`, with targets, ATT&CK id, `impact`, and a precondition if one applies |
| `mapping.evidence_from_finding` | which findings are evidence for it, and of which kind |
| `mapping.IMPACT_LEAVES` | so it counts as an impact (explaining away, residual, `active_impacts`) |
| `trees.cps_countermeasures` | which actions prevent or restore it |
| `policy.RulesPolicy.PLAYBOOK` / `TRIGGERS` | what the baseline does when it is confirmed |
| `planner/steps.py` `IMPACT_MODE`, `DETECTABILITY` | how the attacker realises it, and how loud it is |
| `scenarios/cps/metrics.py` `expected_response` | what a correct response to it is |
| tests | `test_soar_trees`, `test_soar_mapping`, `test_soar_policy`, `test_attack_planner` |

A new prerequisite step on an AND branch needs fewer changes:
- `prerequisites` picks it up automatically;
- the planner needs it in `PREREQ_ORDER`;
- the mapping needs a finding that observes it, or it can only ever be inferred.

**Adding a countermeasure.** Add it to `cps_countermeasures`:
- commands built from `cps_context`, not literal addresses;
- `prevents`/`restores` lists using existing node ids;
- costs on the same 0..1 scale as the others;
- an `order` placing it among the preventive (≤ 20) or restorative (30–40)
  actions.

The solver considers it at once. The rules policy uses it only once it is in
the playbook. Adding one multiplies the solver's search by two.

**Tuning the belief.** The thresholds and weights are module constants in
`mapping.py`. `test_soar_mapping.py` pins the behaviours they produce: the
model alone never confirms, PLC reactions are not evidence, an open breaker
explains away the operator's dispatch. Check those still hold before and after
changing a constant. To see the effect on real data, replay recorded runs with
`--replay` (§5.4).

## 10. Limits of the current version

- **The tree is hand-written.** It is grounded on the graph but not generated
  from it. Automatic generation is WP2 T2.2
  ([piano-wp2-wp3.md](piano-wp2-wp3.md)).
- **The CPS tree lives in the defence plane.**
  - `cps_attack_tree`, `cps_context` and `cps_countermeasures` are in
    `nodes/soc/soar_trees.py`, next to the generic tree model.
  - The mapping and the planner also hard-code CPS node ids: `IMPACT_LEAVES`,
    `FORWARD_STEPS`, the playbook, `IMPACT_MODE`.
  - None of these modules imports a scenario, so the layering test passes, but
    a second scenario with a different tree would have to split them first, the
    same way the graph's builder was split.
- **`observable` is static.** It marks the IT steps as unobservable, which is
  true of the OT sensor but not with the IT sensor running. Nothing reads it
  except the dashboard.
- **The graph and the tree are fixed for the whole run.** Applied
  countermeasures are not reflected in `reachable` or `feasible` (§4).
- **`reachable` sees only the boundary.** It ignores host firewalls and
  connection state, and only crosses zones through a host whose role is
  `boundary` (§2.4).
- **Unused code paths.** `revert` commands are never run, and `ancestors` and
  `kg.from_json` have no caller.
- **The ATT&CK mapping is a first pass.** `pivot` has no technique id yet, and
  `breaker_open` carries a review note (T0813/T0831 are also plausible).
- **Costs are nominal.** `time_to_effect_s`, `op_cost` and `energy_cost` are
  hand-set, not measured. The `action` records in `response.jsonl` (issued and
  done times) are where measured values would come from.
