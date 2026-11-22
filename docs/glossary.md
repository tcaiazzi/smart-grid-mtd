# Glossary

Terms that recur across the documentation, each with a pointer to where it is used.

## Platform concepts

**Cyber range** — an environment for running attacks and defences against emulated
systems safely, reproducibly and observably. This repository is one, for smart-grid
security.

**Scenario** — one experiment, whole: its lab topology, episode, entry point,
campaign, metrics and analysis, in a single directory. The five here are `mqtt-mtd`,
`cps`, `cps-advisor`, `cps-recon` and `cps-soc`. See [the scenario pages](index.md#the-scenarios).

**Feature** — one addition to the CPS scenario (people in the loop, the SOC's tools,
a recon attacker), with hooks on the options, the lab and the episode. A CPS
scenario is `cps` with a tuple of features. See [Architecture](platform.md).

**Plane** — one of the four families of reusable building blocks a scenario composes:
**traffic**, **attack**, **defense**, **monitor**. See [Components](components.md).

**Component** — a reusable building block of a plane, declared in that plane's
`components.py`: it stages, starts and collects something in the lab.

**Guest agent** — the program a component runs *inside* a container. It is copied
there as a flat file and can import only the standard library and what its node's
image installs. In code, `GuestAgent` is the component class that launches one.

**Node software** — what a lab node does at run time that is not the platform's:
Wazuh and its configuration, the SOC's analytics, the red team's agent, the players'
nodes. It lives under `nodes/`. See [Where files go](structure.md).

**Lab** — the emulated network a scenario deploys: Kathará nodes on collision
domains, described by a **Topology**.

**Run** — one seeded execution of a scenario's episode on a freshly deployed lab,
with a directory of its own. See [Running and measuring](running-and-metrics.md).

**Episode** — the phases a run goes through, composed from components. For the CPS
scenarios: `deploy`, `services`, `normal`, `attack`, `post_attack`, `download`,
`undeploy`, with `engage` and `open` when people or harnesses play.

**Topology** — the declarative description of a lab: nodes, links, addresses, routes
and zones. See [Architecture](platform.md).

**LabSpec** — the CPS lab as data: zones, hosts by role, services, the flows the
boundary forwards. The `Topology`, the firewall's rules and the SOC's inventory are
derived from it.

**Campaign** — many configurations × seeds run and scored together, aggregated with a
95% confidence interval; resumable. See [Running and measuring](running-and-metrics.md).

**Ledger / progress stream** — the `progress.jsonl` timeline of a run that the
**dashboard** reads, live or in replay. See [The dashboard](dashboard.md).

**Telemetry** — what a sensor in the lab reported, kept in a stream of its own
(`<node>.telemetry.jsonl`), apart from the ledger and from the ground truth.

**Artifact** — a file a run leaves in its directory. The [reference](reference.md#artifacts)
lists them.

**Run card** — `run.json`: the commit, the lab, the images and the options a run was
made with, and how it ended.

**Playground** — a lab kept up for people instead of being torn down after the
episode (`PLAYGROUND=1`), and by extension the red-vs-blue exercise. See the
[playground guide](playground-red-vs-blue.md).

**Ground truth** — the host-side record of what really happened (attack steps, Modbus
writes, footholds), kept off the lab so the in-lab sensors never see it.

**Guest path** — the flat filename a file takes once copied into a container; it is a
contract and cannot change. The host path it comes from is free.

## Emulation and OT

**[Kathará](https://github.com/KatharaFramework/Kathara)** — the container-based
network emulator that deploys the labs.

**OT / IT** — Operational Technology (the plant and its controllers) vs Information
Technology (the office/enterprise network). The CPS scenarios turn on the boundary
between them.

**Modbus** — the industrial protocol the plant speaks; the attack's goal is
unauthorized Modbus **writes** to the plant's registers.

**PLC** — Programmable Logic Controller, the device that regulates the plant. In AUTO
it corrects a bad setpoint; in MANUAL it leaves what is written in place.

**HMI** — Human-Machine Interface, the operator's workstation; in the CPS lab it is
the only host the firewall lets reach the plant, and the attacker's way in.

**EWS** — the engineering workstation, on IT and on the plant's own network, as the
machine that programs a PLC is; the attacker's other way to the plant, around the
firewall.

**Engine** — the physical-plant twin (a pandapower model): voltages and loads are
computed, not scripted, so a wrong command really produces an over-voltage or a trip.

**DG** — Distributed Generator, the generator on the emulated low-voltage line.

**Feeder / unit** — one low-voltage line of the plant, with its load, generator and
breaker. The engine serves each feeder as a Modbus **unit** of its own, with the same
register map; the plant's description (`ot_registers.plant()`) lists them.

**pu (per unit)** — a voltage as a fraction of its nominal value: 1.05 pu is 5 %
above nominal. The plant is normal inside a band around 1.

**Digital twin** — a computed model standing in for the physical system: here the
engine, whose power flow answers every command.

**DPI** — Deep Packet Inspection; the OT sensor passively inspects Modbus traffic.

**Finding / alert** — a **finding** is what a sensor reports; an **alert** is what
the Wazuh manager makes of it and hands to the SOC.

**SEMP** — the operator's node in the MQTT lab: it runs the MQTT broker and the MTD
coordinator. See [MQTT MTD](scenario-mqtt.md).

**SCMC** — the nanogrid's node in the MQTT lab: it publishes the grid's telemetry
(physics simulated with pymgrid) to the broker on the SEMP over mutual TLS.

**Nanogrid** — the small grid whose MQTT traffic the MQTT scenario protects; the
passive attacker **fingerprints** it to pick a source IP to **blackhole** (drop).

## Defence and response

**MTD (Moving Target Defense)** — proactively changing the system's observable
configuration so an attacker's knowledge goes stale. The MQTT scenario's MTD
coordinator does this on the SEMP, on a fixed timer or driven by an **RL** policy.

**RL coordinator** — a reinforcement-learning policy, trained offline and distilled to
numpy for the lab, that decides when the MTD should move.

**SOC** — Security Operations Centre; in the CPS lab it runs **Wazuh** plus analytics
that detect, decide and respond. In `cps` it acts by itself (*auto* mode); in
`cps-advisor` it *advises*: each countermeasure is a **suggestion** an operator
approves or rejects, and one nobody answers expires. In `cps-soc` the blue team
also has a SIEM (the Wazuh indexer and dashboard) and case management
(**DFIR-IRIS**).

**SIEM** — Security Information and Event Management: where alerts are stored,
searched and drawn. In `cps-soc`, the Wazuh indexer and dashboard.

**DFIR-IRIS** — the open-source case-management platform of `cps-soc`: the SOC's
suggestions arrive there as tasks of a case. See [CPS SOC](scenario-cps-soc.md).

**Wazuh** — the open-source security platform used as the SOC's manager and agents,
with active responses. See [Components](components.md).

**SOAR** — Security Orchestration, Automation and Response: the SOC's decision loop
from alerts to countermeasures. See [SOAR — KG & attack trees](kg-and-attack-trees.md).
The name also labels two things in `cps-soc`: the network DFIR-IRIS's own services
talk on, and `nodes/soar/`, IRIS's set-up.

**Belief** — what the SOC currently holds about each node of the attack tree:
*confirmed*, *suspected*, *inferred* or unknown. The policy decides on it.

**Policy** — how the SOC turns its belief into countermeasures: `rules`, a fixed
playbook, or `solver`, which picks the subset with the lowest expected cost.

**Approval** — whether a high-impact countermeasure needs a yes: `auto`, `deny`,
`delay:<s>` (simulated), or `operator:<s>` (a person, or a harness, at the console).

**KG (Knowledge Graph)** — the model of the system and its weaknesses that the attack
tree is grounded on. See [SOAR — KG & attack trees](kg-and-attack-trees.md).

**Attack tree** — the stepwise model of how an attacker reaches a goal, generated from
the knowledge graph. It is handed to the attacker in `cps`/`cps-advisor`, and
*derived by reconnaissance* by the attacker in `cps-recon`, with the same generator;
the SOC uses it to interpret what it sees.

**Step kind** — what a node of the attack tree is (`breaker_open`, `pivot`, …). It is
the node's id, unless the step recurs on several ways in or feeders, where the id is
qualified (`breaker_open@hmib:u2`) and the kind is what consumers read.

**Countermeasure** — a response the SOC can apply (e.g. `block_flow`, `isolate_hmi`,
`force_auto`); several are revocable. The table of them is in
[KG and attack trees §3.5](kg-and-attack-trees.md#35-countermeasures-the-defence-annotation).

**ATT&CK** — MITRE's catalogue of adversary techniques; each step of the attack tree
carries the id of the ICS technique it is.

**Reconnaissance (recon)** — what the attacker of `cps-recon` does instead of being
handed the tree: it scans, then looks around from the host it took, and builds a
**belief tree** of its own. **Tree fidelity** scores that tree against the true
one, as precision and recall. See [CPS recon](scenario-cps-recon.md).

**Attacker profile** — how the tree-guided attacker chooses its steps:
opportunistic, targeted or stealthy.

## People and players

**Red team / blue team** — the attackers and the defenders of a game. The glossary
of roles used across these pages: the **attacker** (red), the **defender** (blue,
the SOC and its operator) and the **referee**, who watches the dashboard and plays
neither side.

**Seat** — a team's place in a game: its console and its shell, on its own node. A
seat is taken by a person or by a harness.

**Harness** — an agent program (Claude Code, a scripted player, …) seated as a
player. See [Harnesses as players](playing-with-agents.md).

**Engagement** — the part of a game in which two harnesses play, bounded in time
and in tool calls.

**Scorecard** — what a game records of each player under `players` in
`metrics.json`: calls, steps, waits, shell commands.

**Benchmark** — the campaign that repeats games per harness, as red and as blue,
against graded scripted opponents (`make cps-bench`).

**QKD cert bootstrap** — the mutual-TLS bundle the SCMC and the SEMP share, delivered
over a QKD-simulated channel; a defence component of the MQTT lab.
