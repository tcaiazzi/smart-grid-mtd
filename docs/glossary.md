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
`components.py`. A **guest agent** is a component that launches code *inside* a
container.

**Episode** — the phases a scenario run goes through (deploy, calibrate, attack,
respond, score, …), composed from components.

**Topology** — the declarative description of a lab: nodes, links, addresses, routes
and zones. See [Architecture](platform.md).

**LabSpec** — the CPS lab as data: zones, hosts by role, services, the flows the
boundary forwards. The `Topology`, the firewall's rules and the SOC's inventory are
derived from it.

**Campaign** — many configurations × seeds run and scored together, aggregated with a
95% confidence interval; resumable. See [Running and measuring](running-and-metrics.md).

**Ledger / progress stream** — the `progress.jsonl` timeline of a run that the
**dashboard** reads, live or in replay.

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
computed, not acted, so a wrong command really produces an over-voltage or a trip.

**DG** — Distributed Generator, the generator on the emulated low-voltage line.

**Feeder / unit** — one low-voltage line of the plant, with its load, generator and
breaker. The engine serves each feeder as a Modbus **unit** of its own, with the same
register map; the plant's description (`ot_registers.plant()`) lists them.

**DPI** — Deep Packet Inspection; the OT sensor passively inspects Modbus traffic.

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

**SOC** — Security Operations Center; in the CPS lab it runs **Wazuh** plus analytics
that detect, decide and respond — or, in `cps-advisor`, *advise* an operator. In
`cps-soc` the blue team also has a SIEM (the Wazuh indexer and dashboard) and case
management (**DFIR-IRIS**).

**Wazuh** — the open-source security platform used as the SOC's manager and agents,
with active responses. See [Components](components.md).

**SOAR** — Security Orchestration, Automation and Response: the SOC's decision loop
from alerts to countermeasures. See [SOAR — KG & attack trees](kg-and-attack-trees.md).

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
`force_auto`); several are revocable. See the [playground guide](playground-red-vs-blue.md).

**QKD cert bootstrap** — the mutual-TLS bundle the SCMC and the SEMP share, delivered
over a QKD-simulated channel; a defence component of the MQTT lab.
