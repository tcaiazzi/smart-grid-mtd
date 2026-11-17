# Attacks and defences

A reading guide to what the platform can attack with and defend with. This is the
narrative view; [Components](components.md) is the full reference, with every hook and
constructor argument, and the source is each plane's `components.py`.

Every attack records what it really did in the run's **ground truth** (host-side, so
the in-lab sensors never see the oracle). Every guest sensor emits
telemetry-shaped events that the ledger mirrors onto the dashboard.

## Attacks (`cyberrange/planes/attack`)

### Cyber-physical (CPS scenarios)

| Component | What it does |
|---|---|
| **VulnApp** | A deliberately vulnerable diagnostics web app with a command injection — the attacker's foothold on the HMI. Its access log makes its requests observable to the IT sensor. |
| **ScriptedChain** | A fixed per-mode chain: RCE → pivot → unauthorized Modbus writes. The simplest driven attack. |
| **PlannedAttacker** | A reactive, tree-guided attacker that chooses each step on an attack tree, by profile (opportunistic / targeted / stealthy). It runs **in the lab**; the tree is handed to it as data. |
| **ReconAttacker** | Like `PlannedAttacker`, but **not** handed the tree: it derives one by reconnaissance (nmap on the IT side, then living off the land on the compromised HMI) and plans on that belief tree. The `cps-recon` scenario. |
| **RedConsole** | The same steps as the planner, but run **by a person** one at a time from a console on the attacker node — the red team's seat in the playground. |

The physical effects an attack aims for differ in how noisy and how durable
they are: pushing the DG setpoint out of range (loud, the PLC recovers), opening the
line breaker (loud, stays open until reclosed), and taking manual control then
writing a high-but-legal setpoint (quiet, the PLC does not correct it). Three more
vary their writes over time: ramping the setpoint up in small steps (the quietest),
swinging it between two legal levels, and opening and re-closing the breaker over
and over. The
[playground guide](playground-red-vs-blue.md) lays them out for players.

### MQTT smart grid

| Component | What it does |
|---|---|
| **PassiveFingerprinter** | The passive attacker on the broker-side link: it sniffs, fingerprints the nanogrid's traffic with a trained CNN, and picks the source IP to **blackhole**. |
| **DeliveryAttack** | Blackhole episodes on the router (the CNN's pick, or an oracle's) plus benign faults, all recorded in the ground truth — the detection scenario. |

## Defences (`cyberrange/planes/defense`)

Detection and response, proactive and reactive:

| Component | What it does |
|---|---|
| **MtdCoordinator** | Moving-target defence on the SEMP (the MQTT lab's broker node), on fixed timers or driven by an RL policy — the MQTT scenario's proactive defence. |
| **QkdCertBootstrap** | Delivers the MQTT lab's mutual-TLS bundle over a QKD-simulated channel. |
| **OtSensor** | Passive Modbus DPI on the OT link (rules plus a learned model); emits findings on its management NIC. |
| **ItSensor** | A host sensor on the HMI — web log, processes, connections — that confirms the early, IT-side steps of an attack. |
| **WazuhManager** / **WazuhAgent** | The SOC's Wazuh manager on the management network, and the hosts reporting to it and running its active responses. |
| **SocAnalytics** | The SOC's decision loop on the manager's node: alerts → attack tree → policy → responses asked of the manager, or **put to an operator** when the SOC only advises. |
| **JumpHost** | SSH from the defenders' node to the hosts they manage. |

The response loop — how `SocAnalytics` turns alerts into countermeasures through the
knowledge graph and attack tree — is covered in
[SOAR — KG & attack trees](kg-and-attack-trees.md). The countermeasures themselves,
and which are revocable, are in the [playground guide](playground-red-vs-blue.md).
