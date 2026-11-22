# Red team vs blue team playground

A guide for the people playing and for the referee. It explains the scenario, what
each team holds and what it can do. The technical details of how it is built are in
[scenario-cps-advisor.md](scenario-cps-advisor.md) and [scenario-cps.md](scenario-cps.md).

## 1. The scenario in brief

A small low-voltage electricity-distribution plant, emulated: a line with a
distributed generator (DG) and a breaker, regulated by a PLC. The plant is a digital
twin — voltages and loads are computed, not scripted — so a wrong command really does
produce an over-voltage or a trip.

- The **red team** starts from a machine on the office (IT) network and wants to
  produce a physical effect on the plant.
- The **blue team** sits in the SOC: it sees what the sensors detect, receives the
  response system's suggestions, and decides what to apply.
- The **referee** watches both teams from a read-only dashboard.

A seat need not be a person's: a harness such as Claude Code can play either
team, at the same console and under the same rules
([playing-with-agents.md](playing-with-agents.md)). On the consoles and on the
referee's dashboard a harness's actions are marked *agent*, each with the reason
it gave. A person can give a reason too, in the *why* box next to their name.

The SOC here **does not act on its own**: it proposes each countermeasure with its
explanation and waits for a person to approve it. A suggestion left unanswered expires
and is not applied.

## 2. The map

```
      IT NETWORK 10.10.0.0/24          FIREWALL           OT NETWORK 10.20.0.0/24
   ┌────────────────────────┐   10.10.0.1 | 10.20.0.1   ┌───────────────────────┐
   │ attacker   10.10.0.10  │   ┌──────────────────┐    │ plc      10.20.0.10   │
   │ hmi        10.10.0.20  │──▶│ only HMI → engine │──▶│ engine   10.20.0.20   │
   │  (operator workstation │   │ Modbus tcp/5020   │    │  (plant, Modbus       │
   │   + diagnostics app)   │   │ passes            │    │   tcp/5020)           │
   │ ews        10.10.0.30 ─┼───┼──────────────────┼────┼─ ews      10.20.0.30   │
   └───────────┬────────────┘   └────────┬─────────┘    └──────────┬────────────┘
               │                          │                         │ passive listening
   ────────────┴──────────────────────────┴─────────────────────────┴────────────
      MANAGEMENT NETWORK (MGMT) 10.30.0.0/24
      hmi 10.30.0.30    firewall 10.30.0.1    sensor 10.30.0.10    soc 10.30.0.20
      ews 10.30.0.50
```

Four facts to keep in mind:

1. **The attacker cannot reach the plant directly.** The firewall lets a single flow
   through to the OT network: from the HMI to the engine, over Modbus.
2. **The HMI is the only door through the firewall.** It is the operator's
   workstation, it runs a vulnerable diagnostics web application, and it is connected
   to both of the networks that matter: IT and management.
3. **The engineering workstation (`ews`) is a door around it.** It stands on IT and on
   the plant's own network, as the machine that programs a PLC does. It forwards
   nothing, but whoever takes it is next to the PLC and the engine.
4. **The sensor listens without speaking.** It sees all of the OT network's Modbus
   traffic and sends what it detects to the SOC over the management network.

### The plant's commands

The plant is commanded by writing three Modbus registers on the engine:

| Register | Name | Meaning | Values |
|---|---|---|---|
| 0 | `dg_setpoint` | power requested of the generator | kW × 10; normal 200 (= 20 kW), maximum allowed 600 (= 60 kW) |
| 1 | `switch_cmd` | line breaker | 0 = closed, 1 = open |
| 2 | `ctrl_mode` | who regulates | 0 = AUTO (the PLC), 1 = MANUAL (the operator) |

In AUTO the PLC corrects a wrong setpoint by itself. In MANUAL it stands aside: what
is written stays.

## 3. How a game plays out

1. The referee starts the control dashboard and the lab:
   ```sh
   make dashboard      # http://127.0.0.1:8765
   make cps-teams
   ```
2. The lab comes up and for about a minute the plant runs normally: the sensor learns
   what normal traffic looks like. **The blue team enters right away**, the red team
   does not.
3. Once calibration is over **the red team enters** and the game begins.
4. The game runs until the referee ends it with Ctrl-C. On shutdown, everything that
   happened is saved in the run directory.

To each team the referee hands **two links**, and nothing else: the console and the
terminal. They are printed on the terminal the lab was started from (the red team's
only once calibration is over) and written to
`output/cps-advisor/latest/teams.json`. Each link carries the team's secret: whoever
has the link gets in.

| | Console | Terminal |
|---|---|---|
| Blue team | `http://127.0.0.1:8766/#token=…` | `http://blue:…@127.0.0.1:8767/` |
| Red team | `http://127.0.0.1:8768/#token=…` | `http://red:…@127.0.0.1:8769/` |

## 4. Red team

### Goal

Reach a physical effect on the plant. There are seven, differing in noise and in how
long they last:

| Effect | How | How noticeable | What happens |
|---|---|---|---|
| Out-of-range setpoint | DG power beyond the maximum | very | the PLC rejects it and recovers: it must be repeated to have an effect |
| Opening the breaker | `switch_cmd = 1` | very | the line is cut off until someone recloses it |
| Taking manual control | `ctrl_mode = 1`, then a high but legal setpoint | little | every value is within the norm and comes from the HMI; the PLC does not correct it, the effect stays |
| Ramping the setpoint | `ctrl_mode = 1`, then the setpoint raised 1 kW at a time | least | the same effect as manual control, reached with no single jump; it takes about 40 s |
| Swinging the setpoint | `ctrl_mode = 1`, then the setpoint alternated between 55 and 5 kW | fairly | the voltage swings for as long as the writes go on |
| Chattering the breaker | `switch_cmd` alternated between 1 and 0 | very | the line is cut off and restored over and over, and ends cut off |
| Lying to the PLC | from the engineering workstation, falsify the voltages the PLC reads | it writes nothing, but the position shows | the PLC raises the DG setpoint itself; lasts while the lie does (about 40 s) |

### The path

The plant is reached only by going through the HMI, in this order:

1. **Initial access**: exploit the HMI's diagnostics application.
2. **Command execution** on the HMI.
3. **Pivot**: from the HMI, reach the engine on the Modbus port.
4. **Action on the plant**: one of the six writes above.

The last effect takes another way, which does not use the flow through the
firewall: after step 2, read the engineering workstation's maintenance
credential on the HMI and **take the workstation**, which stands on the plant's
own network; from there **get between the PLC and the engine**, then falsify
the readings.

### The console

It lists these steps, each with its ATT&CK technique, how noisy it is, and the exact
command it runs. **Run** launches it and shows what it printed.

- A step marked *not ready* has a prerequisite that has not succeeded yet. You can try
  it anyway: it will fail, and you will see it.
- You run one step at a time.
- The history at the bottom keeps the outcome of every attempt.

### The terminal

A root shell on the `attacker` machine, for everything the console does not cover:
looking around the IT network, trying by hand the commands the steps automate, writing
the Modbus registers with your own parameters. The tools are already on the machine
(`exploit_client.py`, `ot_write.py`, `curl`, `python3`).

Careful: **every typed command is recorded**, and a Modbus write done by hand from the
shell, instead of from a console step, lands in the command record but not among the
scored effects. To get credit for an effect, go through the console's steps.

## 5. Blue team

### Goal

Notice the attack, ideally **before** the plant suffers for it, and stop it with the
least damage — without, for example, cutting off the legitimate operator when a block
at the boundary would do.

### The console

It shows, continuously updated:

- **Suggestions**: what the SOC proposes to do. Each suggestion says what the sensor
  saw, what the action prevents or restores, how confident the SOC is, what it costs,
  the exact commands it will run, and the alternatives it discarded. You **Approve** or
  **Reject**, with a countdown: left unanswered, it expires.
- **Countermeasures**: you can apply or revoke them on your own initiative, without
  waiting for a suggestion.
- **Attack tree**: what the SOC believes the attacker has done, step by step, with the
  level of certainty.
- **Detections** and **responses**: what the sensors flagged and what was executed, on
  which host and at whose decision.

At the top you choose the **SOC mode**:

- **Advise** (default): nothing starts without approval.
- **Automatic**: the SOC runs what its policy decides on its own. Useful for leaving it
  the obvious countermeasures and focusing on the hard decisions.

### The countermeasures

| Countermeasure | Where | Effect | Revocable |
|---|---|---|---|
| `notify` | nowhere | only warns, runs nothing | — |
| `block_flow` | firewall | blocks the Modbus flow HMI → plant at the boundary | yes |
| `isolate_hmi` | hmi | cuts the HMI off the network (the legitimate operator too) | yes |
| `force_auto` | firewall | returns control to the PLC and the setpoint to its nominal value | — |
| `restore_breaker` | firewall | recloses the breaker | — |
| `isolate_ews` | ews | takes the engineering workstation off the plant's network | yes |
| `repair_arp` | firewall | tells the PLC and the engine each other's true address again | — |

If the game is started with the IT-side sensor (`CPS_IT=1`) the SOC also sees the
early steps of the attack on the HMI, and two more countermeasures are added:
`kill_proc_tree` (kills the processes the attacker started on the HMI) and
`block_web_src` (blocks the address the attack on the diagnostics application comes
from).

`block_flow` cuts the attacker's path while leaving the HMI standing; `isolate_hmi` is
more drastic (the operator loses the workstation) and so is the one the SOC flags as
most delicate. What each countermeasure prevents or restores on the attack tree,
and what it costs, is in
[KG and attack trees §3.5](kg-and-attack-trees.md#35-countermeasures-the-defence-annotation).

### The terminal

A shell on the SOC, which is also the bridge to the other defence hosts: from here
`ssh firewall`, `ssh sensor`, `ssh hmi` work over the management network. Use it to
look at a host's state, the firewall rules, the logs — everything the console does not
show. Here too every command is recorded.

### On the SOC's tools (`make cps-soc-teams`)

The same game, with the blue team on the tools of a real SOC instead of the SOC's
console (technical details in [scenario-cps-soc.md](scenario-cps-soc.md)). The blue
team's links, written to `output/cps-soc/latest/teams.json`, are three: the
terminal, the **SIEM** (the Wazuh dashboard, with the run's login) and the **cases**
(DFIR-IRIS, same login). The certificates come from the lab's own authority: the
browser asks for an exception once.

- **Suggestions are tasks** of the run's case in IRIS. Close a task to approve it,
  cancel it to reject it; one left open expires.
- **Applying or revoking a countermeasure by hand**, and switching the SOC between
  *advise* and *automatic*, are entries of IRIS's menus: on a countermeasure's task,
  and on the case.
- **The attack tree and the knowledge graph** are in the Wazuh dashboard
  (*Attack tree*), coloured by what the SOC believes; the time picker shows them as
  they were at any moment. The case summary in IRIS carries the tree as text.
- **Alerts** worth a look arrive on IRIS's *Alerts* page, to merge into the case,
  escalate or close.

## 6. Referee (control dashboard)

`make dashboard`, read-only: it cannot act on the lab. It sees everything the two
consoles keep apart, on a single timeline:

- the run's phases and the plant's state;
- views as tabs: **Match** to referee (the kill chain, both teams side by side,
  the plant), **Structure** for the topology and the attack tree, **Attacker**
  and **Defender** to show each team, after the game, what the other did and
  saw at the same moment, **Players** for what each team ran;
- the **kill chain**: for every attack step, when the attacker did it, when the
  defender first suspected and confirmed it, and what stopped it; with the time to
  detect, to respond and to impact;
- the game's **journal**, in a column beside whichever view is open, filtered by
  team; a click on a row takes the dashboard to that moment;
- the **Attacker · Defender** card: for each team what it is doing and what it sees,
  and a lane timeline (attacker, defender, plant). The time bar at the top of the page
  takes everything to any moment of the game: ◀ ▶ step from fact to fact, Play
  replays it;
- the SOC's **suggestions** with their outcome (approved, rejected, expired), as a
  history;
- the **Teams** card (in the *Players* view) with, in time order, the red team's steps, the blue team's actions
  and **every command typed by either**, with the host and the team.

On a defence host, a command's team is read from how the shell arrived there:

- **blue** — over SSH from the SOC;
- **red** — a shell obtained through the HMI's vulnerable application (or left running
  by a service), or SSH from a host that is not the SOC: the sign that the attacker has
  taken that host;
- **control** — everything else, i.e. the referee's shell (`kathara connect`). It
  appears in the Teams card but not in the `ground_truth`: the referee can look inside
  a node without it counting as an attack.

## 7. What keeps the two teams apart

- Every console and every terminal requires its own team's **token**. The tokens
  differ, are generated per game, and never land on the record the referee reads.
- On the lab networks the consoles' ports are closed: from the HMI you cannot reach the
  blue team's console, nor the other way round.
- One technical path remains: a node with a published port can reach the host and from
  there the other team's port. The only thing stopping it is the token — so **do not
  share your links outside your team**.

## 8. What is left after the game

In the run directory (`output/cps-advisor/latest/`):

- `ground_truth.jsonl` — what really happened (red team steps, Modbus writes,
  commands);
- `progress.jsonl` — the timeline the referee saw;
- `response.jsonl` — the SOC's suggestions, verdicts and actions;
- `<host>.commands.jsonl` and `<host>.terminal.typescript` — the commands and the
  transcript of each terminal;
- `teams.json` — the links handed to the teams.

The score is computed as for the `cps` scenario:
`make cps-metrics CPS_RUN=output/cps-advisor/latest`. Keep in mind that here the timings
include the operators', and that an effect obtained with a hand-written shell write
(instead of a step) shows in the plant but not among the scored effects.
