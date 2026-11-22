# The cps-advisor scenario: people in the loop

## 1. What it is for

In the `cps` scenario the SOC decides and acts: a finding confirms a step of the
attack tree, the policy picks countermeasures, the Wazuh manager runs them. Here
the same SOC, on the same lab, **acts on nothing by itself**. Every
countermeasure it would run becomes a *suggestion* — what to do, on which host,
and why — and waits for an operator, who approves or rejects it. A suggestion
nobody answers expires and is not applied: no answer is not consent.

With `--teams` the attack is a person's too. Nobody drives it: a **red team**
attacks from the attacker node, a **blue team** defends from the SOC, and a
referee watches both. It is a playground, kept up until Ctrl-C. A guide for the
people playing it is in [playground-red-vs-blue.md](playground-red-vs-blue.md);
this document is how it is built.

Everything else — plant, sensors, knowledge graph, attack tree, policies,
metrics — is the `cps` scenario's ([CPS](scenario-cps.md),
[KG & attack trees](kg-and-attack-trees.md)).

## 2. Three consoles, served from three places

A team's console is also its **seat**: with `--teams` it serves a player that is
not a browser as well, so a harness can play either team from a sandboxed node
of its own (`--red-harness`, `--blue-harness`; see
[playing-with-agents.md](playing-with-agents.md)).

Each side must see only what its side knows. The ledger holds both the
attacker's writes and the SOC's decisions, so three filtered views of one page
would keep the teams apart by convention only. Each console is therefore served
by the node of the team that uses it:

| Console | Served by | Shows | Can do |
|---|---|---|---|
| **Control** | the platform's dashboard, on the host (`make dashboard`) | everything: the ledger, both teams' steps and commands on one timeline | nothing — it only reads |
| **Blue** | the SOC node (`nodes/soc/soc_operator.py`, `soc_console.html`) | *What I'm doing*: suggestions, countermeasures, responses. *What I see*: the whole attack tree coloured by the SOC's belief, findings | approve / reject, apply or revert a countermeasure by hand, switch the SOC between *advise* and *automatic*, open a shell |
| **Red** | the attacker node (`nodes/redteam/red_console.py`, `red_console.html`), `--teams` only | *What I'm doing*: the attack's steps indented under the steps they need, each done / failed / ready / waiting, and what each run printed. *What I know*: only what its own steps reported (foothold user, command execution, plant reachability, writes accepted) | run a step, open a shell |

```
 host                         lab
 ┌─ control dashboard ─┐      (reads the ledger: no way into the lab)
 │  :8765  read-only   │
 └─────────────────────┘
 blue :8766 console ────────▶ soc       soc_operator.py ⇄ soc_analytics.py ─▶ Wazuh manager
 blue :8767 terminal ───────▶ soc       ttyd → bash ── ssh ─▶ firewall, sensor, hmi (MGMT)
 red  :8768 console ────────▶ attacker  red_console.py → exploit_client.py --step …
 red  :8769 terminal ───────▶ attacker  ttyd → bash
```

**The blue console is the SOC's own.** It is node software, stdlib only, and is
what would be deployed with the SOC outside the lab. Its API, behind the blue
team's bearer token:

- `GET /state` — the SOC's view, with the suggestions;
- `GET /approvals` — the suggestions alone;
- `POST /approvals/<id>` `{"verdict": "approve" | "reject"}` — the first verdict wins;
- `POST /countermeasures/<id>` `{"op": "apply" | "revert"}` — on the operator's
  own initiative, through the manager like the SOC's own responses;
- `POST /mode` `{"mode": "advise" | "auto"}`.

**The red console is given the attack tree as data** and builds its steps on
the node (`red_steps.py`): every feasible, executable node of the tree, with the
command that realises it (`exploit_client.py --step …`). It decides nothing. A step marked *not ready*
has a prerequisite that has not succeeded; it can be tried anyway. Its API,
behind the red team's token: `GET /state` and `POST /steps/<id>`.

**Shells.** Each team has a web terminal (`ttyd`) on its node. The blue team's
is on the SOC, which is its jump host: `ssh firewall`, `ssh sensor`, `ssh hmi`
work from there, over MGMT, with a key the SOC makes at start-up and the
platform installs on those hosts. `sshd` listens on the MGMT address only and
accepts that key only.

**Every command is on record.** `nodes/common/command_audit.sh` is loaded by
every interactive bash on those hosts — web terminal or SSH — and writes one
JSON line when a command starts and one with its exit code when it ends
(`<node>.commands.jsonl` among the artifacts). Each terminal session is also
transcribed whole (`<node>.terminal.typescript`). The platform mirrors the
commands to the ledger as `team_command`, with the team, read from how the
shell got there (each record carries the shell's ancestor processes and the
address an SSH session came from). On a defended host: SSH from the SOC is the
blue team's; a shell that descends from the HMI's vulnerable app, one a service
left behind as an orphan, or SSH from any other address is the red team's;
anything else — the referee's `kathara connect` — is `control`, shown on the
ledger and kept out of the ground truth. It is a record, not a control: root on a node can switch it off, and the transcript
shows that too.

**Keeping the teams apart.** Each console and terminal needs its team's token,
fresh per run. The tokens are written to `<out_dir>/teams.json` on the host
(mode 600) and shown on the terminal the run was started from; they never
reach the run's log or the ledger, which the other
team's referee view could read. On the lab's networks the consoles' ports are
dropped by `iptables`, so the HMI cannot reach the SOC's console nor a defended
host the red one. One path remains by construction: a node with a published
port can reach the host, and through it the other team's published port — where
the token is what stops it.

**What differs from a real deployment**, and nothing else is meant to: the
token is a per-run shared secret where a deployment has the operators' identity
and TLS, and the ports are published by the container runtime instead of a
management network's routing.

## 3. What a suggestion says

Built by `ResponseEngine.explain` from what the policy already knows:

| Field | Content |
|---|---|
| `trigger` | the finding that led to it: class, detector, confidence, source |
| `prevents` / `restores` | the attack-tree nodes the action stops or undoes, each with its label, ATT&CK technique and the SOC's current belief |
| `rationale` | the policy's own justification (the playbook line, or the solver's cost comparison) |
| `countermeasure` | label, D3FEND technique, the host it runs on, the exact commands, operational and energy cost, what it interrupts while in effect, time to effect |
| `decided_with` | the other actions of the same decision |
| `cost_terms`, `alternatives` | solver only: the expected loss of the chosen set and the non-dominated alternatives it weighed |

After a verdict:

- **approved** → requested from the manager like any automatic response; its
  outcome is an `action` record as usual;
- **rejected** → never proposed again in this run. The policy decides again on
  the same belief without it, so with `solver` the operator is offered the
  next-best set (reject `block_flow` and `isolate_hmi` is proposed);
- **expired** → dropped; it may be proposed again if new evidence arrives.

## 4. How it is built on `cps`

`CpsAdvisorScenario` is the `cps` scenario with one feature, `People`
(`cyberrange/scenarios/cps_advisor/feature.py`), and its own defaults
(`--respond solver`, `--approval operator:120`). It adds no episode of its own.
`People` contributes through the features' hooks ([platform.md](platform.md)
§2, "A scenario built on another"):

- **the lab** (`extras`): the same nodes under the lab name `cps-advisor` — so
  both labs can be up side by side — plus, per node, the files, published ports
  and `iptables` rules that people need. The managed hosts (by role: the
  boundary, the sensor, the HMI) get the access scripts; the SOC also its
  console page and two published ports; with `--teams` the attacker gets the
  red console and two more;
- **the SOC** (`operator_api`): the same `SocAnalytics`, started with
  `--approval operator:<s>` and the `operator_*` arguments;
- **the blue team's access** (`services`): `WebTerminal` and `RecordedShell` on
  the SOC, `JumpHost` from it to the managed hosts, a `RecordedShell` on each of
  those;
- **the red team's access** (`engage`), after the normal phase and once the
  ground truth is open: `WebTerminal`, `RecordedShell` and `RedConsole` on the
  attacker;
- **what may be decided** (`check_approval`): only `operator:<seconds>`.

`cps-soc` uses the same feature without the SOC's console
(`People(console=False)`). The components are described in
[components.md](components.md).

What the scenario refuses before deploying anything: `--respond off` (an
advisor with no policy has nothing to suggest), an `--approval` other than
`operator:<seconds>`, `--teams` without `--playground` unless a harness sits at
each seat (the lab has to stay up for the people in it), `--teams` with
`--attack` (the attack is the red team's), a harness without `--teams` or
without what it needs from the host, and host ports that are not distinct.

## 5. Running it

```bash
make cps-image          # once (and again after an image change: ttyd is in it)
make dashboard          # terminal 1: the control view, http://127.0.0.1:8765
make cps-teams          # terminal 2: red against blue, up until Ctrl-C
```

The run prints each team's links as they become usable and writes them to
`output/cps-advisor/latest/teams.json`:

```
blue team console: http://127.0.0.1:8766/#token=…
blue team terminal: http://blue:…@127.0.0.1:8767/
red team console: http://127.0.0.1:8768/#token=…      (after the calibration)
red team terminal: http://red:…@127.0.0.1:8769/
```

Hand each team its two links and nothing else. The red team is let in only
after the sensor's model has calibrated on normal operation (`CPS_NORMAL`
seconds): an attack during calibration would be learned as normal.

Without a red team, `make cps-advisor PLAYGROUND=1` runs the scripted attack
(`CPS_ATTACK_MODE`) against the same advising SOC and blue console; without
`PLAYGROUND=1` the run ends `CPS_ADVISOR_POST` seconds after the attack.
`make cps-advisor-lab` is the same lab with no attack at all, and
`make cps-advisor-dashboard` the dashboard restricted to this scenario's runs.

A harness can sit at a team's console instead of a person. `make cps-teams
RED_HARNESS=…` (or `BLUE_HARNESS=…`) fills one seat and leaves the other to a
person; `make cps-agents` fills both, plays for `ENGAGEMENT_S` seconds at most
and scores itself; `make cps-bench` repeats those games as a campaign, to
compare harnesses. They need the players' images (`make cps-players-image`).
The harnesses, their variables and what is measured of them are in
[Harnesses as players](playing-with-agents.md).

| Variable | Default | |
|---|---|---|
| `CPS_ADVISOR_RESPOND` | `solver` | the advising policy (`rules` or `solver`) |
| `CPS_ADVISOR_TIMEOUT` | `120` | seconds a suggestion waits for its verdict |
| `CPS_ADVISOR_POST` | `180` | `cps-advisor` only: post-attack observation |
| `CPS_BLUE_PORT`, `CPS_BLUE_SHELL_PORT` | `8766`, `8767` | host ports of the SOC console and the blue shell |
| `CPS_RED_PORT`, `CPS_RED_SHELL_PORT` | `8768`, `8769` | host ports of the red console and the red shell |
| `CPS_ADVISOR_OUT` | a new one per run, under `output/cps-advisor/runs/` | run directory |

The `CPS_*` variables of the `cps` scenario for durations, detectors, the
scripted attack and IT telemetry apply unchanged. On the command line
(`python -m cyberrange.scenarios.cps_advisor.cli --help`) `--blue-token` and
`--red-token` fix a team's secret instead of drawing a fresh one per run. Every
variable is in the [reference](reference.md).

The consoles' APIs can be driven without a browser:

```bash
curl -H "Authorization: Bearer $BLUE" http://127.0.0.1:8766/state
curl -H "Authorization: Bearer $BLUE" -H 'Content-Type: application/json' \
     -d '{"verdict": "approve", "operator": "me"}' http://127.0.0.1:8766/approvals/<id>
curl -H "Authorization: Bearer $RED" -X POST http://127.0.0.1:8768/steps/it_access
```

## 6. Phases

The episode is the `cps` one
([CPS, §7](scenario-cps.md#7-running-an-experiment)); what the people change is
its middle:

| Run | Phases |
|---|---|
| `cps-advisor` | deploy → services → normal → attack → post_attack (`CPS_ADVISOR_POST` s, for the operator to answer) → download → undeploy |
| `cps-advisor-lab` | the same without attack and post_attack |
| `cps-teams` | deploy → services → normal → **open** → download → undeploy. No attack driver runs: the red team's steps are the attack |
| `cps-agents` | deploy → services → normal → **engagement** → download → undeploy |

- **services** also starts the blue team's access: its web terminal and
  recorded shell on the SOC, the jump host from it to the managed hosts.
- The red team is let in **after normal**, once the sensor's model has
  calibrated and the ground truth is open: its web terminal, recorded shell and
  console start then.
- **open** is the phase of a run held up with `PLAYGROUND=1` (always, with
  `cps-teams`): the lab stays until Ctrl-C.
- **engagement** exists when a harness sits at each seat. Both start at once,
  and the phase ends after `ENGAGEMENT_S` seconds or when both have stopped
  playing, whichever comes first.

## 7. What is recorded and scored

`response.jsonl` gains, per suggestion, an `approval` record with
`state=requested` (with `request`, `due_t`, `explanation`) and one with its
outcome (`granted` / `rejected` with `operator` and `waited_s`, or `expired`).
Every `action` says who asked for it (`by`: `soc`, or the operator's name) and
whether it applied or reverted (`op`); a change of mode is a `mode` record.

With teams, the ground truth is written from what the red team did: the first
step is the `attack_start`, each step a `red_step`, its Modbus writes the usual
`modbus_write`, and every command typed in the red shell a `command`. On the
ledger the control view also gets `team_command` (both teams) and `red_step`.

`make cps-metrics CPS_RUN=output/cps-advisor/latest` scores the run as a `cps`
run, and adds under `response.operator`: `suggestions`,
`suggestions_approved`, `suggestions_rejected`, `suggestions_expired`,
`operator_latency_median_s`.

Read the numbers with the people in mind. `decision_latency_s` includes the
operator's time; `accurate` is false when the operator rejected, or did not
answer, what the run needed. A Modbus write the red team issues by hand from
its shell, instead of through a step, is in the command record but not a
`modbus_write` of the ground truth: the impact metrics, which come from the
plant's frames, still hold, the response metrics are then indicative. And a
playground's length is whatever it was left open. There is no campaign of
human games — a run with people needs people. Harnesses seated as players are
repeated by `make cps-bench` ([Harnesses as players](playing-with-agents.md)).

## 8. Dashboard

`make dashboard`, or `make cps-advisor-dashboard` for this scenario's runs only,
is the control view: read-only, and the one place where both teams' moves are
on one timeline. It draws the `cps` panel, and with an operator or players it
has a **Players** view: the SOC's suggestions with their outcome and, in time
order, each team's steps and every command typed, with the host and the team.
A benchmark of harnesses adds a **Harnesses** tab to the campaign's results,
one row per harness, side and opponent. [The dashboard](dashboard.md) describes
the page; do not hand its address to a team during a game, because it shows the
other side.

## 9. Limits

- **The token is a per-run shared secret.** Whoever has a team's link is that
  team; a deployment would have the operators' identities and TLS.
- **The two teams are kept apart by the token on one path.** A node with a
  published port can reach the host, and through it the other team's published
  port (§2).
- **The command record is a record, not a control.** Root on a node can switch
  it off; the terminal's transcript shows that it did.
- **A Modbus write issued by hand from the red shell is not a `modbus_write` of
  the ground truth**, so the response metrics of such a run are indicative (§7).
- **Games played by people are not repeated by a campaign**, and a playground
  lasts as long as it is left open: its duration-dependent metrics do not
  compare with a timed run's.
- **Harnesses play on this scenario only.** `cps-soc` has no SOC console for a
  harness to sit at.

## 10. Quick reference

| What | Where |
|---|---|
| Scenario and feature | `cyberrange/scenarios/cps_advisor/{scenario,feature}.py` |
| Command line of one run | `cyberrange/scenarios/cps_advisor/cli.py` |
| Harnesses, their briefing and the benchmark | `cyberrange/scenarios/cps_advisor/{harnesses,briefing,campaign}.py` |
| Deploy manifest | `cyberrange/scenarios/cps_advisor/guest_files.py` |
| Dashboard panel | `cyberrange/scenarios/cps_advisor/panel.js` |
| The SOC's console | `nodes/soc/soc_operator.py`, `nodes/soc/soc_console.html` |
| The red team's console | `nodes/redteam/red_console.py`, `nodes/redteam/red_console.html`, `nodes/redteam/red_steps.py` |
| The command record | `nodes/common/command_audit.sh` |
| Make targets | `make/cps-advisor.mk` |
| For the people playing | [Red vs blue playground](playground-red-vs-blue.md) |
| For harnesses playing | [Harnesses as players](playing-with-agents.md) |
| The lab, episode and metrics it builds on | [CPS](scenario-cps.md) |
