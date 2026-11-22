# The cps-soc scenario: a real SOC's tools for the blue team

## 1. What it is for

`cps-soc` is the [`cps-advisor`](scenario-cps-advisor.md) scenario with the
tools of a real Security Operations Centre in the lab. The plant, the sensors,
the SOC's analytics and its policy stay exactly as they are. So does the
episode: a SOC that advises, an operator who decides, and with `--teams` a red
team against a blue team.

What changes is where the blue team works. In `cps-advisor` it uses the SOC's
own console. Here that console is replaced by two open-source products:

| Tool | Products | What the blue team does there |
|---|---|---|
| **SIEM** | Wazuh indexer + Wazuh dashboard 4.14.10, the same version as the lab's Wazuh manager | searches the alerts; follows the attack tree and the knowledge graph, coloured by the SOC's belief |
| **Case management** | DFIR-IRIS v2.4.29 (web, app, worker, Postgres, RabbitMQ) | approves or rejects each countermeasure the SOC proposes; triages the alerts; applies or reverts a countermeasure by hand |

Each service runs on its own node, as its project's official deployment runs
it. The new nodes are the defence's tooling, not part of the plant: the SOC's
inventory and its knowledge graph do not include them.

It is a scenario of its own, rather than an option of `cps-advisor`, because
its lab adds seven nodes and about 3 GB of memory. No `cps` or `cps-advisor`
run should pay for that.

## 2. The lab

The `cps` lab, as `cps-advisor` extends it, plus seven nodes:

| Node | Image | Address | Service | Memory, at steady state |
|---|---|---|---|---|
| `indexer` | `kathara/wazuh-indexer` | MGMT 10.30.0.21 | Wazuh indexer (OpenSearch, 1 GB heap) | 1.43 GB |
| `wazuhui` | `kathara/wazuh-dashboard` | MGMT 10.30.0.22 | Wazuh dashboard, published on `--siem-port` | 0.19 GB |
| `irisweb` | `kathara/iris-web` | SOAR 10.40.0.1, MGMT 10.30.0.40 | IRIS's nginx, published on `--cases-port` | 0.01 GB |
| `irisapp` | `kathara/iris-app` | SOAR 10.40.0.10 | IRIS application, with the SOC's IRIS module | 0.18 GB |
| `irisworker` | `kathara/iris-app` | SOAR 10.40.0.11 | IRIS's Celery worker | 0.97 GB |
| `irisdb` | `iriswebapp_db:v2.4.29` (unmodified) | SOAR 10.40.0.20 | Postgres | 0.05 GB |
| `irismq` | `rabbitmq:3.13.7-management-alpine` (unmodified) | SOAR 10.40.0.30 | RabbitMQ | 0.13 GB |

The SOC node moves to `kathara/soc-siem`, which adds Filebeat to the Wazuh
manager (+0.26 GB). Filebeat ships the alerts to the indexer, as on a Wazuh
server.

`SOAR` (10.40.0.0/24) is IRIS's own back-end network, like the back-end network
in IRIS's compose file. Only IRIS's web front also sits on MGMT.

The HMI, which is where the attacker gets in, is on MGMT too. Each tool node
therefore accepts traffic on MGMT only from the hosts that need it:

- the indexer from the SOC and the dashboard;
- IRIS's web front from the SOC;
- the Wazuh dashboard from nobody on the lab: the team reaches it through its
  published port only.

`only_from()` in `cyberrange/scenarios/cps_soc/scenario.py` writes these rules.

**Images.** The services' images are pinned, each with a thin layer of our own
(`docker/wazuh-*`, `docker/iris-*`). That layer does four things:

- It makes the container root, because Kathará runs a node's startup commands
  as the image's user. Each service still drops to its own user.
- It adds `ip`, `iptables` and `tar`. Kathará copies a node's files by
  unpacking a tar inside the container.
- It sets `WORKDIR /`.
- It copies the lab's certificates.

`kathara/wazuh-pki` is the lab's only certificate authority, so the services
trust each other. Its certificates name the services, not addresses
(`wazuh.indexer`, `wazuh.dashboard`, `wazuh.manager`, `iris.lab`). The nodes
that dial a service find its address in their own `/etc/hosts`, which the
scenario writes from the lab at start-up, and TLS checks the name. A lab that
moves the tools therefore needs no new image.

**Startup.** Each tool node starts idle on a shell (`Node.entrypoint`). A
component then starts its service, once the lab has addressed and configured
the node. Both interfaces answer about 20 s after the deploy, well inside the
normal-operation phase.

**Secrets.** Every secret is drawn per run: the indexer's users, IRIS's keys
and passwords, and the blue team's login. The team receives them only through
`teams.json`.

## 3. How the SOC's work reaches the tools

**Suggestions become IRIS tasks.** `nodes/soc/iris_desk.py` gives the SOC the
same desk interface as its own console, so nothing else in the SOC changes.
Each countermeasure the SOC proposes is filed as a task of the run's case, with
its reasons, the attack-tree nodes it covers and its commands. The analyst
closes the task to approve it or cancels it to reject it. A task nobody answers
is cancelled at expiry with the note "Expired". Filing is idempotent: IRIS's
first requests can be slow, and a retried request adopts the task already
filed.

**The SOC's levers are IRIS menu entries.** A module of our own,
`nodes/soar/iris_soc_response/`, adds them the way IRIS's official modules
add theirs:

- on a countermeasure's task: apply or revert it;
- on the case: let the SOC act alone, or have it advise.

At start-up the SOC files the lab's countermeasures in the case as a catalogue,
one *On hold* task each. Choosing a menu entry files an order task. The SOC's
desk takes the order, runs it the same way the console would, and closes it.
IRIS is the only channel: IRIS's worker cannot reach the SOC.

The order format lives in one file (`orders.py`), copied both into the module
and onto the SOC, so the two cannot drift apart.

**Wazuh alerts land in IRIS's triage.** A custom Wazuh integration
(`nodes/wazuh/manager/iris_forward.py`) forwards two kinds of alert to IRIS's
*Alerts* page:

- an OT sensor alert when it opens (rule 100101);
- every IT sensor finding on the HMI (rule 100100).

Repeats within 120 s (same host, rule, class and source) update the open alert's
"Seen N times" note instead of opening another. The analyst merges each alert
into the case, escalates it or closes it.

**The attack tree and the knowledge graph in both tools.** `nodes/soc/belief_feed.py`
feeds the Wazuh manager one event per tree node and one per graph node and edge:
all of them at start-up, then only those that change.

- **In Wazuh.** The *Attack tree* dashboard (`nodes/wazuh/dashboard/*.vega.json`)
  draws both views from the alerts. Moving the time picker back shows the tree
  as it was at that time.
- **In IRIS.** The case summary carries the tree as text, because IRIS filters
  SVG and HTML everywhere. The hosts are the case's *Assets*: an implicated host
  is marked "compromised" once, without overwriting the analyst's notes. Each
  confirmed or inferred leaf is a *Timeline* event whose category is its ATT&CK
  tactic.

What the feed delivered is kept as `soc.belief.jsonl` among the run's
artifacts. The extra alerts are low-level (rules 100130–100132), and nothing
acts on them.

## 4. How it is built on cps-advisor

`cps-soc` is the `cps` scenario with two features (`docs/platform.md`):
`(SocTools(), People(console=False))`. `People` is `cps-advisor`'s, without the
SOC's console. `SocTools` (`cyberrange/scenarios/cps_soc/feature.py`) does four
things:

- **`extras` and `nodes`**: puts the SOC on its new image and adds the seven
  tool nodes;
- **`prepare`**: draws the run's secrets;
- **`operator_api`**: hands the SOC an IRIS desk and a belief feed;
- **`services`**: starts the tools, before the people's own services, because
  it is listed first.

Everything else, including the episode, the teams and the scoring, is
`cps-advisor`'s.

## 5. Running it

```bash
make cps-image          # once
make cps-soc-image      # once: the lab CA, the SOC + Filebeat, Wazuh indexer/dashboard, IRIS
make dashboard          # terminal 1: the control view, http://127.0.0.1:8765
make cps-soc            # terminal 2: scripted attack; suggestions wait as IRIS tasks
```

The other targets:

- `make cps-soc-lab`: the same lab with no attack (`PLAYGROUND=1` keeps it up).
- `make cps-soc-teams`: red team against blue team, up until Ctrl-C.
- `make cps-soc-dashboard`: the control dashboard restricted to this scenario's
  runs.

The run writes the blue team's links, with the run's login, to
`output/cps-soc/latest/teams.json`:

```
blue team siem: https://127.0.0.1:8770/  (login blue / …)
blue team attack tree: https://127.0.0.1:8770/app/dashboards#/view/cps-attack-tree
blue team cases: https://127.0.0.1:8771/  (login blue / …)
blue team terminal: http://blue:…@127.0.0.1:8767/
```

The certificates come from the lab's own authority, so the browser asks for an
exception once.

| Variable | Default | |
|---|---|---|
| `CPS_SIEM_PORT` | `8770` | host port of the Wazuh dashboard |
| `CPS_CASES_PORT` | `8771` | host port of IRIS |
| `CPS_SOC_OUT` | a new one per run, under `output/cps-soc/runs/` | run directory |

The `CPS_ADVISOR_*` variables (policy, timeout of a suggestion, post-attack
observation) and the `CPS_*` variables of `cps` apply unchanged.

The host needs about 3 GB of free memory beyond what a `cps-advisor` run uses.

## 6. What is recorded and scored

As in `cps-advisor`, the ledger receives `approval` events, and
`response.operator` in the metrics counts suggestions approved, rejected and
expired. The approver is the IRIS account that closed the task (`blue`). An
order from IRIS's menu carries the analyst's login (`by:<login>`).

The run's artifacts also include:

- the indexer's and IRIS's console logs;
- `soc.belief.jsonl`, the belief delivered to the SIEM.

## 7. Known limits

- The published ports (8770, 8771) are protected only by the run's credentials,
  as the consoles of `cps-advisor` are by their tokens.
- IRIS's asynchronous module hooks do not work in 2.4.29: the worker does not
  load the key it checks queued data with. The SOC's menu entries are therefore
  registered as synchronous, and IRIS's app runs them within the analyst's
  request.
- The tools take host numbers .21, .22 and .40 on the SOC's network. A lab
  whose own hosts use one of them is refused when the tools are added.
