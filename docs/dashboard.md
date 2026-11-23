# The dashboard

One page follows every run and every campaign of every scenario, while it runs
and after it has ended. This is the guide to using it. How a scenario draws its
own part of the page — the panel hooks and helpers — is in
[Architecture, §5](platform.md#5-following-it-live).

Three other pages in this repository are also called dashboards and are not this
one: the **live MTD dashboard** that `semp` serves during an MQTT run
([MQTT MTD, §8](scenario-mqtt.md#8-the-live-mtd-dashboard)), the **SOC's console**
where an operator answers suggestions ([CPS advisor](scenario-cps-advisor.md)), and
the **Wazuh dashboard** and **DFIR-IRIS** of `cps-soc`
([CPS SOC](scenario-cps-soc.md)).

## 1. Starting it

```bash
make dashboard              # every scenario's runs and campaigns under output/
make cps-dashboard          # only the cps runs
make cps-advisor-dashboard  # only the cps-advisor runs
make cps-recon-dashboard    # only the cps-recon runs
make cps-soc-dashboard      # only the cps-soc runs
```

Then open <http://127.0.0.1:8765>. Leave it running in a terminal of its own;
Ctrl-C stops it.

| Variable | Default | |
|---|---|---|
| `CPS_DASH_PORT` | `8765` | the port, for all five targets |
| `OUTPUT_ROOT` | `output` | the directory searched for ledgers |

The targets run `python -m cyberrange.core.dashboard`, which also takes
`--scenario <name>` (what the per-scenario targets pass: it filters on the
scenario each run recorded, not on where the run was written) and `--host`. The
server binds `127.0.0.1` unless told otherwise, so by default the page is
reachable only from the machine that runs it.

The dashboard only reads files. It has no endpoint that changes anything, in the
lab or on disk, and it needs no cooperation from a run: start it before, during
or after one. The page loads nothing from another host — its libraries are files
of this repository — so it works on a lab machine without internet access.

## 2. What it reads

Every run and every campaign writes a progress ledger, `progress.jsonl`, in its
output directory ([Running and measuring](running-and-metrics.md)). The server
walks its root for ledgers, at most every 10 s, and the page polls it:

- a ledger still being written is shown **running**, and the page follows it
  live;
- a finished one is **replayed** from the same file, with the same views;
- a ledger whose writer stopped touching it for 30 s without closing it is
  shown **interrupted**.

The badge next to the title gives the time the page last heard from its server,
or says that it is not updating and why. Event kinds that no view shows are
counted at the foot of the page, and an empty table says why it is empty.

## 3. The page

A **band** at the top stays in sight while the page scrolls: the experiment
chosen, its state in one line, the server badge, the theme button and the time
bar. Under it, three columns:

- on the left, the **runs** of the experiment, one per line; a click shows that
  run. Open by default when there is more than one;
- in the middle, the **views**, as tabs. Each holds the cards that answer one
  question, so a view is read without scrolling past the others. A scenario
  with a panel composes its own; without one the page has two, *Run* and
  *Campaign*. A card with nothing to show is left out, and so is a tab whose
  cards all are;
- on the right, what a panel **docks** beside the views, in sight whichever tab
  is chosen (the CPS journal).

The two side columns are opened and closed by the buttons in the band and sized
by dragging the handle between columns. Under 1100 px of width they open over
the view instead of beside it. Every card can be closed (▾) and explains itself
(ⓘ). A long list — a journal, a table of results — draws only the rows in
sight, is ordered by a click on a column's header, and keeps the reader's place
when a live run adds a row.

Common to every scenario:

- the list of ledgers, with the scenario of each;
- a campaign's progress and ETA, and the table of its runs;
- the current run's phases;
- the **results of the run shown**, once it is scored: every metric it recorded,
  in one list filtered by kind or by name. In a campaign, each metric stands
  beside the campaign's mean and 95% CI for runs of the same mode;
- the campaign's results, with a mean [95% CI] tab.

## 4. The time bar

One bar, in the band, sets the time every time-aware card is drawn at, on the
run's own clock:

- the slider is a time; a live run is laid on its planned length, so the thumb
  does not jump as facts arrive;
- ◀ ▶ step through the facts the scenario marks (an attack step, a detection,
  a countermeasure);
- **Play** replays the run at ×1, ×5 or ×20;
- **Live** goes back to following the run.

Keys, outside a text field: ←/→ previous or next fact, Shift+←/→ ten seconds,
Space play or pause, End live.

## 5. Links into the page

| Parameter | Opens |
|---|---|
| `?show=<view>` | the page on that view (tab). The page keeps it up to date in the address, so the address of what you are looking at is a link to it |
| `?run=<run_id>` | that run |
| `?view=topology\|kg\|tree` | the structure card on that drawing (topology by default) |

`?view=tree&run=<run_id>` opens a run's attack tree directly.

## 6. What each scenario adds

**CPS** (`cps`, and the three scenarios built on it). Six views:

- **Match**, the one the page opens on: the kill chain, the run's results, the
  Attacker · Defender card, the plant's voltage chart and the findings;
- **Structure**: topology, knowledge graph and attack tree;
- **Attacker**: only the attacker — its steps, plans and reconnaissance, and
  the tree as it knows it;
- **Defender**: only the defender — what it saw and believed and when, its
  decisions, the tree as it believes it;
- **Players**: the operator's suggestions and what each team did. Present only
  when a run has an operator or players. Once a run with a harness at a seat is
  scored, the **Trajectories** card is added below (see after this list);
- **Campaign**: progress, every run, the aggregated results, with four tabs of
  its own (detection, physical impact, response, countermeasures).

The **Journal** is docked beside whichever view is open: every fact of the run,
newest first, by side. A click on a row takes the page to that moment.

The **Kill chain** card puts each attack step on one axis: when the attacker did
it, when the defender first suspected and confirmed it, the countermeasure that
covered it, and the time to detect, to respond and to impact.

The **Attacker · Defender** card sets the two sides next to each other — what
the attacker is doing and knows, what the defender sees, believes and decided —
over a lane timeline (attacker, defender, plant) and a truth-vs-belief table per
attack step.

The **structure** card draws three views of the run's recorded `kg.json` and
`tree.json`, each draggable and zoomable (− + or Ctrl + wheel). On the attack
tree, *show* chooses the side: *Defender's* (each node as it believes it, with
the countermeasures that prevent ⊘ or restore ↺ it), *Attacker's* (the tree it
was handed or built), *Both*. What every card and mark means is described where
the scenario is: [CPS, §8](scenario-cps.md#8-campaigns-and-the-progress-dashboard).

On a plant of several feeders, a row of buttons above the chart chooses the
feeder shown.

**Trajectories** is each harness's game, step by step, read from the documents
the run keeps of it once scored (`trajectory-<team>.json`); it is absent while
the run is played, and from a run with no harness. One chart puts every player
on the same axis, a lane for its model and one for its tools: a bar is the
model answering, or a call for as long as it took, coloured by what the call
does (looks at the lab, acts on it, a shell command, a wait); ✕ marks a call
that was not carried out or did not work, ◆ a refusal of the model. *By time*
draws each bar as long as it took; *By steps* gives every step the same width,
so that a minute's wait does not hide the short calls around it. A click on a
mark moves the time bar there, and below the chart the step each player was on
at that time is given in full: what the model said, what each call asked and
what came back. Under it, where each player's time went, and every step as a
table.

**CPS advisor** shows the CPS panel. A benchmark of harnesses
([Harnesses as players](playing-with-agents.md)) adds a **Harnesses** tab to the
campaign's results: how the harness at each seat played.

**CPS recon** shows the CPS panel, with the attacker's own knowledge on the
attack tree: the real nodes the attacker does not know are framed in red, the
ones it believes in that are not real are listed in the legend, and the
*Attacker's* side draws the tree it built by reconnaissance
([CPS recon](scenario-cps-recon.md)).

**CPS SOC** shows the CPS panel unchanged. The analyst's own tools — the Wazuh
dashboard and IRIS — are separate pages on their own ports
([CPS SOC](scenario-cps-soc.md)).

**MQTT** shows the defence's changes on a timeline, one lane per thing it moves
(broker address and port, client source address, message padding, publish
timing) coloured by outcome, the delivery gaps, and the table of its actions.

## 7. The referee's view

When people or harnesses play in a lab, the dashboard is the referee's page: it
shows on one timeline what the two teams' consoles keep apart, and it cannot act
on the lab. The **Players** view lists the SOC's suggestions with their outcome
and, in time order, each team's steps and every command typed, with the host and
the team. See the [playground guide](playground-red-vs-blue.md#6-referee-control-dashboard).

Do not hand a team the dashboard's address during a game: it shows the other
side.

## 8. What the browser remembers

Kept in the browser's local storage, per browser and per address of the page:
which side columns are open and how wide, the view last chosen, the cards
closed, the replay speed and the theme. The **Theme** button switches light and
dark; until it is used the page follows the system's setting. Clearing the
site's data resets all of it; nothing is stored on the server.

## 9. The server's endpoints

All `GET`, all read-only.

| Endpoint | Answers |
|---|---|
| `/` | the page |
| `/api/ledgers` | `{root, now, ledgers}`: the ledgers found under the root, newest first |
| `/api/events?id=&since=&limit=` | `{gen, next, total, events}`: one page of a ledger's events |
| `/api/structure?id=&run=` | `{source, kg, tree}`: a run's knowledge graph and attack tree — as recorded, or rebuilt from the current lab model for a run without them |
| `/api/trajectories?id=&run=` | `{trajectories: {team: document}}`: what each player at a seat did, step by step, once the run is scored; empty for a run that kept none |
| `/graph.js` | every registered scenario's `panel.js`, in one script |
| `/vendor/<file>` | a library the page loads, if `cyberrange/core/vendor/VENDOR.json` lists it |

Only ledgers found under the root are served, and a run only if its ledger names
it. The paging of `/api/events` and the vendoring policy are described in
[Architecture, §5](platform.md#5-following-it-live).
