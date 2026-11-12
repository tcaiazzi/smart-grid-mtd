---
name: cyberrange-runs-and-metrics
description: "Run and score experiments on this cyber range: single runs, campaigns, the progress ledger and the dashboard, and the offline metrics and figures computed from a finished run's artifacts. Use when: invoking a make target or python -m cyberrange.scenarios.*, starting or resuming a campaign, choosing between a single run, a campaign and main.py, picking seeds or output directories, reading progress.jsonl, metrics.json, summary.md or ci.csv, following a run on the dashboard, diagnosing a run that failed or produced nothing, or adding a metric in a scenario's metrics.py or a figure under its analysis/."
argument-hint: "What you want to run or measure: which scenario, how many repetitions, which numbers you need out of it"
user-invocable: true
---

# Running and scoring experiments

## Scope / Not this skill

| This skill | Elsewhere |
|---|---|
| Launching runs and campaigns, reading what they produce | Declaring the scenario → **cyberrange-scenario** |
| Writing `metrics.py` and `analysis/` figures | Writing a component → **cyberrange-components** |
| `make selftest` as one target among many | Guardrails and snapshots → **cyberrange-guardrails** |

Never invent a command. Every stage has a `make` target, and the campaign runner
shells out to those same targets — so a target renamed or bypassed breaks a
campaign hours in. `make help` prints the full catalogue with what each writes
where; `docs/scenario-mqtt.md` and `docs/scenario-cps.md` have the variables.

## Which of the three do I want?

| Want | Use | Writes |
|---|---|---|
| One lab run, one configuration | `python -m cyberrange.scenarios.<name>.cli …` or the matching `make` target | `<out-dir>/` |
| The same thing over a grid of modes/seeds, resumable | a campaign (`make cps-campaign`, or `campaign.py` of the scenario) | `output/campaigns/<name>/` |
| The paper's four configurations plus every figure | `.venv/bin/python main.py` | `output/…` + `output/campaigns/paper-mbps<M>/` |

`main.py --dry-run` prints every command it would run without running any of
them. Use it before a long run, and to find out what a target actually expands
to.

### A run to play with, not to score

- `PLAYGROUND=1` on a single-run target (`--playground` on any scenario's CLI)
  keeps the lab up after the episode, in a phase named `open`, until Ctrl-C;
  the run then tears down normally and ends `ok`. Its length is arbitrary, so
  do not compare its duration-dependent metrics with a campaign's. Campaigns
  never set it.
- `make cps-advisor PLAYGROUND=1` runs the CPS lab with a SOC that only
  suggests: the countermeasures wait at the SOC's own console (link printed by
  the run, port 8766) for Approve / Reject.
- `make cps-teams` is red team against blue team on that lab: nobody drives the
  attack, each team works from the console and shell on its own node, and
  `make dashboard` is the referee's read-only view. Links and tokens are in
  `<out_dir>/teams.json`. Both need people, so neither has a campaign. See
  `docs/scenario-cps-advisor.md`.

## Before the first run

- `.venv/bin/python` — the repo is never installed, so always the venv binary.
- Images: `make cps-image` builds `kathara/cps` and `kathara/soc` (the SOC's Wazuh manager); `kathara/mqtt` is the MQTT one.
- The MQTT scenario needs a background trace (`assets/pcap/…`, `make split`).
- A deploy **replaces** any lab with the same name: two runs of the same
  scenario cannot overlap on one machine.

## What a run leaves behind

Three streams, kept apart on purpose (`cyberrange/core/streams.py`):

| File | Means | Written by |
|---|---|---|
| `ground_truth.jsonl` | what really happened | host only — never visible to a defender, which is what makes scoring honest |
| `telemetry.jsonl` (downloaded as `<node>.telemetry.jsonl`) | what the defenders observed and did | guest sensors/coordinators |
| `progress.jsonl` | the run as it happened: phases, retries, metrics | the host ledger |

Plus each component's console log (`<node>.<name>.log`), its declared artifacts,
`topology.json`, and — once scored — `metrics.json`.

A campaign directory holds `campaign.json` (its grid and parameters),
`progress.jsonl` (one ledger for the whole campaign), `summary.md` and `ci.csv`
(the 95%-CI aggregate, refreshed as runs finish).

## Campaigns: start, resume, extend

A campaign is **units** of **steps**. A unit is one configuration × one
repetition; its steps run in order and a failed step stops that unit but not the
others. `needs` expresses dependencies between units.

- **Resuming is the default.** Re-run the same campaign name and scored steps
  that already have `<run_dir>/metrics.json` are skipped, not repeated. This is
  why you resume instead of starting over after a crash.
- **To force a rerun**, delete that run's `metrics.json` (or its directory), not
  the whole campaign.
- **Exit codes are shared** by every campaign entry point (`main.py`,
  `make cps-campaign`, `make sweep`): `0` all units finished, `1` some unit
  failed or was blocked (named on the last line), `4` no lab could start —
  start Docker, nothing was run.
- **To extend** a set of repetitions, raise the count and re-run; existing runs
  are kept.

Follow one live with `make dashboard` (every scenario) or `make cps-dashboard`
(only the CPS runs and campaigns). The dashboard reads the ledger files under `--root`; it
needs no cooperation from the run.

## Diagnosing a run that produced nothing

In this order, because each step rules out a layer:

1. **`progress.jsonl`, last lines** — `run_end{status, rc}` says whether the core
   considered it valid. A non-zero `rc` usually comes from the scenario's
   `check_run` (MQTT returns 3 when the SCMC never published).
2. **The component's console log** (`<node>.<name>.log`) — a guest process that
   died on import or on a missing file says so here, and nowhere else.
3. **`make lab-conf SCENARIO=<name>`** — compare what the node *should* receive
   with what the agent tried to run. A mismatch here is a deploy-contract
   problem: see **cyberrange-components**.
4. **Was the lab replaced?** A second deploy of the same `lab_name` tears the
   first one down mid-run.

## Adding a metric

`cyberrange/scenarios/<name>/metrics.py` exposes `compute_metrics(run_dir) -> dict`,
returned by `Scenario.metrics`. Campaigns call it when a scored step ends, store
it in `<run_dir>/metrics.json` and fold it into the aggregate.

**Return a flat, numeric dict.** `aggregate.flatten` will flatten nested dicts
into `a.b.c` keys and count booleans as `0/1` (so a boolean becomes a rate), but
it **silently drops every non-numeric leaf**: a metric that returns a string or a
list simply never appears in `summary.md` or `ci.csv`, with no error anywhere.
Missing values (`None`, `NaN`) are excluded from that metric's `n`, so a latency
is averaged over the runs that actually detected — which is usually what you
want, and always worth stating in the metric's name.

Read the metric from the run's artifacts, never from a live lab: scoring must be
repeatable on a finished directory.

## Adding a figure

Figures live in `cyberrange/scenarios/<name>/analysis/` and read finished runs
under `output/`. They are offline code: no Kathará, no containers, no network.
Give the module a `main()` and a `-m` entry point, add a `make` target for it in
`make/<scenario>.mk` (naming the module through the `M_*` variable in
`make/common.mk`, where every entry point is named once), and keep the output
path under the run or campaign directory it describes.

## Pitfalls

- **Starting a campaign over instead of resuming it** — hours of lab time, and
  the new runs get different seeds unless you pin them.
- **Hand-writing a command that a target already encodes.** The target carries
  defaults, flags and output paths that the campaign also relies on.
- **Scoring against telemetry.** Telemetry is what a defender believed; the
  reference is `ground_truth.jsonl`. Mixing them makes a detector look perfect.
- **Metrics that are not numbers** (see above) — the commonest silent loss.
- **Writing outside the run directory.** Everything a run produces belongs under
  its `out_dir`, or the dashboard and the aggregate will not find it.

## Verify

```sh
.venv/bin/python main.py --dry-run          # what would run, without running it
make -n <target>                            # the expanded command line of one stage
.venv/bin/python -m pytest tests -q
```
