# Running and measuring

Three ways to run, what a run leaves behind, and how it is scored. Every target
and variable is in the [reference](reference.md); the
[scenario pages](index.md#the-scenarios) say what each scenario does with them.

## Single run, campaign, or `main.py`

| You want to… | Use | Notes |
|---|---|---|
| Run one configuration once and look at it | a single-run target, e.g. `make cps-attack …` | One lab, one episode, one output directory. Best for developing and debugging. |
| Run many configurations × seeds, scored and aggregated | a **campaign**, e.g. `make cps-campaign` | Resumable; a failed run does not stop the others; results aggregated with a 95% CI. |
| Reproduce the MQTT MTD evaluation end to end | `.venv/bin/python main.py` | Runs the four compared configurations as a campaign and emits the figures. |
| Study the MTD's parameters | `make sweep` | The ablation, as a resumable campaign under `output/sweep/` ([MQTT MTD](scenario-mqtt.md)). |
| Compare harnesses as players | `make cps-bench` | Each harness as red and as blue against graded scripted opponents, over seeds ([Harnesses as players](playing-with-agents.md)). |

To see the plan before anything deploys, add `DRY=1` to the campaign targets
(`cps-campaign`, `cps-bench`, `sweep`) or `--dry-run` to `main.py`.

## Seeds and output directories

- **Seeds.** Every run is seeded (`SEED=…`). The same seed reproduces the same run;
  a campaign sweeps a range of seeds (e.g. `CPS_SEEDS=1-5`, the default) across a set
  of modes (`CPS_MODES`), so results come with a confidence interval rather than a
  single number.
- **Output directory.** Each run writes under `output/`, and — for the CPS
  scenarios — in a directory of its own:
  `output/<scenario>/runs/<date-time>[-RUN_NAME]`, with `output/<scenario>/latest`
  pointing at the last one. Two runs never share a directory: they would share a
  ledger and overwrite each other's artifacts.
  - `RUN_NAME=hijack` adds a name to the directory's.
  - `CPS_OUT=output/cps/mine` names the directory yourself. One that already
    holds a run is refused; `OVERWRITE=1` empties it first.
  - The targets that read a run (`cps-metrics`, `cps-replay`) look at `latest`
    unless told another (`CPS_RUN=…`).
  - Campaigns write under `output/campaigns/<name>/`.
  - `make runs` lists the runs kept, one line each (`RUNS_OF=cps-advisor` for one
    scenario's). `make clean` removes everything under `output/` — nothing there
    is tracked by git.

## What a run leaves behind

A finished run directory holds the raw record of what happened. Files collected
from a lab node are prefixed with that node's name (`<node>.<file>`):

| File | What it is |
|---|---|
| `run.json` | The run's card: the commit it was made with and whether the tree had uncommitted changes, fingerprints of the lab it deployed, the node images, its options (secrets masked), and how it ended. Written at the start, so a run that dies still says what it was. |
| `progress.jsonl` | The run's timeline — the event stream the dashboard shows. |
| `ground_truth.jsonl` | What really happened: attack steps, Modbus writes, footholds (host-side, never seen by the in-lab sensors). |
| `<node>.telemetry.jsonl` | What a sensor reported (e.g. `sensor.telemetry.jsonl`, `hmi.it_telemetry.jsonl`). |
| `response.jsonl` | The SOC's findings, suggestions, verdicts and responses (CPS scenarios). |
| `topology.json`, `kg.json`, `tree.json` | The lab as deployed, its knowledge graph and its attack tree (CPS scenarios). |
| `<node>.*.log` | Each node's logs (the PLC, the engine, Wazuh, the SOC analytics, …). |
| `metrics.json` / `metrics.md` | The scored metrics, as data and as a report, for a single run and for each run of a campaign alike. Under `run.card` they carry the fingerprints of the run's card, so a row of a table still says which code and lab it comes from. |

These are the files every run has. The ones a particular scenario or mode adds —
the players' records, the attacker's belief, the recorded shells — are in the
[reference](reference.md#artifacts), which lists them all.

A run whose essential services are not all running — the engine, the PLC, the
sensor, the SOC's analytics, the red team's console — **fails**, with a
`component_down` event naming the one that died, instead of ending as a valid run
that measured a lab with a piece missing. Its artifacts are downloaded all the
same: the dead component's console log is among them. In a campaign the run is
retried.

Campaigns write under `output/campaigns/<name>/`, one directory per run in `runs/`,
plus:

| File | What it is |
|---|---|
| `summary.md` / `summary.csv` | Per-configuration **mean [95% CI]** across the runs. |
| `ci.csv` | The aggregate as data. |
| `campaign.json` | The campaign's manifest and progress (what ran, what is left). |
| `progress.jsonl` | The campaign's own ledger: the dashboard follows the campaign from it. |

A scenario's campaign may add tables of its own, such as `impact.csv` and
`response.csv` for `cps` and `harness.csv` for the harness benchmark.

## Scoring a run

Metrics are computed **offline** from a finished run's artifacts, so you can
re-score without re-running:

```bash
make cps-metrics                               # the last run: detection, impact, response
make cps-metrics CPS_RUN=output/cps/runs/<run> # another one
```

For the MQTT scenario the figures and comparisons are their own targets
(`make plots`, `make entropy-compare`, `make plot-tradeoff`, …); see the
[reference](reference.md).

To ask *what a response policy would have done* on an already-finished run, without
touching the lab:

```bash
make cps-replay CPS_RUN=output/cps/runs/<run>
```

## Following a run live

```bash
make dashboard                 # http://127.0.0.1:8765 — every scenario
make cps-dashboard             # restricted to the CPS runs/campaigns
make cps-advisor-dashboard     # the advisor runs: suggestions and operator answers
make cps-recon-dashboard       # the recon runs: what the attacker has discovered
make cps-soc-dashboard         # the cps-soc runs
```

The dashboard reads `progress.jsonl` as it is written, so it works for a live run
and for replaying a finished one. In the team-vs-team playground it is also the
referee's read-only view ([playground guide](playground-red-vs-blue.md)).
[The dashboard](dashboard.md) is the guide to what it shows.

## When a run fails

A run ends as `ok`, `invalid`, `failed` or `interrupted`, and says so in
`run.json` and on the ledger. [Troubleshooting](troubleshooting.md) has the
order in which to look at a run that failed or produced nothing.

## Adding a metric or a figure

Metrics live in a scenario's `metrics.py` and figures under its `analysis/`; both
read a finished run's artifacts rather than instrumenting the run.
[Extending the platform](extending.md#adding-a-metric-or-a-figure) has the steps for each.
