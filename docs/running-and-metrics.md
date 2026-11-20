# Running and measuring

Three ways to run, what a run leaves behind, and how it is scored. For per-scenario
targets and variables, `make help` is always authoritative; the
[scenario pages](index.md#the-scenarios) are the reference for what each one does.

## Single run, campaign, or `main.py`

| You want to… | Use | Notes |
|---|---|---|
| Run one configuration once and look at it | a single-run target, e.g. `make cps-attack …` | One lab, one episode, one output directory. Best for developing and debugging. |
| Run many configurations × seeds, scored and aggregated | a **campaign**, e.g. `make cps-campaign` | Resumable; a failed run does not stop the others; results aggregated with a 95% CI. |
| Reproduce the MQTT MTD evaluation end to end | `.venv/bin/python main.py` | Runs the four compared configurations as a campaign and emits the figures. |

Add `--dry-run` (or `DRY=1` on targets that support it) to see the plan before
anything deploys.

## Seeds and output directories

- **Seeds.** Every run is seeded (`SEED=…`). The same seed reproduces the same run;
  a campaign sweeps a range of seeds (e.g. `CPS_SEEDS=1-5`, the default) across a set
  of modes (`CPS_MODES`), so results come with a confidence interval rather than a
  single number.
- **Output directory.** Each run writes under `output/`. Single-run targets take an
  explicit path (e.g. `CPS_OUT=output/cps/hijack`); campaigns write under
  `output/campaigns/<name>/`. `make clean` removes everything under `output/` —
  nothing there is tracked by git.

## What a run leaves behind

A finished run directory holds the raw record of what happened. Files collected
from a lab node are prefixed with that node's name (`<node>.<file>`):

| File | What it is |
|---|---|
| `progress.jsonl` | The run's timeline — the event stream the dashboard shows. |
| `ground_truth.jsonl` | What really happened: attack steps, Modbus writes, footholds (host-side, never seen by the in-lab sensors). |
| `<node>.telemetry.jsonl` | What a sensor reported (e.g. `sensor.telemetry.jsonl`, `hmi.it_telemetry.jsonl`). |
| `response.jsonl` | The SOC's findings, suggestions, verdicts and responses (CPS scenarios). |
| `<node>.*.log` | Each node's logs (the PLC, the engine, Wazuh, the SOC analytics, …). |
| `metrics.json` / `metrics.md` | The scored metrics, as data and as a report. A campaign writes them for each of its runs. A single run puts its score on its ledger (`run_metrics`, what the dashboard shows); `make cps-metrics` writes `metrics.md` and prints the data (see below). |

Campaigns write under `output/campaigns/<name>/`, one directory per run in `runs/`,
plus:

| File | What it is |
|---|---|
| `summary.md` / `summary.csv` | Per-configuration **mean [95% CI]** across the runs. |
| `ci.csv` | The aggregate as data. |
| `campaign.json` | The campaign's manifest and progress (what ran, what is left). |

## Scoring a run

Metrics are computed **offline** from a finished run's artifacts, so you can
re-score without re-running:

```bash
make cps-metrics CPS_OUT=output/cps/hijack     # detection, impact, response -> metrics.md
```

For the MQTT scenario the figures and comparisons are their own targets
(`make plots`, `make entropy-compare`, `make plot-tradeoff`, …); see `make help`.

To ask *what a response policy would have done* on an already-finished run, without
touching the lab:

```bash
make cps-replay CPS_OUT=output/cps/hijack
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

## Adding a metric or a figure

Metrics live in a scenario's `metrics.py` and figures under its `analysis/`; both
read a finished run's artifacts rather than instrumenting the run. See
[Extending the platform](extending.md) and the scenario pages for where each one
belongs.
