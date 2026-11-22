# Troubleshooting

What goes wrong most often, what causes it and what to do. Each entry starts
from what you see.

## Stopping and cleaning up

### Stopping a run

Press Ctrl-C **once** and wait. The run stops its components, downloads the
artifacts and undeploys the lab; it is recorded as `interrupted`. A playground
(`PLAYGROUND=1`, `make cps-teams`, …) ends the same way, and is recorded as `ok`:
the interrupt is how such a run is meant to end.

A second Ctrl-C during the teardown interrupts the teardown itself, and can
leave the lab up.

### A lab is still up after a crash

**Cause.** The run was killed (a second Ctrl-C, a closed terminal, `kill -9`)
before it reached its undeploy.

**Fix.** Either of:

- run the same scenario again: a deploy first undeploys any lab of the same
  name, so the leftover is replaced;
- remove every Kathará device and network of your user:

  ```bash
  kathara list      # what is up
  kathara wipe      # remove all of it
  ```

  `kathara wipe` does not ask which lab: do not use it while a run you care
  about is going.

### Two runs of the same scenario at once

**Cause.** A lab is identified by its name, one per scenario (`cps`,
`cps-advisor`, `cps-recon`, `cps-soc`; `test` for `mqtt-mtd`). Deploying a lab
replaces the one with the same name, so a second run tears the first one's lab
down mid-run.

**Fix.** Run one lab of a scenario at a time. Campaigns already do.

### `make clean` removed my runs

`make clean` deletes everything under `output/`: every run, every campaign, the
trained models, the built documentation site. It is not a way to clear state
between runs — a new run gets a new directory anyway. Copy out what you want to
keep first.

## Starting a run

### "the Docker daemon is not reachable" (exit code 4)

**Cause.** Docker is not running, or your user cannot talk to it.

**Fix.** Start it (WSL: `sudo service docker start`, or open Docker Desktop),
check that `docker ps` works without `sudo`, and run again. Nothing was run.

### "… already holds a run"

**Cause.** The run was given an output directory (`CPS_OUT=…`, `--out-dir`) that
already contains a `progress.jsonl`. Two runs in one directory would share a
ledger and overwrite each other's artifacts, so the second is refused.

**Fix.** One of:

- leave the directory out: the run gets a new one,
  `output/<scenario>/runs/<date-time>`, and `output/<scenario>/latest` points at
  it;
- `RUN_NAME=hijack` to add a name to that new directory's;
- `OVERWRITE=1` to empty the directory you named first.

### An image is missing

**Cause.** The lab's images are built locally, once, and after any change under
`docker/`.

| Scenario | Build |
|---|---|
| `mqtt-mtd` | `docker build -t kathara/mqtt docker/mqtt/` |
| `cps`, `cps-advisor` | `make cps-image` (`kathara/cps`, `kathara/soc`) |
| `cps-recon` | `make cps-image`, then `make cps-recon-image` (`kathara/redteam`) |
| `cps-soc` | `make cps-image`, then `make cps-soc-image` (the Wazuh indexer and dashboard, IRIS, the lab CA; it also pulls IRIS's database and RabbitMQ, so it needs the network) |
| harnesses as players | `make cps-players-image` (`kathara/player`, `kathara/player-claude`) |

A guest agent that fails on an import it should have means the image predates a
change to its Dockerfile: build it again.

### A port is already in use

**Cause.** Another process — often an earlier dashboard or a run left open —
holds the port.

| Port | Used by | Variable |
|---|---|---|
| 8765 | the dashboard | `CPS_DASH_PORT` |
| 8766, 8767 | the blue team's console and shell | `CPS_BLUE_PORT`, `CPS_BLUE_SHELL_PORT` |
| 8768, 8769 | the red team's console and shell | `CPS_RED_PORT`, `CPS_RED_SHELL_PORT` |
| 8770, 8771 | the Wazuh dashboard and IRIS (`cps-soc`) | `CPS_SIEM_PORT`, `CPS_CASES_PORT` |
| 8080 | the live MTD dashboard (`mqtt-mtd`) | `DASHBOARD_PORT` (`0` disables it) |

**Fix.** Stop the other process (`ss -ltnp | grep 8765` names it), or set the
variable to a free port.

### The MQTT scenario cannot find its trace

**Cause.** The scenario replays a background traffic capture from
`assets/pcap/traccia.pcap`, and that file is not in the repository.

**Fix.** Put any capture of background traffic there, or name another with
`--trace <file>`. The one used for the paper is not distributed; any pcap will
do to run the scenario.

## A run that went wrong

### How a run ended

The last event of `progress.jsonl` is `run_end`, with `status` and `rc`; the
same status is in the run's `run.json`.

| Status | Means |
|---|---|
| `ok` | the episode ran and the scenario's own check passed |
| `invalid` | the episode ran, but the scenario's check says the run did not measure what it should have (`rc` is its non-zero code; MQTT returns 3 when the SCMC never published) |
| `failed` | an error stopped it; `error` holds the end of the traceback |
| `interrupted` | Ctrl-C |

A single run exits with the scenario's code, or 4 when no lab could start. A
campaign (`main.py`, `make cps-campaign`, `make sweep`, `make cps-bench`) exits
with 0 when every unit finished, 1 when one failed or was blocked (named on its
last line), 4 when no lab could start.

### A run produced nothing, or nothing useful

Look in this order; each step rules out a layer.

1. **The last lines of `progress.jsonl`.** `run_end` says how the run ended
   (above), and a `component_down` event names a service that died.
2. **The component's console log**, `<node>.<name>.log` in the run directory. A
   guest process that died on an import or on a missing file says so here and
   nowhere else. The logs are downloaded from a failed run too.
3. **`make lab-conf SCENARIO=<name>`**, which writes the lab as Kathará would
   receive it under `output/labconf/<name>/`. Compare what a node should
   receive with what the agent tried to run.
4. **Was the lab replaced?** A second deploy of the same lab name tears the
   first one down mid-run (above).

### The run failed with `component_down`

**Cause.** A service the run cannot do without was not running when the episode
ended: the plant's engine, the PLC, the sensor, the SOC's analytics or the red
team's console. The run fails rather than ending as a valid run that measured a
lab with a piece missing.

**Fix.** Read the console log of the component the event names; the artifacts
were downloaded all the same. In a campaign the run is retried.

### A campaign stopped half-way

Run the same command again with the same campaign name. Resuming is the
default: runs already scored (those with a `metrics.json`) are skipped. To
repeat one run, delete its `metrics.json` or its directory, not the campaign.

## `cps-soc`

### The lab is slow to come up, or the host swaps

**Cause.** `cps-soc` adds seven nodes — the Wazuh indexer and dashboard, and
IRIS with its database, queue and worker — and about 3 GB of memory beyond a
`cps-advisor` run.

**Fix.** Free the memory before starting, and give the SIEM and IRIS time on
their first start: IRIS's first requests can be slow. See
[CPS SOC](scenario-cps-soc.md).

## Playing in a lab

### A team's link or token is lost

The links handed to the teams, tokens included, are in `teams.json` in the run
directory: `output/cps-advisor/latest/teams.json`, or
`output/cps-soc/latest/teams.json` for `cps-soc-teams`. They are fresh at each
run, so an old link does not open a new game.

## Tests

### Tests are skipped: "node is not installed"

**Cause.** The checks of the dashboard panels (`tests/core/test_panels.py`) and
of the interactive scenario guide (`tests/core/test_scenario_guide.py`) run
under Node.js and skip themselves without it. The suite stays green, with those
checks not made.

**Fix.** Install Node.js before changing a `panel.js`, `dashboard.html` or
`docs/scenario-guide.html`.

### A guardrail test is red

A failing test under `tests/core/` that compares against `tests/snapshots/`, or
the floor on the number of tests, is information about the change, not an
obstacle: do not regenerate a snapshot or lower `MIN_TESTS` to make it pass
without knowing why it moved.
