# Make targets, variables and artifacts

Every `make` target, every variable that shapes one, the command-line options that
have no variable, and every file a run or a campaign writes. `make help` lists the
targets and a handful of the MQTT variables with their current values; this page
also lists the rest, with the defaults set in `Makefile` and `make/*.mk`.

A variable is given on the command line, after the target:

```bash
make cps-attack CPS_ATTACK_MODE=manual-hijack SEED=3 RUN_NAME=hijack
```

Target names are an interface: campaigns shell out to them and the tests parse
them. What each scenario does with them is on its own page; how to choose between
a single run, a campaign and `main.py` is in
[Running and measuring](running-and-metrics.md).

## Targets

### Platform

| Target | What it does | Writes |
|---|---|---|
| `help` | Lists the targets, with the current value of the variables it shows | — |
| `dashboard` | Serves the progress dashboard of every scenario's runs and campaigns on `http://127.0.0.1:$(CPS_DASH_PORT)` | — |
| `runs` | Lists the runs kept under `OUTPUT_ROOT`, one line each (`RUNS_OF=<scenario>` for one scenario's) | — |
| `lab-conf` | Exports the topology of `SCENARIO` as a Kathará lab directory (`lab.conf` and `.startup` files) | `output/labconf/<scenario>/` |
| `platform-loc` | Counts lines of code: platform core, plane components, each scenario | `output/platform-loc.md` |
| `clean` | Removes `OUTPUT_ROOT` and everything under it, every kept run included | — |

### Quality and documentation

| Target | What it does | Writes |
|---|---|---|
| `fmt` | Reformats every Python file (`ruff format`, 100 columns) | the sources |
| `lint` | Reports formatting drift, style and dead-code problems; changes nothing | — |
| `selftest` | The whole test suite; no Kathará, no Docker | — |
| `selftest-fast` | The suite without the tests marked `slow` | — |
| `check` | `lint`, the whole suite, then a dry run (`make -n`) of every target | — |
| `docs-serve` | Serves the documentation site with live reload on `http://127.0.0.1:8000` | — |
| `docs-build` | Builds the documentation site | `output/site/` |

### mqtt-mtd

The pipeline is dataset → train → attack. One parameter configuration lives in one
experiment directory, `output/<slug>/`, where the slug is `baseline-mbps<M>` with
`NO_MTD=1`, `mtd-<parameters>` otherwise and `mtdrl[-<RL_TAG>]-<parameters>` with
`RL=1` ([output layout](scenario-mqtt.md#output-layout)).

| Target | What it does | Writes |
|---|---|---|
| `split` | Splits `BG_TRACE` into a train and a test trace (`SPLIT_RATIO`) | `assets/pcap/datasets/` |
| `datasets` | Generates the training and the test capture; deploys the lab twice | `<exp>/datasets/` |
| `dataset-train`, `dataset-test` | *Sub-steps of `datasets`*: one capture each, skipped when the capture exists | `<exp>/datasets/train.pcap`, `test.pcap` |
| `train` | Trains the attacker's classifier on the training capture | `<exp>/model/model.pt`, `scaler.pkl` |
| `evaluate` | Scores the saved model on the test capture, training it first if absent; `MODEL_SRC=baseline` for the cross-model evaluation | `<exp>/eval/model-<src>/` |
| `attack` | Runs the model-driven attack in the lab: sniff `ATTACK_DURATION` s, block, observe `POST_ATTACK` s | `<exp>/attack/model-<src>/` |
| `baseline` | `attack` with `NO_MTD=1` | the baseline's `attack/model-baseline/` |
| `demo` | Deploys the lab and runs it live, with no capture and no attack | — |
| `experiment` | `datasets`, `train`, `attack` for the current variant | `<exp>/` |
| `experiment-baseline` | `experiment` with `NO_MTD=1` | `output/baseline-mbps<M>/` |
| `all-datasets` | `datasets` for both variants, baseline then MTD | both experiment directories |
| `all-train` | `train` for both variants | both `model/` directories |
| `all-evaluate` | The three evaluations: baseline on baseline, MTD on MTD, baseline model on MTD traffic | the `eval/model-<src>/` directories |
| `all-attack` | The three attacks, in the same order | the `attack/model-<src>/` directories |
| `all` | `all-datasets`, `all-evaluate`, `all-attack`, `plots` | everything above |
| `plots` | Computes both variants' entropy, then the comparison figures and `summary.csv` | `<exp>/` |
| `plots-baseline` | Standalone figures of the baseline run | `output/baseline-mbps<M>/` |
| `plots-all` | Replots every experiment directory under `OUTPUT_ROOT`; `NO_DETECTION=1` skips the slow re-scoring of captures | each experiment directory |
| `entropy` | Flow and per-field Shannon entropy of the nanogrid traffic in the test capture | `<exp>/entropy.csv` |
| `entropy-compare` | The baseline-vs-MTD entropy figure; needs both `entropy.csv` | `<exp>/entropy_comparison.pdf` |
| `entropy-all` | Recomputes `entropy.csv` for every experiment directory that has a test capture, then `plots-all` | each experiment directory |
| `train-rl` | Trains the RL coordinator's policy offline; no lab | `$(RL_DIR)/policy.zip`, `policy.npz` |
| `train-rl-entropy` | `train-rl` with the entropy-only reward | `output/rl-entropy/policy.{zip,npz}` |
| `compare-rl` | Compares the RL coordinator with the fixed-timer one and the baseline at this configuration, from existing results; no lab | `output/compare-<parameters>/` |
| `compare-rl-all` | `compare-rl` for every `mtd-<parameters>/` under `OUTPUT_ROOT` | one `compare-<parameters>/` each |
| `plot-tradeoff` | Security against hop cost, RL policy against the fixed-timer frontier (simulation; no lab) | `$(RL_DIR)/tradeoff.pdf`, `tradeoff.csv` |
| `sweep` | The MTD parameter ablation (groups E0–E4) as a resumable campaign ([details](scenario-mqtt.md#6-the-parameter-ablation)) | `output/campaigns/ablation/`, `output/sweep/`, `output/sweep_manifest.csv` |
| `detector-runs` | Labelled attack runs for the delivery-attack detector, one per seed × variant × attack; runs that already have their telemetry are skipped | `$(DET_ROOT)/runs/<variant>-<attack>-s<seed>/` |
| `detector-dataset` | *Sub-step of the two below*: the windowed dataset built from those runs | `$(DET_ROOT)/windows.csv` |
| `detector-train` | The dataset, then the ablation on the development seeds | `$(DET_ROOT)/ablation.md` |
| `detector-final` | The dataset, then the chosen configuration fitted on the development seeds and scored once on the test seeds | `$(DET_ROOT)/kpi.md`, `kpi.csv`, `detector.npz` |

The whole evaluation of the paper is not a target but a command,
`.venv/bin/python main.py`, which runs these targets as a campaign.

### cps

| Target | What it does | Writes |
|---|---|---|
| `cps-image` | Builds the node images `kathara/cps` and `kathara/soc` | Docker images |
| `cps-selftest` | The CPS slice of the suite; no Kathará | — |
| `cps-engine` | Prints the two commands that run the engine and the PLC locally over loopback Modbus; runs nothing | — |
| `cps-lab` | Deploys the lab, normal operation only | a run directory |
| `cps-attack` | Deploys the lab and drives the attack (`CPS_ATTACK_MODE`) | a run directory |
| `cps-campaign` | `CPS_MODES` × `CPS_SEEDS`, scored and aggregated; reusing `CPS_CAMPAIGN` resumes it | `output/campaigns/<CPS_CAMPAIGN>/` |
| `cps-dashboard` | The dashboard restricted to the `cps` runs and campaigns | — |
| `cps-metrics` | Scores the finished run `CPS_RUN` | `<CPS_RUN>/metrics.md` |
| `cps-replay` | What a response policy would have done on the finished run `CPS_RUN`; no lab | `<CPS_RUN>/response.<policy>.replay.jsonl` |

A run directory is `output/<scenario>/runs/<date-time>[-RUN_NAME]`, with
`output/<scenario>/latest` pointing at the last one
([seeds and output directories](running-and-metrics.md#seeds-and-output-directories)).

### cps-advisor

| Target | What it does | Writes |
|---|---|---|
| `cps-advisor-lab` | Deploys the advisor lab, normal operation only | a run directory |
| `cps-advisor` | Attacks the lab; the SOC suggests and a person approves or rejects at its console | a run directory |
| `cps-advisor-dashboard` | The dashboard restricted to the `cps-advisor` runs | — |
| `cps-teams` | Red team against blue team, each from its own console; stays up until Ctrl-C. `RED_HARNESS` or `BLUE_HARNESS` seats a harness instead of a person | a run directory, with `teams.json` |
| `cps-players-image` | Builds the images of the players' nodes, `kathara/player` and `kathara/player-claude` | Docker images |
| `cps-agents` | A harness at each seat; plays `ENGAGEMENT_S` at most, then scores itself | a run directory |
| `cps-bench` | Benchmarks harnesses: each one as red and as blue against scripted opponents, over seeds ([details](playing-with-agents.md#7-benchmarking-harnesses)) | `output/campaigns/<BENCH>/` |

### cps-recon

| Target | What it does | Writes |
|---|---|---|
| `cps-recon-image` | Builds the attacker's image, `kathara/redteam` | Docker image |
| `cps-recon-lab` | Deploys the recon lab, normal operation only | a run directory |
| `cps-recon` | Attacks the lab with the attacker that derives its own tree | a run directory |
| `cps-recon-dashboard` | The dashboard restricted to the `cps-recon` runs | — |

### cps-soc

| Target | What it does | Writes |
|---|---|---|
| `cps-soc-image` | Builds the six images of the SOC's tools and pulls the IRIS database and RabbitMQ images | Docker images |
| `cps-soc-lab` | Deploys the `cps-soc` lab, normal operation only | a run directory |
| `cps-soc` | Attacks the lab; the SOC's suggestions wait as tasks in IRIS | a run directory |
| `cps-soc-teams` | Red team against blue team on Wazuh and IRIS; stays up until Ctrl-C | a run directory, with `teams.json` |
| `cps-soc-dashboard` | The dashboard restricted to the `cps-soc` runs | — |

## Variables

An empty default means the variable is unset.

### Platform

| Variable | Default | What it does |
|---|---|---|
| `PYTHON` | `.venv/bin/python` | The interpreter every target runs |
| `OUTPUT_ROOT` | `output` | Root of the experiment directories, the single runs, `lab-conf` and `platform-loc`; what `clean` removes. The `cps-campaign` and `cps-bench` targets do not pass it on: those campaigns go under `output/campaigns/` |
| `SEED` | *(empty)* | Experiment seed; every role of a run derives its own from it. Empty: unseeded |
| `RUN_NAME` | *(empty)* | A name appended to a new run directory's |
| `OVERWRITE` | *(empty)* | `1`: run into a named directory (`CPS_OUT` and the like) that already holds a run, emptying it first. Without it such a directory is refused |
| `PLAYGROUND` | *(empty)* | `1`: after the episode, keep the lab and its components up until Ctrl-C. Single-run targets only |
| `SCENARIO` | `cps` | The scenario `lab-conf` exports |
| `RUNS_OF` | *(empty)* | Restricts `runs` to one scenario |
| `DRY` | *(empty)* | `1`: print the plan and run nothing. Honoured by `cps-campaign`, `cps-bench` and `sweep` |
| `CPS_DASH_PORT` | `8765` | Port of the progress dashboard, for `dashboard` and every `*-dashboard` target |

`UPDATE_SNAPSHOTS=1` and `UPDATE_GUIDE_CONTRACT=1` are read by the test suite, not
by `make`: they rewrite frozen expectations and are deliberate acts — see
[Contributing](contributing.md).

### mqtt-mtd

The variables that change the experiment directory's name are explained on the
scenario page ([key variables](scenario-mqtt.md#key-variables)).

**Variant, durations and traces**

| Variable | Default | What it does |
|---|---|---|
| `NO_MTD` | *(empty)* | `1`: the baseline, without MTD. Must be an assignment (`make train NO_MTD=1`) |
| `MODEL_SRC` | the run's variant | Which model scores the run; `baseline` uses the baseline's model on MTD traffic |
| `BG_TRACE` | `assets/pcap/traccia.pcap` | The background trace `split` divides |
| `SPLIT_RATIO` | `0.7` | Share of the trace that goes to the train part |
| `TRAIN_TRACE` | `assets/pcap/datasets/<trace>_train.pcap` | Trace replayed while the training capture is taken |
| `TEST_TRACE` | `assets/pcap/datasets/<trace>_test.pcap` | Trace replayed for the test capture, the attack and the detector runs |
| `BG_REPLAY_MBPS` | `2` | Replay rate of the background trace, Mbit/s |
| `DATASET_DURATION` | `120` | Seconds of each dataset capture |
| `ATTACK_DURATION` | `40` | Seconds the attacker sniffs before it blocks |
| `POST_ATTACK` | `40` | Seconds observed after the block |
| `BLOCK_POLICY` | `top1` | `top1`: always block the top-ranked address. `threshold`: only when its nanogrid fraction reaches `BLOCK_THRESHOLD` |
| `BLOCK_THRESHOLD` | *(empty)* | The threshold of that policy; empty: `DETECT_THRESHOLD` of `cyberrange/planes/attack/thresholds.py` |
| `DASHBOARD_PORT` | *(empty)* | Host port of the node's live page: the MTD dashboard on the SEMP here (empty: the CLI's 8080; `0`: none), the sensor's page in the CPS scenarios (empty: off) |
| `DETECTOR_MODEL` | *(empty)* | A delivery-attack detector (`.npz`) to run live on the SEMP during `attack` and `detector-runs` |

**MTD parameters**

| Variable | Default | What it does |
|---|---|---|
| `MTD_HOP_INTERVAL` | `2` | Seconds between broker address hops |
| `MTD_IP_POOL` | `10.1.0.2` | Broker IP pool; one entry disables IP hopping |
| `MTD_PORT_POOL` | `8883,8884,8885,8886,8887` | Broker port pool |
| `MTD_PAD_BUCKETS` | `128,256,384,512,640,768,1024` | Payload padding sizes |
| `MTD_PAD_INTERVAL` | `3` | Seconds between padding rotations |
| `MTD_SCMC_IP_POOL` | `10.0.0.2` | The SCMC's source IP pool; one entry disables source hopping |
| `MTD_SRC_HOP_INTERVAL` | `2` | Seconds between source-IP hops |
| `MTD_FREQ_POOL` | `1.0` | Publish-interval pool, seconds; one entry disables frequency hopping |
| `MTD_FREQ_INTERVAL` | `30` | Seconds between publish-interval changes |

**RL coordinator**

| Variable | Default | What it does |
|---|---|---|
| `RL` | *(empty)* | `1`: the trained policy drives the MTD schedule instead of the fixed timers; the experiment directory takes the `mtdrl-` prefix. Ignored with `NO_MTD=1` |
| `RL_DIR` | `output/rl` | Where `train-rl` writes the policy and `plot-tradeoff` its figure |
| `RL_POLICY` | `$(RL_DIR)/policy.npz` | The distilled policy a run with `RL=1` loads |
| `RL_TICK` | `1.0` | Seconds between the policy's decisions |
| `RL_TAG` | *(empty)* | A label that keeps competing policies apart: the prefix becomes `mtdrl-<tag>-` |
| `RL_TIMESTEPS` | `200000` | PPO training steps of `train-rl` |
| `RL_W_SEC` | `1.0` | Weight of security in the reward |
| `RL_W_AVAIL` | `1.0` | Weight of the availability cost in the reward |
| `RL_REWARD_MODE` | `blend` | `blend`: security against cost. `entropy`: diffusion only |
| `RL_TAGS` | *(empty)* | Extra policy tags `compare-rl` adds as bars of their own, comma-separated |
| `COMPARE_DIR` | `$(OUTPUT_ROOT)/compare-<parameters>` | Where `compare-rl` writes |

**Figures and ablation**

| Variable | Default | What it does |
|---|---|---|
| `NO_DETECTION` | *(empty)* | `1`: `plots-all` and `entropy-all` skip the slow re-scoring of the captures |
| `ENTROPY_SEMP_POOL` | `10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6,10.1.0.7,10.1.0.8` | Broker pool `entropy-all` labels the nanogrid traffic with: a superset of every configuration's |
| `GROUPS` | *(empty)* | The ablation groups `sweep` runs, e.g. `e1,e2`; empty: all five |

**Delivery-attack detector** ([what it is](scenario-mqtt.md#9-the-delivery-attack-detector))

| Variable | Default | What it does |
|---|---|---|
| `DET_ROOT` | `$(OUTPUT_ROOT)/detector` | Where the detector's runs, dataset and results go |
| `DET_SEEDS` | `1 2` | Seeds of `detector-runs`, space-separated. `detector-final` needs runs for every seed of `DET_TEST_SEEDS` |
| `DET_VARIANTS` | `fixed rl` | Coordinators the runs cover |
| `DET_ATTACKS` | `cnn oracle` | Who picks the address to blackhole: the CNN attacker or the oracle |
| `DET_POST_ATTACK` | `180` | Seconds of each run's post-attack phase |
| `DET_BLOCK_DURATION` | `40` | Seconds each blackhole lasts |
| `DET_BLOCK_EPISODES` | `2` | Blackholes per run |
| `DET_CNN_MODEL_DIR` | `$(OUTPUT_ROOT)/baseline-mbps2/model` | The attacker's model those runs use |
| `DET_DEV_SEEDS` | `1-3` | Seeds everything is tuned on |
| `DET_TEST_SEEDS` | `4-10` | Seeds scored once, by `detector-final` |
| `DET_MODEL` | `mlp` | The model `detector-final` fits |
| `DET_FEATURES` | `v2h` | Its feature set |
| `DET_HIDDEN` | `16,16` | Its hidden layers |
| `DET_SMOOTHING` | `1of1` | Its alarm smoothing |

### cps

These apply to the `cps` targets and, unless noted, to the `cps-advisor`,
`cps-recon` and `cps-soc` ones, which run the same lab
([running an experiment](scenario-cps.md#7-running-an-experiment)).

| Variable | Default | What it does |
|---|---|---|
| `CPS_OUT` | *(empty)* | The run's directory, when it must be a given one; empty: a new one |
| `CPS_RUN` | `CPS_OUT`, else `$(OUTPUT_ROOT)/cps/latest` | The finished run `cps-metrics` and `cps-replay` read |
| `CPS_NORMAL` | `60` | Seconds of normal operation before the attack |
| `CPS_LEARN` | `45` | Seconds, inside the normal phase, the sensor's model calibrates on |
| `CPS_POST` | `30` | Seconds observed after the attack (`cps`, `cps-recon`) |
| `CPS_STEP` | `1.0` | Seconds per step of the physical process |
| `CPS_DETECTORS` | `rules,model` | The sensor's detectors |
| `CPS_ATTACK_MODE` | `setpoint-overvoltage` | The attack: also `breaker-open`, `manual-hijack`, `slow-ramp`, `setpoint-oscillation`, `breaker-chatter`, `meas-fdi` |
| `CPS_ATTACK_DRIVER` | `scripted` | `scripted`: the fixed chain of the mode. `planner`: the reactive, tree-guided attacker |
| `CPS_PROFILE` | `opportunistic` | Planner driver: how the attacker chooses its next step (`opportunistic`, `targeted`, `stealthy`) |
| `CPS_GOAL` | *(empty)* | Planner driver, targeted profile: the impact leaf to aim for |
| `CPS_DWELL` | `0` | Planner driver: seconds between steps |
| `CPS_RESPOND` | `off` | Response policy: `off`, `rules`, `solver`. `cps-replay` replays `rules` when it is `off` |
| `CPS_APPROVAL` | `auto` | Operator approval of high-impact countermeasures: `auto`, `deny`, `delay:<seconds>` |
| `CPS_IT` | *(empty)* | `1`: the IT-side sensor on the HMI, with legitimate diagnostic traffic |
| `CPS_CAMPAIGN` | the date and time, `YYYYmmdd-HHMM` | The campaign's name; reuse it to resume |
| `CPS_SEEDS` | `1-5` | The campaign's seeds |
| `CPS_MODES` | `normal,setpoint-overvoltage,breaker-open,manual-hijack` | The campaign's modes |

### cps-advisor

| Variable | Default | What it does |
|---|---|---|
| `CPS_ADVISOR_OUT` | *(empty)* | The run's directory for `cps-advisor`, `cps-advisor-lab` and `cps-teams`; empty: a new one |
| `CPS_ADVISOR_RESPOND` | `solver` | The policy that advises: `rules` or `solver` |
| `CPS_ADVISOR_TIMEOUT` | `120` | Seconds a suggestion waits for the operator's verdict before it expires |
| `CPS_ADVISOR_POST` | `180` | Seconds observed after the attack: time for a person to answer (`cps-advisor`, `cps-soc`) |
| `CPS_BLUE_PORT` | `8766` | Host port of the SOC's console |
| `CPS_BLUE_SHELL_PORT` | `8767` | Host port of the blue team's shell |
| `CPS_RED_PORT` | `8768` | Host port of the red console (`cps-teams`, `cps-agents`, `cps-soc-teams`) |
| `CPS_RED_SHELL_PORT` | `8769` | Host port of the red team's shell |

**Harnesses** ([how to run them](playing-with-agents.md#1-run-it))

| Variable | Default | What it does |
|---|---|---|
| `RED_HARNESS`, `BLUE_HARNESS` | *(empty)* | The harness at that seat. Empty: a person with `cps-teams`, `claude-code` with `cps-agents` |
| `RED_MODEL`, `BLUE_MODEL` | *(empty)* | The model that harness runs |
| `ENGAGEMENT_S` | `900` | `cps-agents`: how long two harnesses play, at most |
| `MAX_CALLS` | *(empty)* | Each harness's budget of tool calls; empty: none |
| `PLAYER_DNS` | *(empty)* | Name servers of the players' nodes; empty: the scenario's default, public ones |
| `CPS_AGENTS_OUT` | *(empty)* | The run's directory for `cps-agents`; empty: a new one |

**Benchmark** (`cps-bench`)

| Variable | Default | What it does |
|---|---|---|
| `BENCH` | the date and time, `YYYYmmdd-HHMM` | The benchmark's name; reuse it to resume |
| `BENCH_HARNESS` | `claude-code` | The harnesses under test, comma-separated, each `<name>[:<model>]` |
| `BENCH_SIDES` | `red,blue` | The seats each harness is tried at |
| `BENCH_SEEDS` | `1-3` | The seeds |
| `BENCH_OPPONENTS` | *(empty)* | The scripted opponents; empty: all three of the other side |
| `BENCH_ENGAGEMENT_S` | `300` | Each game's length |
| `BENCH_MAX_CALLS` | `60` | Each harness's budget of tool calls |

### cps-recon

| Variable | Default | What it does |
|---|---|---|
| `CPS_RECON_OUT` | *(empty)* | The run's directory; empty: a new one |

`cps-recon` passes no attack mode: the attacker chooses from the tree it derives.
`CPS_PROFILE`, `CPS_GOAL` and `CPS_DWELL` apply to it.

### cps-soc

`cps-soc` uses the `cps-advisor` variables for the policy, the timeout, the
post-attack time and the shell and red-console ports.

| Variable | Default | What it does |
|---|---|---|
| `CPS_SOC_OUT` | *(empty)* | The run's directory; empty: a new one |
| `CPS_SIEM_PORT` | `8770` | Host port of Wazuh's dashboard |
| `CPS_CASES_PORT` | `8771` | Host port of DFIR-IRIS |

`cps-soc-teams` does not take `RED_HARNESS` or `BLUE_HARNESS`: both teams are people.

## Options without a variable

These exist only on the command line of the module a target runs. Pass them by
calling the module directly, e.g. `.venv/bin/python -m cyberrange.scenarios.cps.cli
--attack --max-steps 20`; `--help` on any of them prints the full list.

**Every scenario's run** (`cyberrange.scenarios.<name>.cli`, added by the core)

| Option | Default | What it does |
|---|---|---|
| `--progress-file` | `<out-dir>/progress.jsonl` | Where the run's ledger is written |
| `--run-id` | the output directory's name | The run's id on the ledger |
| `--poll-interval` | `2.0` | Seconds between live pulls of guest state into the ledger; `0`: no live view |

`--out-root`, `--run-name`, `--overwrite`, `--seed` and `--playground` are what
`OUTPUT_ROOT`, `RUN_NAME`, `OVERWRITE`, `SEED` and `PLAYGROUND` set.

**`cps` and the scenarios built on it**

| Option | Default | What it does |
|---|---|---|
| `--max-steps` | `12` | Planner driver: the attacker's step budget |
| `--attack-via HOST` | scripted: the lab's first HMI; planner: any | The HMI the attack gets in through |
| `--attack-unit UNIT` | scripted: the plant's first feeder; planner: any | The feeder the attack acts on, by its Modbus unit |
| `--attack-repeat` | per attack mode | Times the write sequence is issued |
| `--attack-interval` | `0.5` | Seconds between the attack's writes |
| `--respond-interval` | `0.5` | Seconds between the responder's telemetry pulls |

**`cps-recon`**

| Option | Default | What it does |
|---|---|---|
| `--it-cidr` | the lab's IT subnet | The subnet the attacker scans: its own |
| `--scan-ports` | `22,80,502,5020,8080` | The ports nmap probes on that scan |

**`cps-advisor` and `cps-soc`**

| Option | Default | What it does |
|---|---|---|
| `--blue-token`, `--red-token` | a fresh one per run | The token in each team's links |

**Campaigns** (`cyberrange.scenarios.cps.campaign`, `cyberrange.scenarios.cps_advisor.campaign`)

| Option | Default | What it does |
|---|---|---|
| `--out-root` | `output/campaigns` | Where the campaign's directory goes |
| `--retries` | `1` | Retries of a failed run before it is recorded as failed |
| `--no-resume` | resume | Rerun the runs that already have their metrics |

Both accept every option of their scenario's run, applied to each run.

**Scoring and replay**

| Module | Option | What it does |
|---|---|---|
| `cyberrange.scenarios.cps.metrics` | `--json PATH` | Also write the metrics as JSON there |
| | `--aggregate CAMPAIGN_DIR` | Aggregate `<dir>/runs/*/metrics.json` into the campaign's summary files |
| `cyberrange.scenarios.cps.responder` | `--out PATH` | The replay's log; default `<run>/response.<policy>.replay.jsonl` |

**Dashboard** (`cyberrange.core.dashboard`)

| Option | Default | What it does |
|---|---|---|
| `--root` | `output` | Where to look for progress ledgers (`OUTPUT_ROOT`) |
| `--scenario` | all | Show only one scenario's runs and campaigns: what the `*-dashboard` targets pass |
| `--host` | `127.0.0.1` | The address the server binds |

**`mqtt-mtd`** (`cyberrange.scenarios.mqtt_mtd.cli`)

| Option | Default | What it does |
|---|---|---|
| `--mtd-hop-timeout` | `10.0` | Seconds; no make variable sets it |
| `--oracle-block {src,broker,random}` | off | Blackhole the address the SCMC uses right now instead of the CNN's pick. `detector-runs` passes `random` for its oracle runs |
| `--block-duration` | never lifted | Lift each blackhole after this many seconds (`detector-runs`: `DET_BLOCK_DURATION`) |
| `--block-episodes` | `1` | Blackholes per run (`detector-runs`: `DET_BLOCK_EPISODES`) |
| `--impair-profile {none,random}` | `none` | `random`: seeded benign faults in the post-attack phase (`detector-runs` passes it) |
| `--name` | | Dataset mode: the capture's name; the targets pass `train` and `test` |
| `--trace` | `assets/pcap/traccia.pcap` | The background trace the router replays; the targets pass `TRAIN_TRACE` or `TEST_TRACE` |
| `--datasets-dir`, `--results-dir` | under `output/<slug>/` | Where a dataset run and an attack run write; the targets pass the experiment directory's |

Two pools have different defaults on the command line and in `make`: called
directly, the module hops the broker across `10.1.0.2,10.1.0.4,10.1.0.5` and the
SCMC across `10.0.0.2,10.0.0.4,10.0.0.5`, while the targets always pass
`MTD_IP_POOL` and `MTD_SCMC_IP_POOL`, whose single-entry defaults disable both.

**`main.py`**

| Option | Default | What it does |
|---|---|---|
| `--mbps` | `2` | Replay rate of the background trace |
| `--runs N` | `1` | Repeat the evaluation N times, run *i* under `output/run-<i>/` with `SEED=<seed-base>+i` |
| `--seed-base` | `0` with `--runs` > 1 | Seed of run 0 |
| `--first-run` | `0` | Index of the first run, to extend an existing set |
| `--retries` | `2` | Retries of a failed lab step |
| `--lab-timeout` | no limit | Stop a lab step running longer than this many seconds, then retry it |
| `--resume` | rerun | Skip attacks that already have `metrics.json` |
| `--name` | `paper-mbps<M>` | The campaign's name, under `output/campaigns/` |
| `--dry-run` | | Print every command, run nothing |

The ablation module (`cyberrange.scenarios.mqtt_mtd.ablation`, behind `sweep`)
also takes `--name` (default `ablation`), `--retries`, `--lab-timeout` and
`--no-resume`.

## Artifacts

### A run directory

A file collected from a lab node carries the node's name as a prefix:
`<node>.<file>`. A component's console output is collected the same way, as
`<node>.<log>` (`engine.engine.log`, `soc.soc_analytics.log`). The CPS scenarios
below are `cps`, `cps-advisor`, `cps-recon` and `cps-soc`.

**Written on the host**

| File | Written by | Scenarios |
|---|---|---|
| `run.json` | The core, when the run starts and again when it ends: the run's card | all |
| `progress.jsonl` | The core's ledger: the run's timeline, what the dashboard shows | all |
| `topology.json` | The core, at deploy: the lab as deployed | all |
| `ground_truth.jsonl` | The scenario and its attack components, on the host only: what really happened | all (`mqtt-mtd`: attack runs) |
| `metrics.json`, `metrics.md` | The core, from the scenario's metrics, when the run ends; `cps-metrics` rewrites `metrics.md` | all (`metrics.md` when the scenario has a report) |
| `kg.json`, `tree.json` | The CPS scenario, at deploy: the knowledge graph and the attack tree of the lab | CPS |
| `teams.json` | The advisor feature: each team's links and tokens. Host only, never copied into the lab | `cps-teams`, `cps-agents`, `cps-soc-teams` |
| `response.<policy>.replay.jsonl` | `cps-replay` | CPS, on demand |

**Collected from the nodes — CPS**

| File | Written by | Scenarios |
|---|---|---|
| `engine.engine_frames.jsonl` | The engine (`PhysicalProcess`): one frame of the plant's state per step | CPS |
| `sensor.telemetry.jsonl` | `OtSensor`: the sensor's findings and alerts | CPS |
| `<node>.it_telemetry.jsonl` | `ItSensor` on the HMI | CPS, with `CPS_IT=1` |
| `response.jsonl` | `SocAnalytics`: the SOC's findings, suggestions, verdicts and responses | CPS |
| `soc.kg.json`, `soc.tree.json` | `SocAnalytics`: the graph and the tree the SOC itself built | CPS |
| `soc.belief.jsonl` | `SocAnalytics`: its belief over time | when the scenario asks for the feed (`cps-soc`) |
| `soc.alerts.json`, `soc.ossec.log` | `WazuhManager` | CPS |
| `<node>.cps-response.jsonl`, `<node>.ossec.log` | `WazuhAgent`: the countermeasures that host ran, and the agent's log | CPS |
| `ews.ews_maint.access.jsonl`, `ews.ot_mitm.jsonl` | `EwsMaintenance`: who used the maintenance service; the record of an attack standing between the PLC and the engine | CPS, when produced |
| `<node>.exploit.log` | `ScriptedChain` | scripted attack |
| `<node>.red_agent.log`, `<node>.red_actions.jsonl` | `PlannedAttacker`: what the attacker did | planner attack |
| `attacker.belief_tree.json`, `attacker.red_recon_agent.log` | `ReconAttacker`: the tree the attacker derived | `cps-recon` |
| `attacker.red_actions.jsonl` | `RedConsole`: the steps the red team ran | teams |
| `<node>.commands.jsonl` | `RecordedShell`: every command typed in a team's shell on that node | teams |
| `<node>.terminal.typescript` | `WebTerminal`: the transcript of the team's terminal | teams |
| `<node>.sshd.log` | `JumpHost`, on each host the blue team can reach | teams |
| `player-<team>.jsonl`, `player-<team>.firewall.txt` | `SeatPlayer`: the harness's transcript, and the firewall counters of its node | a harness at a seat |
| `trajectory-<team>.json` | written when the run is scored: the player's game as one ATIF v1.8 document (`cyberrange/scenarios/cps/trajectory.py`), which the dashboard's Trajectories card draws | a harness at a seat |
| `<node>.wazuh-cluster.log` | `WazuhIndexer` | `cps-soc` |
| `<node>.integrations.log` | `IrisAlertForwarder` | `cps-soc` |

**mqtt-mtd.** A dataset run writes into `<exp>/datasets/` with the capture's name
as a prefix (`train.`, `test.`); an attack run writes into
`<exp>/attack/model-<src>/` without one.

| File | Written by |
|---|---|
| `<name>.pcap` | Dataset run: the labelled capture |
| `attacker_capture.pcap`, `nanogrid_ranking.csv` | `PassiveFingerprinter`: what the attacker sniffed and how it ranked the sources |
| `router_capture.pcap`, `scmc_capture.pcap`, `post_attack_capture.pcap` | Attack run: the captures on the router, on the SCMC and after the block |
| `client.log`, `client.console.log` | The SCMC's publisher |
| `mosquitto.log` | The broker on the SEMP |
| `coordinator.log`, `telemetry.jsonl` | The MTD coordinator on the SEMP (MTD runs) |
| `scmc_ips.txt` | The scenario: the SCMC's source pool, which the offline labelling reads |
| `run.log` | The scenario: the run's own console output |

### A campaign directory

`output/campaigns/<name>/`, one directory per run under `runs/`.

| File | Written by | Campaigns |
|---|---|---|
| `campaign.json` | The core's campaign runner: the grid and its parameters | all |
| `progress.jsonl` | The campaign's own ledger: every run's events on one timeline | all |
| `runs/<run>/` | One run directory each, as above: `<mode>-s<seed>` for `cps-campaign`, `<side>-<harness>-vs-<opponent>-s<seed>` for `cps-bench` | `cps-campaign`, `cps-bench` |
| `summary.md` | The aggregate as a report: per configuration, mean [95% CI] across the runs | all |
| `ci.csv` | The same aggregate as data | all |
| `summary.csv` | The detection table | `cps-campaign`, `cps-bench` |
| `impact.csv` | The impact table | `cps-campaign`, `cps-bench` |
| `response.csv` | The response table; only when the runs had a response | `cps-campaign`, `cps-bench` |
| `harness.csv` | Per cell of the grid, the columns that matter for each side | `cps-bench` |

The MQTT campaigns (`main.py`, `sweep`) keep their runs in the experiment
directories, not under `runs/`, and write `sweep_manifest.csv` — one row per
configuration — at the root of their output.

### Elsewhere under `output/`

| Path | Written by |
|---|---|
| `<scenario>/runs/<date-time>[-name]/`, `<scenario>/latest` | The single runs of the CPS scenarios |
| `campaigns/<name>/` | Every campaign |
| `baseline-mbps<M>/`, `mtd-…/`, `mtdrl-…/` | The MQTT experiment directories: `datasets/`, `model/`, `eval/model-<src>/`, `attack/model-<src>/`, `summary.csv`, `entropy.csv` and the figures |
| `compare-<parameters>/` | `compare-rl`, and `main.py`'s last step |
| `run-<i>/` | `main.py --runs N`: the whole layout above, once per run |
| `rl/`, `rl-entropy/` | `train-rl`, `train-rl-entropy`: `policy.zip` and `policy.npz` |
| `sweep/`, `sweep_manifest.csv` | `sweep`: the ablation's figures and its grid |
| `detector/` | The detector targets: `runs/`, `windows.csv`, `ablation.md`, `kpi.md`, `kpi.csv`, `detector.npz` |
| `labconf/<scenario>/` | `lab-conf` |
| `platform-loc.md` | `platform-loc` |
| `site/` | `docs-build` |

Nothing under `output/` is tracked by git, and `make clean` removes all of it.
