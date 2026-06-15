# Smart Grid AI-MTD — pipeline: dataset -> train -> attack
#
# Quick start:
#   make datasets     # generate train+test PCAPs (deploys the Kathará lab twice)
#   make train        # train the 1D-CNN on the train dataset
#   make evaluate     # evaluate on the test dataset using the saved model (trains first if absent)
#   make attack       # run the model-driven attack in the lab
#   make experiment   # full pipeline: datasets -> train -> attack
#
# Output structure — one self-contained directory per experiment config:
#   output/<exp-slug>/                     exp-slug = baseline-mbps<M> | mtd-<MTD_PARAMS_SLUG>
#     datasets/                            train/test PCAPs + capture logs
#     model/                               trained model + scaler
#     eval/model-<src>/                    evaluate metrics (predictions, plots)
#     attack/model-<src>/                  attack captures, ranking, broker log
#     summary.csv + comparison plots       (from `make plots`)
#   output/sweep/                          aggregate sweep plots (from run_sweep.sh)
#
# MTD vs baseline: set NO_MTD=1 for the baseline (no-MTD) variant.
# Cross-model attack: MODEL_SRC=baseline uses the baseline model on MTD traffic.
#
# Override variables as needed, e.g.:
#   make dataset-train TRAIN_TRACE=assets/pcap/traccia.pcap DATASET_DURATION=60
#   make datasets MTD_HOP_INTERVAL=1 MTD_PORT_POOL=8883,8884,8885,8886,8887,8888

PYTHON ?= .venv/bin/python

# Guard: NO_MTD must be a variable *assignment* (NO_MTD=1), not a bare goal.
ifneq ($(filter NO_MTD,$(MAKECMDGOALS)),)
  $(error Use NO_MTD=1 as an assignment, e.g. `make train NO_MTD=1` (not a bare `NO_MTD`))
endif

# Experiment variant: MTD enabled (default) or baseline without MTD.
ifeq ($(filter-out 0 no false off,$(NO_MTD)),)
  VARIANT  := mtd
  MTD_FLAG :=
else
  VARIANT  := baseline
  MTD_FLAG := --no-mtd
endif

# Background trace split: one source trace -> train/test parts.
BG_TRACE    ?= assets/pcap/traccia.pcap
SPLIT_RATIO ?= 0.7
SPLIT_DIR   := assets/pcap/datasets
TRAIN_TRACE ?= $(SPLIT_DIR)/$(basename $(notdir $(BG_TRACE)))_train.pcap
TEST_TRACE  ?= $(SPLIT_DIR)/$(basename $(notdir $(BG_TRACE)))_test.pcap

DATASET_DURATION ?= 120
ATTACK_DURATION  ?= 40
POST_ATTACK      ?= 40
BG_REPLAY_MBPS   ?= 2

# ── MTD parameters ─────────────────────────────────────────────────────────────
# Tune these to make fingerprinting harder.
# Shorter intervals and larger pools create more candidate flows, diluting the
# nanogrid signal seen by the attacker.
MTD_HOP_INTERVAL ?= 2
MTD_IP_POOL      ?= 10.1.0.2
MTD_PORT_POOL    ?= 8883,8884,8885,8886,8887
MTD_PAD_BUCKETS  ?= 128,256,384,512,640,768,1024
MTD_PAD_INTERVAL ?= 3
# SCMC source-IP hopping (publisher side). Single entry disables it (mirrors the
# MTD_IP_POOL default); set e.g. 10.0.0.2,10.0.0.4,10.0.0.5 to enable.
MTD_SCMC_IP_POOL   ?= 10.0.0.2
MTD_SRC_HOP_INTERVAL ?= 2
# Message-frequency hopping: rotate the SCMC publish interval across a pool so the
# inter-arrival timing is also a moving target. Single-entry pool disables it.
MTD_FREQ_POOL    ?= 1.0
MTD_FREQ_INTERVAL ?= 30
MTD_PARAMS_FLAG  := --mtd-hop-interval $(MTD_HOP_INTERVAL) \
                    --mtd-ip-pool $(MTD_IP_POOL) \
                    --mtd-port-pool $(MTD_PORT_POOL) \
                    --mtd-pad-buckets $(MTD_PAD_BUCKETS) \
                    --mtd-pad-interval $(MTD_PAD_INTERVAL) \
                    --mtd-scmc-ip-pool $(MTD_SCMC_IP_POOL) \
                    --mtd-src-hop-interval $(MTD_SRC_HOP_INTERVAL) \
                    --mtd-freq-pool $(MTD_FREQ_POOL) \
                    --mtd-freq-interval $(MTD_FREQ_INTERVAL)

# Compact slug encoding the active MTD parameters (used in output dir names).
comma          := ,
MTD_N_IPS      := $(words $(subst $(comma), ,$(MTD_IP_POOL)))
MTD_N_PORTS    := $(words $(subst $(comma), ,$(MTD_PORT_POOL)))
MTD_N_PADS     := $(words $(subst $(comma), ,$(MTD_PAD_BUCKETS)))
MTD_N_SCMC_IPS := $(words $(subst $(comma), ,$(MTD_SCMC_IP_POOL)))
MTD_N_FREQS    := $(words $(subst $(comma), ,$(MTD_FREQ_POOL)))
MTD_PARAMS_SLUG := hop$(MTD_HOP_INTERVAL)-padint$(MTD_PAD_INTERVAL)-ips$(MTD_N_IPS)-ports$(MTD_N_PORTS)-pads$(MTD_N_PADS)-srcips$(MTD_N_SCMC_IPS)-mbps$(BG_REPLAY_MBPS)-freqint$(MTD_FREQ_INTERVAL)-freqs$(MTD_N_FREQS)

# ── Attack model source ────────────────────────────────────────────────────────
# Defaults to the run variant. Set MODEL_SRC=baseline to use the baseline model
# on MTD traffic (cross-model attack).
MODEL_SRC ?= $(VARIANT)

# ── Experiment directory ─────────────────────────────────────────────────────
# Everything for one parameter configuration lives under output/<EXP_SLUG>/:
#   datasets/  model/  eval/model-<src>/  attack/model-<src>/  summary.csv
# The slug reuses the compact MTD_PARAMS_SLUG; baseline omits the MTD params
# (the coordinator is not started) and keys on the replay rate only.
ifeq ($(VARIANT),baseline)
  EXP_SLUG := baseline-mbps$(BG_REPLAY_MBPS)
else
  EXP_SLUG := mtd-$(MTD_PARAMS_SLUG)
endif
EXP_DIR := output/$(EXP_SLUG)

# Experiment dir whose model scores this run. MODEL_SRC=baseline (cross-model)
# reads the baseline config's model; otherwise it's this config's own model.
ifeq ($(MODEL_SRC),baseline)
  MODEL_EXP_DIR := output/baseline-mbps$(BG_REPLAY_MBPS)
else
  MODEL_EXP_DIR := $(EXP_DIR)
endif

# ── Output paths (all under the experiment dir) ──────────────────────────────
TRAIN_PCAP := $(EXP_DIR)/datasets/train.pcap
TEST_PCAP  := $(EXP_DIR)/datasets/test.pcap

MODEL  := $(EXP_DIR)/model/model.pt
SCALER := $(EXP_DIR)/model/scaler.pkl

ATTACK_MODEL  := $(MODEL_EXP_DIR)/model/model.pt
ATTACK_SCALER := $(MODEL_EXP_DIR)/model/scaler.pkl

# Results are keyed by the scoring model's variant so the cross-model run does
# not overwrite the own-model run.
EVAL_OUT_DIR   := $(EXP_DIR)/eval/model-$(MODEL_SRC)
ATTACK_OUT_DIR := $(EXP_DIR)/attack/model-$(MODEL_SRC)

BASELINE_DIR := output/baseline-mbps$(BG_REPLAY_MBPS)

.PHONY: help split datasets dataset-train dataset-test all-datasets train all-train evaluate attack baseline demo experiment experiment-baseline all-evaluate all-attack all plots plots-baseline plots-all entropy entropy-compare entropy-all clean

help:
	@echo "Variant: $(VARIANT)  (set NO_MTD=1 for baseline)   Model: $(MODEL_SRC)"
	@echo "Experiment dir: $(EXP_DIR)"
	@echo ""
	@echo "Targets:"
	@echo "  split               Split $(BG_TRACE) into train/test traces (SPLIT_RATIO=$(SPLIT_RATIO))"
	@echo "  dataset-train       Generate the training dataset -> $(TRAIN_PCAP)"
	@echo "  dataset-test        Generate the test dataset -> $(TEST_PCAP)"
	@echo "  datasets            Generate both datasets"
	@echo "  all-datasets        Generate datasets for both variants (baseline + mtd)"
	@echo "  train               Train the classifier -> $(MODEL)"
	@echo "  all-train           Train both classifiers (baseline + mtd)"
	@echo "  evaluate            Evaluate saved model on the test set (trains first if absent)"
	@echo "                      -> $(EVAL_OUT_DIR)"
	@echo "                      Cross-model: make evaluate MODEL_SRC=baseline"
	@echo "  all-evaluate        Run all three evaluations: no-mtd/no-mtd, mtd/mtd, mtd/no-mtd"
	@echo "  attack              Run the model-driven attack (ATTACK_DURATION=$(ATTACK_DURATION)s,"
	@echo "                      POST_ATTACK=$(POST_ATTACK)s observed after the block)"
	@echo "                      -> $(ATTACK_OUT_DIR)"
	@echo "                      Cross-model: make attack MODEL_SRC=baseline"
	@echo "  baseline            Run the attack with MTD disabled"
	@echo "  all-attack          Run all three attack scenarios"
	@echo "  all                 Full pipeline: both datasets -> all-evaluate -> all-attack -> plots"
	@echo "  experiment          Full pipeline with MTD: datasets -> train -> attack"
	@echo "  experiment-baseline Full pipeline without MTD (NO_MTD=1)"
	@echo "  plots               Compare scenarios -> $(EXP_DIR)/"
	@echo "  plots-baseline      Standalone baseline figures -> output/baseline-mbps$(BG_REPLAY_MBPS)/"
	@echo "  plots-all           Replot every experiment dir under output/ (NO_DETECTION=1 to skip scoring)"
	@echo "  entropy             Flow/field entropy of the nanogrid traffic -> $(EXP_DIR)/entropy.csv"
	@echo "  entropy-compare     Baseline-vs-MTD entropy figure -> $(EXP_DIR)/entropy_comparison.pdf"
	@echo "  entropy-all         Recompute entropy + refresh ALL figures from existing results (NO_DETECTION=1 to skip scoring)"
	@echo "  clean               Remove all generated outputs"
	@echo ""
	@echo "MTD parameters (override on the command line):"
	@echo "  MTD_HOP_INTERVAL    Seconds between hops              (default: $(MTD_HOP_INTERVAL))"
	@echo "  MTD_IP_POOL         Broker IP pool (IP hopping)       (default: $(MTD_IP_POOL))"
	@echo "  MTD_PORT_POOL       Broker port pool (port hopping)   (default: $(MTD_PORT_POOL))"
	@echo "  MTD_PAD_BUCKETS     Payload padding bucket sizes      (default: $(MTD_PAD_BUCKETS))"
	@echo "  MTD_PAD_INTERVAL    Seconds between padding rotations (default: $(MTD_PAD_INTERVAL))"
	@echo "  MTD_SCMC_IP_POOL    SCMC source IP pool (src hopping) (default: $(MTD_SCMC_IP_POOL))"
	@echo "  MTD_SRC_HOP_INTERVAL Seconds between source-IP hops   (default: $(MTD_SRC_HOP_INTERVAL))"
	@echo "  MTD_FREQ_POOL       Publish-interval pool (freq hop)  (default: $(MTD_FREQ_POOL))"
	@echo "  MTD_FREQ_INTERVAL   Seconds between freq changes      (default: $(MTD_FREQ_INTERVAL))"
	@echo ""
	@echo "Replay parameters:"
	@echo "  BG_REPLAY_MBPS      Background trace replay rate Mbit/s (default: $(BG_REPLAY_MBPS))"

split $(TRAIN_TRACE) $(TEST_TRACE):
	@mkdir -p $(SPLIT_DIR)
	$(PYTHON) split_trace.py $(BG_TRACE) --train-ratio $(SPLIT_RATIO) --train-out $(TRAIN_TRACE) --test-out $(TEST_TRACE)

# Order-only prerequisites (|): build what is missing, but skip generation
# entirely when the output already exists, regardless of timestamps.
dataset-train: $(TRAIN_PCAP)

$(TRAIN_PCAP): | $(TRAIN_TRACE)
	$(PYTHON) run_experiment.py --generate-dataset $(DATASET_DURATION) $(MTD_FLAG) $(MTD_PARAMS_FLAG) \
		--bg-replay-mbps $(BG_REPLAY_MBPS) \
		--name train --trace $(TRAIN_TRACE) --datasets-dir $(EXP_DIR)/datasets

dataset-test: $(TEST_PCAP)

$(TEST_PCAP): | $(TEST_TRACE)
	$(PYTHON) run_experiment.py --generate-dataset $(DATASET_DURATION) $(MTD_FLAG) $(MTD_PARAMS_FLAG) \
		--bg-replay-mbps $(BG_REPLAY_MBPS) \
		--name test --trace $(TEST_TRACE) --datasets-dir $(EXP_DIR)/datasets

datasets: dataset-train dataset-test

# Generate datasets for both variants (baseline + mtd).
all-datasets:
	$(MAKE) datasets NO_MTD=1
	$(MAKE) datasets NO_MTD=0

# Ground-truth labeling pools for classify.py: nanogrid = traffic between the
# SCMC source-IP pool and the SEMP broker-IP pool (port-agnostic). Must match the
# pools the lab actually hops across, or train/eval labels (and the metric) are wrong.
CLASSIFY_LABEL_FLAGS := --scmc-ip-pool $(MTD_SCMC_IP_POOL) --semp-ip-pool $(MTD_IP_POOL)

# Training produces model.pt + scaler.pkl in $(EXP_DIR)/model
$(MODEL):
	$(PYTHON) classify.py --mode train --train-pcap $(TRAIN_PCAP) --out-dir $(EXP_DIR)/model \
		$(CLASSIFY_LABEL_FLAGS)

train: $(MODEL)

# Train both classifiers (baseline + mtd).
all-train:
	$(MAKE) train NO_MTD=1
	$(MAKE) train NO_MTD=0

evaluate: $(ATTACK_MODEL) $(TEST_PCAP)
	$(PYTHON) classify.py --mode evaluate --load-model --test-pcap $(TEST_PCAP) \
		--model $(ATTACK_MODEL) --scaler $(ATTACK_SCALER) --out-dir $(EVAL_OUT_DIR) \
		$(CLASSIFY_LABEL_FLAGS)

attack: $(ATTACK_MODEL)
	$(PYTHON) run_experiment.py --attack $(ATTACK_DURATION) --post-attack $(POST_ATTACK) $(MTD_FLAG) $(MTD_PARAMS_FLAG) \
		--bg-replay-mbps $(BG_REPLAY_MBPS) \
		--results-dir $(ATTACK_OUT_DIR) --model $(ATTACK_MODEL) --scaler $(ATTACK_SCALER) --trace $(TEST_TRACE)

# Cross-model: the foreign model must be trained already — don't silently
# rebuild it on the wrong dataset.
ifneq ($(MODEL_SRC),$(VARIANT))
$(ATTACK_MODEL):
	@echo "Cross-model: $@ not found. Train it first: 'make train NO_MTD=1' (baseline) or 'make train' (mtd)." >&2; exit 1
endif

# Baseline: same as `attack` but with MTD disabled.
baseline:
	$(MAKE) attack NO_MTD=1

demo:
	$(PYTHON) run_experiment.py

experiment: datasets train attack

experiment-baseline:
	$(MAKE) experiment NO_MTD=1

# All three evaluation/attack combinations in dependency order:
# 1. baseline dataset + baseline model (also trains baseline model)
# 2. mtd dataset + mtd model (also trains mtd model)
# 3. mtd dataset + baseline model (cross-model; both models already exist after 1+2)
all-evaluate:
	$(MAKE) evaluate NO_MTD=1
	$(MAKE) evaluate
	$(MAKE) evaluate MODEL_SRC=baseline

all-attack:
	$(MAKE) attack NO_MTD=1
	$(MAKE) attack
	$(MAKE) attack MODEL_SRC=baseline

all:
	$(MAKE) all-datasets
	$(MAKE) all-evaluate
	$(MAKE) all-attack
	$(MAKE) plots

# Build the entropy CSVs (baseline + current variant) first so plot_results can
# render the comparison/timeseries figures alongside detection/availability.
plots:
	$(MAKE) entropy NO_MTD=1
	$(MAKE) entropy
	$(PYTHON) plot_results.py --mtd-params-slug $(MTD_PARAMS_SLUG) --bg-replay-mbps $(BG_REPLAY_MBPS) \
		--plots-dir $(EXP_DIR)

# Standalone figures for the no-MTD baseline run -> output/baseline-mbps<M>/
plots-baseline:
	$(MAKE) entropy NO_MTD=1
	$(PYTHON) plot_results.py --baseline-only --bg-replay-mbps $(BG_REPLAY_MBPS) \
		--plots-dir output/baseline-mbps$(BG_REPLAY_MBPS)

# Regenerate figures + summary.csv for every experiment dir under output/.
# Add NO_DETECTION=1 to skip the (slow) pcap re-scoring and refresh availability only.
plots-all:
	$(PYTHON) plot_results.py --replot-all --output-root output \
		$(if $(filter-out 0 no false off,$(NO_DETECTION)),--no-detection,)

# ── Entropy metric (model-free MTD effectiveness) ────────────────────────────
# Flow-distribution + per-field Shannon entropy of the nanogrid traffic in the
# test capture. Reuses the same labeling pools as classify.py so the nanogrid
# packets match train/eval exactly.
entropy: $(TEST_PCAP)
	$(PYTHON) entropy.py --test-pcap $(TEST_PCAP) \
		--scmc-ip-pool $(MTD_SCMC_IP_POOL) --semp-ip-pool $(MTD_IP_POOL) \
		--out-dir $(EXP_DIR)

# Baseline-vs-MTD comparison figure -> $(EXP_DIR)/entropy_comparison.pdf.
# Requires both configs' entropy.csv (run `make entropy NO_MTD=1` and
# `make entropy` first).
entropy-compare:
	$(PYTHON) entropy.py --compare \
		--baseline-csv $(BASELINE_DIR)/entropy.csv \
		--mtd-csv $(EXP_DIR)/entropy.csv \
		--out-dir $(EXP_DIR)

# Generous SEMP/broker labeling pool that brackets every config's actual pool
# (the broker only ever uses 10.1.0.x; replayed background uses neither subnet),
# so one fixed pool labels nanogrid correctly for any dir. Entropy is computed
# over the *observed* values, so a superset pool gives identical results — verified
# against the exact-pool run. Override if a config uses broker IPs outside this set.
ENTROPY_SEMP_POOL ?= 10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6,10.1.0.7,10.1.0.8

# Recompute entropy.csv for every experiment dir that already has a test capture,
# then refresh ALL figures (entropy + detection/availability/topk) from the
# existing results — no lab redeploy. The exact SCMC source pool comes from each
# dir's datasets/scmc_ips.txt; the broker pool is the generous set above.
# Add NO_DETECTION=1 to skip the slow pcap re-scoring in the figure refresh.
entropy-all:
	@for pcap in output/*/datasets/test.pcap; do \
		[ -e "$$pcap" ] || continue; \
		ddir=$$(dirname $$pcap); dir=$$(dirname $$ddir); \
		scmc=$$(cat $$ddir/scmc_ips.txt 2>/dev/null); \
		[ -n "$$scmc" ] || scmc=10.0.0.2; \
		echo "=== entropy: $$dir  (scmc=$$scmc) ==="; \
		$(PYTHON) entropy.py --test-pcap $$pcap \
			--scmc-ip-pool $$scmc --semp-ip-pool $(ENTROPY_SEMP_POOL) \
			--out-dir $$dir || true; \
	done
	$(MAKE) plots-all $(if $(filter-out 0 no false off,$(NO_DETECTION)),NO_DETECTION=1,)

clean:
	rm -rf output
