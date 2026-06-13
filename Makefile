# Smart Grid AI-MTD — pipeline: dataset -> train -> attack
#
# Quick start:
#   make datasets     # generate train+test PCAPs (deploys the Kathará lab twice)
#   make train        # train the 1D-CNN on the train dataset
#   make evaluate     # evaluate on the test dataset using the saved model (trains first if absent)
#   make attack       # run the model-driven attack in the lab
#   make experiment   # full pipeline: datasets -> train -> attack
#
# Output structure:
#   output/models/<variant>/              trained model + scaler
#   output/datasets/<variant>/            train/test PCAPs
#   output/ml-results/<scenario-slug>/    evaluate metrics (predictions, plots)
#   output/experiment-results/<slug>/     attack captures, ranking, broker log
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
ATTACK_DURATION  ?= 30
BG_REPLAY_MBPS   ?= 2

# ── MTD parameters ─────────────────────────────────────────────────────────────
# Tune these to make fingerprinting harder.
# Shorter intervals and larger pools create more candidate flows, diluting the
# nanogrid signal seen by the attacker.
MTD_HOP_INTERVAL ?= 2
MTD_IP_POOL      ?= 10.1.0.2,10.1.0.4,10.1.0.5
MTD_PORT_POOL    ?= 8883,8884,8885,8886,8887
MTD_PAD_BUCKETS  ?= 128,256,384,512,640,768,1024
MTD_PAD_INTERVAL ?= 3
MTD_PARAMS_FLAG  := --mtd-hop-interval $(MTD_HOP_INTERVAL) \
                    --mtd-ip-pool $(MTD_IP_POOL) \
                    --mtd-port-pool $(MTD_PORT_POOL) \
                    --mtd-pad-buckets $(MTD_PAD_BUCKETS) \
                    --mtd-pad-interval $(MTD_PAD_INTERVAL)

# Compact slug encoding the active MTD parameters (used in output dir names).
comma        := ,
MTD_N_IPS    := $(words $(subst $(comma), ,$(MTD_IP_POOL)))
MTD_N_PORTS  := $(words $(subst $(comma), ,$(MTD_PORT_POOL)))
MTD_N_PADS   := $(words $(subst $(comma), ,$(MTD_PAD_BUCKETS)))
MTD_PARAMS_SLUG := hop$(MTD_HOP_INTERVAL)-padint$(MTD_PAD_INTERVAL)-ips$(MTD_N_IPS)-ports$(MTD_N_PORTS)-pads$(MTD_N_PADS)-mbps$(BG_REPLAY_MBPS)

# ── Attack model source ────────────────────────────────────────────────────────
# Defaults to the run variant. Set MODEL_SRC=baseline to use the baseline model
# on MTD traffic (cross-model attack).
MODEL_SRC ?= $(VARIANT)

# ── Scenario slug ─────────────────────────────────────────────────────────────
# Identifies the (dataset-variant, model-variant, MTD-params) triple.
# MTD params are omitted for the baseline scenario (coordinator not started).
ifeq ($(VARIANT),baseline)
  SCENARIO_SLUG := baseline-scenario-baseline-model-mbps$(BG_REPLAY_MBPS)
else ifeq ($(MODEL_SRC),baseline)
  SCENARIO_SLUG := mtd-scenario-baseline-model-$(MTD_PARAMS_SLUG)
else
  SCENARIO_SLUG := mtd-scenario-mtd-model-$(MTD_PARAMS_SLUG)
endif

# ── Output directories ─────────────────────────────────────────────────────────
MODELS_DIR   := output/models
MODEL_DIR    := $(MODELS_DIR)/$(VARIANT)
MODEL        := $(MODEL_DIR)/model.pt
SCALER       := $(MODEL_DIR)/scaler.pkl

ATTACK_MODEL  := $(MODELS_DIR)/$(MODEL_SRC)/model.pt
ATTACK_SCALER := $(MODELS_DIR)/$(MODEL_SRC)/scaler.pkl

DATASETS_DIR := output/datasets/$(VARIANT)
TRAIN_PCAP   := $(DATASETS_DIR)/train.pcap
TEST_PCAP    := $(DATASETS_DIR)/test.pcap

EVAL_OUT_DIR   := output/ml-results/$(SCENARIO_SLUG)
ATTACK_OUT_DIR := output/experiment-results/$(SCENARIO_SLUG)

.PHONY: help split datasets dataset-train dataset-test all-datasets train all-train evaluate attack baseline demo experiment experiment-baseline all-evaluate all-attack all plots clean

help:
	@echo "Variant: $(VARIANT)  (set NO_MTD=1 for baseline)   Model: $(MODEL_SRC)"
	@echo "Scenario slug: $(SCENARIO_SLUG)"
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
	@echo "  attack              Run the model-driven attack (ATTACK_DURATION=$(ATTACK_DURATION)s)"
	@echo "                      -> $(ATTACK_OUT_DIR)"
	@echo "                      Cross-model: make attack MODEL_SRC=baseline"
	@echo "  baseline            Run the attack with MTD disabled"
	@echo "  all-attack          Run all three attack scenarios"
	@echo "  all                 Full pipeline: both datasets -> all-evaluate -> all-attack -> plots"
	@echo "  experiment          Full pipeline with MTD: datasets -> train -> attack"
	@echo "  experiment-baseline Full pipeline without MTD (NO_MTD=1)"
	@echo "  plots               Compare scenarios -> output/plots/"
	@echo "  clean               Remove all generated outputs"
	@echo ""
	@echo "MTD parameters (override on the command line):"
	@echo "  MTD_HOP_INTERVAL    Seconds between hops              (default: $(MTD_HOP_INTERVAL))"
	@echo "  MTD_IP_POOL         Broker IP pool (IP hopping)       (default: $(MTD_IP_POOL))"
	@echo "  MTD_PORT_POOL       Broker port pool (port hopping)   (default: $(MTD_PORT_POOL))"
	@echo "  MTD_PAD_BUCKETS     Payload padding bucket sizes      (default: $(MTD_PAD_BUCKETS))"
	@echo "  MTD_PAD_INTERVAL    Seconds between padding rotations (default: $(MTD_PAD_INTERVAL))"
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
		--name train --trace $(TRAIN_TRACE) --datasets-dir $(DATASETS_DIR)

dataset-test: $(TEST_PCAP)

$(TEST_PCAP): | $(TEST_TRACE)
	$(PYTHON) run_experiment.py --generate-dataset $(DATASET_DURATION) $(MTD_FLAG) $(MTD_PARAMS_FLAG) \
		--bg-replay-mbps $(BG_REPLAY_MBPS) \
		--name test --trace $(TEST_TRACE) --datasets-dir $(DATASETS_DIR)

datasets: dataset-train dataset-test

# Generate datasets for both variants (baseline + mtd).
all-datasets:
	$(MAKE) datasets NO_MTD=1
	$(MAKE) datasets

# Training produces model.pt + scaler.pkl in $(MODEL_DIR)
$(MODEL):
	$(PYTHON) classify.py --mode train --train-pcap $(TRAIN_PCAP) --out-dir $(MODEL_DIR)

train: $(MODEL)

# Train both classifiers (baseline + mtd).
all-train:
	$(MAKE) train NO_MTD=1
	$(MAKE) train

evaluate: $(ATTACK_MODEL) $(TEST_PCAP)
	$(PYTHON) classify.py --mode evaluate --load-model --test-pcap $(TEST_PCAP) \
		--model $(ATTACK_MODEL) --scaler $(ATTACK_SCALER) --out-dir $(EVAL_OUT_DIR)

attack: $(ATTACK_MODEL)
	$(PYTHON) run_experiment.py --attack $(ATTACK_DURATION) $(MTD_FLAG) $(MTD_PARAMS_FLAG) \
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

plots:
	$(PYTHON) plot_results.py --mtd-params-slug $(MTD_PARAMS_SLUG) --bg-replay-mbps $(BG_REPLAY_MBPS)

clean:
	rm -rf output/models output/datasets output/ml-results output/experiment-results output/plots
