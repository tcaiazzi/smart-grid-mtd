# Smart Grid AI-MTD — pipeline: dataset -> train -> attack
#
# Quick start:
#   make datasets     # generate train+test PCAPs (deploys the Kathará lab twice)
#   make train        # train the 1D-CNN on the train dataset
#   make evaluate     # train + evaluate on the test dataset (plots + report)
#   make attack       # run the model-driven attack in the lab
#   make experiment   # full pipeline: datasets -> train -> attack
#
# MTD vs baseline: every target writes to a per-variant output tree
#   output/mtd/...       (default, MTD enabled)
#   output/baseline/...  (NO_MTD=1, MTD disabled)
# so the two runs never overwrite each other. Use the `baseline` /
# `experiment-baseline` convenience targets, or pass NO_MTD=1 to any target.
#
# Override variables as needed, e.g.:
#   make dataset-train TRAIN_TRACE=assets/pcap/traccia.pcap DATASET_DURATION=60

PYTHON ?= .venv/bin/python

# Guard: NO_MTD must be a variable *assignment* (NO_MTD=1), not a bare goal.
# `make train NO_MTD` treats NO_MTD as a target and silently leaves MTD on, so
# catch that and point at the right syntax.
ifneq ($(filter NO_MTD,$(MAKECMDGOALS)),)
  $(error Use NO_MTD=1 as an assignment, e.g. `make train NO_MTD=1` (not a bare `NO_MTD`))
endif

# Experiment variant: MTD enabled (default) or baseline without MTD.
# Baseline only when NO_MTD is truthy; unset, empty, or 0 keeps MTD on.
ifeq ($(filter-out 0 no false off,$(NO_MTD)),)
  VARIANT  := mtd
  MTD_FLAG :=
else
  VARIANT  := baseline
  MTD_FLAG := --no-mtd
endif

# Background trace split (make split): one source trace -> train/test parts.
# Shared between variants (the background noise is the same).
BG_TRACE    ?= assets/pcap/traccia.pcap
SPLIT_RATIO ?= 0.7
SPLIT_DIR   := assets/pcap/datasets

# Background traces replayed during the train/test captures
# (default: the two parts produced by `make split` from BG_TRACE)
TRAIN_TRACE ?= $(SPLIT_DIR)/$(basename $(notdir $(BG_TRACE)))_train.pcap
TEST_TRACE  ?= $(SPLIT_DIR)/$(basename $(notdir $(BG_TRACE)))_test.pcap

DATASET_DURATION ?= 120
ATTACK_DURATION  ?= 30

# Per-variant output tree (output/mtd/... vs output/baseline/...)
OUT_DIR     := output/$(VARIANT)
DATASET_DIR := $(OUT_DIR)/datasets
ML_DIR      := $(OUT_DIR)/ml_results
TRAIN_PCAP  := $(DATASET_DIR)/train.pcap
TEST_PCAP   := $(DATASET_DIR)/test.pcap
MODEL       := $(ML_DIR)/model.pt
SCALER      := $(ML_DIR)/scaler.pkl

.PHONY: help split datasets dataset-train dataset-test train evaluate attack baseline demo experiment experiment-baseline clean

help:
	@echo "Variant: $(VARIANT)  (set NO_MTD=1 for the baseline tree)  ->  $(OUT_DIR)/"
	@echo "Targets:"
	@echo "  split               Split $(BG_TRACE) into $(TRAIN_TRACE) + $(TEST_TRACE) (SPLIT_RATIO=$(SPLIT_RATIO))"
	@echo "  dataset-train       Generate the training dataset ($(TRAIN_PCAP))"
	@echo "  dataset-test        Generate the test dataset ($(TEST_PCAP))"
	@echo "  datasets            Generate both datasets"
	@echo "  train               Train the classifier -> $(MODEL)"
	@echo "  evaluate            Train + evaluate on the test set (report, ROC, confusion matrix)"
	@echo "  attack              Run the model-driven attack (ATTACK_DURATION=$(ATTACK_DURATION)s)"
	@echo "  baseline            Run the attack with MTD disabled (-> output/baseline/)"
	@echo "  demo                Legacy demo, no model needed (hardcoded IP block)"
	@echo "  experiment          Full pipeline with MTD: datasets -> train -> attack"
	@echo "  experiment-baseline Full pipeline without MTD (NO_MTD=1)"
	@echo "  clean               Remove generated outputs (both variants)"

split $(TRAIN_TRACE) $(TEST_TRACE):
	@mkdir -p $(SPLIT_DIR)
	$(PYTHON) split_trace.py $(BG_TRACE) --train-ratio $(SPLIT_RATIO) --train-out $(TRAIN_TRACE) --test-out $(TEST_TRACE)

# Order-only prerequisites (|): build what is missing, but skip generation
# entirely when the output already exists, regardless of timestamps.
dataset-train: $(TRAIN_PCAP)

$(TRAIN_PCAP): | $(TRAIN_TRACE)
	$(PYTHON) run_experiment.py --generate-dataset $(DATASET_DURATION) $(MTD_FLAG) --name train --trace $(TRAIN_TRACE)

dataset-test: $(TEST_PCAP)

$(TEST_PCAP): | $(TEST_TRACE)
	$(PYTHON) run_experiment.py --generate-dataset $(DATASET_DURATION) $(MTD_FLAG) --name test --trace $(TEST_TRACE)

datasets: dataset-train dataset-test

# Training produces model.pt + scaler.pkl in $(ML_DIR)
$(MODEL):
	$(PYTHON) classify.py --mode train --train-pcap $(TRAIN_PCAP) --out-dir $(ML_DIR)

train: $(MODEL)

evaluate: $(TRAIN_PCAP) $(TEST_PCAP)
	$(PYTHON) classify.py --mode evaluate --train-pcap $(TRAIN_PCAP) --test-pcap $(TEST_PCAP) --out-dir $(ML_DIR)

attack: $(MODEL)
	$(PYTHON) run_experiment.py --attack $(ATTACK_DURATION) $(MTD_FLAG) --model $(MODEL) --scaler $(SCALER) --trace $(TEST_TRACE)

# Baseline: same as `attack` but with MTD disabled (mosquitto on 8883, no
# coordinator, plain publisher). Recursive make so every path resolves under
# output/baseline/ (prerequisites build the baseline dataset + model first).
# The classifier should fingerprint the SCMC and the block should take it down
# — the threat MTD must counter.
baseline:
	$(MAKE) attack NO_MTD=1

demo:
	$(PYTHON) run_experiment.py

experiment: datasets train attack

experiment-baseline:
	$(MAKE) experiment NO_MTD=1

clean:
	rm -rf output/mtd output/baseline
