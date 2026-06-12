# Smart Grid AI-MTD — pipeline: dataset -> train -> attack
#
# Quick start:
#   make datasets     # generate train+test PCAPs (deploys the Kathará lab twice)
#   make train        # train the 1D-CNN on the train dataset
#   make evaluate     # train + evaluate on the test dataset (plots + report)
#   make attack       # run the model-driven attack in the lab
#   make experiment   # full pipeline: datasets -> train -> attack
#
# Override variables as needed, e.g.:
#   make dataset-train TRAIN_TRACE=assets/pcap/traccia.pcap DATASET_DURATION=60

PYTHON ?= .venv/bin/python

# Background trace split (make split): one source trace -> train/test parts
BG_TRACE    ?= assets/pcap/traccia.pcap
SPLIT_RATIO ?= 0.7
SPLIT_DIR   := assets/pcap/datasets

# Background traces replayed during the train/test captures
# (default: the two parts produced by `make split` from BG_TRACE)
TRAIN_TRACE ?= $(SPLIT_DIR)/$(basename $(notdir $(BG_TRACE)))_train.pcap
TEST_TRACE  ?= $(SPLIT_DIR)/$(basename $(notdir $(BG_TRACE)))_test.pcap

DATASET_DURATION ?= 120
ATTACK_DURATION  ?= 30

DATASET_DIR := output/datasets
ML_DIR      := output/ml_results
TRAIN_PCAP  := $(DATASET_DIR)/train.pcap
TEST_PCAP   := $(DATASET_DIR)/test.pcap
MODEL       := $(ML_DIR)/model.pt
SCALER      := $(ML_DIR)/scaler.pkl

.PHONY: help split datasets dataset-train dataset-test train evaluate attack demo experiment clean

help:
	@echo "Targets:"
	@echo "  split           Split $(BG_TRACE) into $(TRAIN_TRACE) + $(TEST_TRACE) (SPLIT_RATIO=$(SPLIT_RATIO))"
	@echo "  dataset-train   Generate the training dataset ($(TRAIN_PCAP))"
	@echo "  dataset-test    Generate the test dataset ($(TEST_PCAP))"
	@echo "  datasets        Generate both datasets"
	@echo "  train           Train the classifier -> $(MODEL)"
	@echo "  evaluate        Train + evaluate on the test set (report, ROC, confusion matrix)"
	@echo "  attack          Run the model-driven attack (ATTACK_DURATION=$(ATTACK_DURATION)s)"
	@echo "  demo            Legacy demo, no model needed (hardcoded IP block)"
	@echo "  experiment      Full pipeline: datasets -> train -> attack"
	@echo "  clean           Remove generated outputs (datasets, model, captures)"

split $(TRAIN_TRACE) $(TEST_TRACE):
	@mkdir -p $(SPLIT_DIR)
	$(PYTHON) split_trace.py $(BG_TRACE) --train-ratio $(SPLIT_RATIO) --train-out $(TRAIN_TRACE) --test-out $(TEST_TRACE)

# Order-only prerequisites (|): build what is missing, but skip generation
# entirely when the output already exists, regardless of timestamps.
dataset-train: $(TRAIN_PCAP)

$(TRAIN_PCAP): | $(TRAIN_TRACE)
	$(PYTHON) run_experiment.py --generate-dataset $(DATASET_DURATION) --name train --trace $(TRAIN_TRACE)

dataset-test: $(TEST_PCAP)

$(TEST_PCAP): | $(TEST_TRACE)
	$(PYTHON) run_experiment.py --generate-dataset $(DATASET_DURATION) --name test --trace $(TEST_TRACE)

datasets: dataset-train dataset-test

# Training produces model.pt + scaler.pkl in $(ML_DIR)
$(MODEL): | $(TRAIN_PCAP)
	$(PYTHON) classify.py --mode train --train-pcap $(TRAIN_PCAP)

train: $(MODEL)

evaluate: $(TRAIN_PCAP) $(TEST_PCAP)
	$(PYTHON) classify.py --mode evaluate --train-pcap $(TRAIN_PCAP) --test-pcap $(TEST_PCAP)

attack: $(MODEL)
	$(PYTHON) run_experiment.py --attack $(ATTACK_DURATION) --model $(MODEL) --scaler $(SCALER) --trace $(TEST_TRACE)

demo:
	$(PYTHON) run_experiment.py

experiment: datasets train attack

clean:
	rm -rf $(DATASET_DIR) $(ML_DIR) output/attacker_capture.pcap output/router_capture.pcap output/mosquitto.log
