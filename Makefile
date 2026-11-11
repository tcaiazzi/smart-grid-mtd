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
#   output/sweep/                          aggregate sweep plots (from scripts/run_sweep.sh)
#
# MTD vs baseline: set NO_MTD=1 for the baseline (no-MTD) variant.
# Cross-model attack: MODEL_SRC=baseline uses the baseline model on MTD traffic.
#
# Override variables as needed, e.g.:
#   make dataset-train TRAIN_TRACE=assets/pcap/traccia.pcap DATASET_DURATION=60
#   make datasets MTD_HOP_INTERVAL=1 MTD_PORT_POOL=8883,8884,8885,8886,8887,8888
#
# The rules live next door, one file per scenario plus the shared platform:
#   make/common.mk   interpreter, output root, entry points, platform targets
#   make/mqtt.mk     the MQTT pipeline (datasets, train, attack, plots, RL)
#   make/cps.mk      the cyber-physical OT/Modbus scenario
# Target names are unchanged and remain the interface: the campaign runner
# shells out to them, and the tests parse `make help`.

include make/common.mk
include make/mqtt.mk
include make/cps.mk

.PHONY: help split datasets dataset-train dataset-test all-datasets train all-train evaluate attack baseline demo experiment experiment-baseline all-evaluate all-attack all plots plots-baseline plots-all entropy entropy-compare entropy-all train-rl train-rl-entropy compare-rl compare-rl-all plot-tradeoff detector-runs detector-dataset detector-train detector-final cps-image cps-selftest cps-engine cps-lab cps-attack cps-campaign cps-dashboard cps-metrics cps-replay dashboard fmt lint selftest selftest-fast lab-conf platform-loc clean

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
	@echo "                      POST_ATTACK=$(POST_ATTACK)s observed after the block,"
	@echo "                      BLOCK_POLICY=$(BLOCK_POLICY), BLOCK_THRESHOLD=$(or $(BLOCK_THRESHOLD),default))"
	@echo "                      -> $(ATTACK_OUT_DIR)"
	@echo "                      Cross-model: make attack MODEL_SRC=baseline"
	@echo "  baseline            Run the attack with MTD disabled"
	@echo "  all-attack          Run all three attack scenarios"
	@echo "  all                 Full pipeline: both datasets -> all-evaluate -> all-attack -> plots"
	@echo "  experiment          Full pipeline with MTD: datasets -> train -> attack"
	@echo "  detector-runs       Labelled attack runs for the delivery-attack detector"
	@echo "                      (DET_SEEDS='$(DET_SEEDS)' x DET_VARIANTS='$(DET_VARIANTS)' x DET_ATTACKS='$(DET_ATTACKS)')"
	@echo "                      -> $(DET_ROOT)/runs/"
	@echo "  detector-train      Dataset + dev-seed ablation (DET_DEV_SEEDS=$(DET_DEV_SEEDS)) -> $(DET_ROOT)/ablation.md"
	@echo "  detector-final      Fit the chosen config on dev, score the test seeds ONCE -> $(DET_ROOT)/kpi.md"
	@echo "  experiment-baseline Full pipeline without MTD (NO_MTD=1)"
	@echo "  plots               Compare scenarios -> $(EXP_DIR)/"
	@echo "  plots-baseline      Standalone baseline figures -> $(OUTPUT_ROOT)/baseline-mbps$(BG_REPLAY_MBPS)/"
	@echo "  plots-all           Replot every experiment dir under $(OUTPUT_ROOT)/ (NO_DETECTION=1 to skip scoring)"
	@echo "  entropy             Flow/field entropy of the nanogrid traffic -> $(EXP_DIR)/entropy.csv"
	@echo "  entropy-compare     Baseline-vs-MTD entropy figure -> $(EXP_DIR)/entropy_comparison.pdf"
	@echo "  entropy-all         Recompute entropy + refresh ALL figures from existing results (NO_DETECTION=1 to skip scoring)"
	@echo "  train-rl            Train the RL coordinator policy offline -> $(RL_DIR)/policy.{zip,npz}"
	@echo "  compare-rl          Model-free RL-vs-fixed-MTD comparison -> $(OUTPUT_ROOT)/compare-<slug>/"
	@echo "  plot-tradeoff       Security-vs-hop-cost frontier (RL vs fixed) -> $(RL_DIR)/tradeoff.pdf"
	@echo "  dashboard           Live progress of every scenario's runs/campaigns (http://127.0.0.1:$(CPS_DASH_PORT))"
	@echo "  fmt                 Reformat every Python file (ruff, 100 columns)"
	@echo "  lint                Report style and dead-code problems, change nothing"
	@echo "  selftest            Whole test suite, no Kathará/Docker"
	@echo "  selftest-fast       Same, without the heavy tests (-m 'not slow')"
	@echo "  lab-conf            Export SCENARIO=$(SCENARIO) as a Kathará lab dir -> $(OUTPUT_ROOT)/labconf/$(SCENARIO)/"
	@echo "  platform-loc        Code size: platform core vs plane components vs scenarios"
	@echo "  clean               Remove all generated outputs"
	@echo ""
	@echo "RL coordinator: add RL=1 to datasets/train/attack to use the trained policy"
	@echo "  RL_POLICY           Distilled policy used at RL=1     (default: $(RL_POLICY))"
	@echo "  RL_TIMESTEPS        PPO training steps for train-rl   (default: $(RL_TIMESTEPS))"
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
