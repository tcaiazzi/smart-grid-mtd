# common.mk — what every scenario shares: the interpreter, the output root,
# seeding, and the platform-wide targets.
#
# It also names every Python entry point once (the M_* variables below). Module
# paths are an internal API — the campaign runner shells out to these same
# targets — and spelling them inline across forty rules means a module that
# moves leaves forty stale strings, which `make -n` prints without complaint.
# Naming them here makes a move a one-line edit, and tests/test_entry_points.py
# resolves every one of them for real.

PYTHON ?= .venv/bin/python

OUTPUT_ROOT      ?= output
SEED             ?=
SEED_FLAG        := $(if $(SEED),--seed $(SEED))

# -- Python entry points ------------------------------------------------------
# Platform
M_CORE            := cyberrange.core
M_DASHBOARD       := cyberrange.core.dashboard
# MQTT scenario
M_MQTT_RUN        := cyberrange.scenarios.mqtt_mtd.cli
M_SPLIT_TRACE     := cyberrange.scenarios.mqtt_mtd.tools.split_trace
M_CLASSIFY        := cyberrange.planes.attack.classify
M_PLOT_RESULTS    := cyberrange.scenarios.mqtt_mtd.analysis.plot_results
M_ENTROPY         := cyberrange.scenarios.mqtt_mtd.analysis.entropy
M_COMPARE         := cyberrange.scenarios.mqtt_mtd.analysis.compare_coordinators
M_DELIVERY_DATA   := cyberrange.scenarios.mqtt_mtd.analysis.delivery_dataset
M_TRAIN_RL        := cyberrange.scenarios.mqtt_mtd.training.train_rl_coordinator
M_TRAIN_DETECTOR  := cyberrange.scenarios.mqtt_mtd.training.train_delivery_detector
M_TRADEOFF        := cyberrange.scenarios.mqtt_mtd.analysis.tradeoff
# CPS scenario
M_CPS_RUN         := cyberrange.scenarios.cps.cli
M_CPS_CAMPAIGN    := cyberrange.scenarios.cps.campaign
M_CPS_RESPONDER   := cyberrange.scenarios.cps.responder
M_CPS_METRICS     := cyberrange.scenarios.cps.metrics

# ── Platform (every scenario) ────────────────────────────────────────────────
SCENARIO ?= cps

dashboard:                 ## progress dashboard of every scenario's runs/campaigns on http://127.0.0.1:$(CPS_DASH_PORT)
	$(PYTHON) -m $(M_DASHBOARD) --root $(OUTPUT_ROOT) --port $(CPS_DASH_PORT)

fmt:                       ## reformat every Python file (ruff format, 100 columns)
	$(PYTHON) -m ruff format .

lint:                      ## report style and dead-code problems without changing anything
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .

selftest:                  ## the whole test suite (no Kathará, no Docker)
	$(PYTHON) -m pytest tests -q

selftest-fast:             ## the suite without the heavy tests (no torch/pandapower/subprocesses)
	$(PYTHON) -m pytest tests -q -m "not slow"

lab-conf:                  ## export SCENARIO's topology as a Kathará lab dir (lab.conf + .startup)
	$(PYTHON) -m $(M_CORE) export $(SCENARIO) --out $(OUTPUT_ROOT)/labconf/$(SCENARIO)

platform-loc:              ## lines of code: platform core vs per-plane components vs each scenario
	$(PYTHON) -m $(M_CORE) loc --markdown $(OUTPUT_ROOT)/platform-loc.md

clean:
	rm -rf output

