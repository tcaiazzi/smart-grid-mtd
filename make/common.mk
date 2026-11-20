# common.mk — what every scenario shares: the interpreter, the output root,
# seeding, and the platform-wide targets.
#
# It also names every Python entry point once (the M_* variables below). Module
# paths are an internal API — the campaign runner shells out to these same
# targets — and spelling them inline across forty rules means a module that
# moves leaves forty stale strings, which `make -n` prints without complaint.
# Naming them here makes a move a one-line edit, and tests/core/test_entry_points.py
# resolves every one of them for real.

PYTHON ?= .venv/bin/python

OUTPUT_ROOT      ?= output
# Where a single run writes: a directory of its own under OUTPUT_ROOT
# (<scenario>/runs/<date-time>[-RUN_NAME], with <scenario>/latest pointing at
# it) unless the scenario's *_OUT variable names one. A named directory that
# already holds a run is refused; OVERWRITE=1 empties it first.
RUN_NAME         ?=
OVERWRITE        ?=
run_dir = $(if $(1),--out-dir $(1),--out-root $(OUTPUT_ROOT)) \
	$(if $(RUN_NAME),--run-name $(RUN_NAME)) $(if $(OVERWRITE),--overwrite)
SEED             ?=
SEED_FLAG        := $(if $(SEED),--seed $(SEED))
# PLAYGROUND=1 keeps a single run's lab up after its episode, until Ctrl-C.
PLAYGROUND       ?=
PLAYGROUND_FLAG  := $(if $(PLAYGROUND),--playground)

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
M_ABLATION        := cyberrange.scenarios.mqtt_mtd.ablation
# CPS scenario
M_CPS_RUN         := cyberrange.scenarios.cps.cli
M_CPS_CAMPAIGN    := cyberrange.scenarios.cps.campaign
M_CPS_RESPONDER   := cyberrange.scenarios.cps.responder
M_CPS_METRICS     := cyberrange.scenarios.cps.metrics
# CPS advisor scenario
M_CPS_ADVISOR_RUN := cyberrange.scenarios.cps_advisor.cli
M_CPS_RECON_RUN   := cyberrange.scenarios.cps_recon.cli
M_CPS_SOC_RUN     := cyberrange.scenarios.cps_soc.cli

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

# A target that no longer expands (a renamed variable, a missing include) is
# found by the campaign that shells out to it, hours into a run: dry-run them
# all here. `make` is spelled out, not $(MAKE), so that `make -n check` prints
# the loop instead of running it.
check: lint                ## before calling a change done: lint, the whole suite, a dry run of every target
	$(PYTHON) -m pytest tests -q
	@broken=0; \
	for t in $$(grep -hoE '^[a-zA-Z0-9_.-]+:' Makefile make/*.mk | tr -d ':' | sort -u | grep -vx check); do \
	    make --no-print-directory -n "$$t" >/dev/null 2>&1 || { echo "BROKEN: $$t"; broken=1; }; \
	done; \
	test $$broken -eq 0 && echo "every make target expands"

lab-conf:                  ## export SCENARIO's topology as a Kathará lab dir (lab.conf + .startup)
	$(PYTHON) -m $(M_CORE) export $(SCENARIO) --out $(OUTPUT_ROOT)/labconf/$(SCENARIO)

runs:                      ## list the runs kept under OUTPUT_ROOT, one line each (RUNS_OF=<scenario> for one scenario's)
	$(PYTHON) -m $(M_CORE) runs --root $(OUTPUT_ROOT) $(if $(RUNS_OF),--scenario $(RUNS_OF))

platform-loc:              ## lines of code: platform core vs per-plane components vs each scenario
	$(PYTHON) -m $(M_CORE) loc --markdown $(OUTPUT_ROOT)/platform-loc.md

docs-serve:                ## serve the documentation site with live reload (http://127.0.0.1:8000)
	$(PYTHON) -m mkdocs serve

docs-build:                ## build the documentation site -> $(OUTPUT_ROOT)/site/
	$(PYTHON) -m mkdocs build

clean:
	rm -rf $(OUTPUT_ROOT)

