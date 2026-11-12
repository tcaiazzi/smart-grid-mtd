# cps.mk — the cyber-physical (OT/Modbus) scenario: the pandapower twin behind
# Modbus, the PLC and the HMI, the active attack chain, the OT/IT sensors and
# the SOAR response loop.

# ── Cyber-physical (OT/Modbus) scenario — doc steps 1–4 ──────────────────────
# Variables for the OT scenario. The lab needs the kathara/cps image (cps-image).
CPS_OUT          ?= $(OUTPUT_ROOT)/cps/run-1
CPS_NORMAL       ?= 60
CPS_LEARN        ?= 45
CPS_POST         ?= 30
CPS_STEP         ?= 1.0
CPS_DETECTORS    ?= rules,model
# setpoint-overvoltage (loud, PLC recovers) | breaker-open (policy violation)
# | manual-hijack (stealthy: in-range writes from the HMI, impact persists)
CPS_ATTACK_MODE  ?= setpoint-overvoltage
CPS_SEED_FLAG    := $(if $(SEED),--seed $(SEED))
# Campaigns (cps-campaign): reuse the same CPS_CAMPAIGN name to resume one.
CPS_CAMPAIGN     ?= $(shell date +%Y%m%d-%H%M)
CPS_SEEDS        ?= 1-5
CPS_MODES        ?= normal,setpoint-overvoltage,breaker-open,manual-hijack
CPS_DASH_PORT    ?= 8765
# SOAR prototype: response policy (off | rules | solver) and operator approval
# for high-impact countermeasures (auto | deny | delay:<s>).
CPS_RESPOND      ?= off
CPS_APPROVAL     ?= auto
CPS_RESPOND_FLAGS := --respond $(CPS_RESPOND) --approval $(CPS_APPROVAL)
# Attack driver: scripted (fixed per-mode chain) | planner (reactive, tree-guided).
CPS_ATTACK_DRIVER ?= scripted
CPS_PROFILE       ?= opportunistic
CPS_DWELL         ?= 0
CPS_ATTACK_FLAGS  := --attack-driver $(CPS_ATTACK_DRIVER) --attacker-profile $(CPS_PROFILE) \
	--dwell $(CPS_DWELL) $(if $(CPS_GOAL),--attack-goal $(CPS_GOAL))
# IT-side telemetry (sensor on the HMI + legitimate diagnostic traffic): CPS_IT=1.
CPS_IT            ?=
CPS_IT_FLAG       := $(if $(CPS_IT),--it-telemetry)
# The CPS slice of the suite (cps-selftest): the scenario's own tests plus the
# plane tests that exercise the OT code it runs, and the two core tests that
# cover the ledger and the dashboard it reports through. Directories, not a
# list of modules: a new test lands in the slice by being written in the right
# place.
CPS_TESTS := tests/scenarios/cps tests/planes \
	tests/core/test_progress.py tests/core/test_dashboard.py

cps-image:                 ## build the OT node image (pandapower + pymodbus)
	docker build -t kathara/cps docker/cps/

cps-selftest:              ## CPS physics, Modbus, PLC, sensor rules+model, attack chain, metrics — NO Kathará
	$(PYTHON) -m pytest -q $(CPS_TESTS)

cps-engine:                ## run engine + PLC locally over loopback Modbus (Ctrl-C to stop)
	@echo "Start the engine and PLC in two shells:"
	@echo "  PYTHONPATH=cyberrange/planes/traffic/agents:cyberrange/planes/defense $(PYTHON) -m modbus_engine --frame-log engine_frames.jsonl"
	@echo "  PYTHONPATH=cyberrange/planes/traffic/agents:cyberrange/planes/defense $(PYTHON) -m plc_controller --engine-host 127.0.0.1"

cps-lab:                   ## deploy the lab, normal operation only
	$(PYTHON) -m $(M_CPS_RUN) --out-dir $(CPS_OUT) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_RESPOND_FLAGS) $(CPS_IT_FLAG)

cps-attack:                ## deploy the lab and drive the active attack chain (CPS_ATTACK_MODE)
	$(PYTHON) -m $(M_CPS_RUN) --out-dir $(CPS_OUT) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --post-attack-duration $(CPS_POST) \
		--step-interval $(CPS_STEP) --attack --attack-mode $(CPS_ATTACK_MODE) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_RESPOND_FLAGS) $(CPS_ATTACK_FLAGS) $(CPS_IT_FLAG)

cps-campaign:              ## run a campaign: CPS_MODES x CPS_SEEDS, scored + aggregated (resumable)
	$(PYTHON) -m $(M_CPS_CAMPAIGN) --name $(CPS_CAMPAIGN) \
		--modes $(CPS_MODES) --seeds $(CPS_SEEDS) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--post-attack-duration $(CPS_POST) --step-interval $(CPS_STEP) \
		--detectors $(CPS_DETECTORS) $(CPS_RESPOND_FLAGS) $(CPS_ATTACK_FLAGS) $(CPS_IT_FLAG) \
		$(if $(DRY),--dry-run)

cps-dashboard:             ## progress dashboard restricted to the CPS runs/campaigns
	$(PYTHON) -m $(M_DASHBOARD) --root $(OUTPUT_ROOT) --scenario cps --port $(CPS_DASH_PORT)

cps-metrics:               ## score a finished run (detection, impact, response)
	$(PYTHON) -m $(M_CPS_METRICS) --out-dir $(CPS_OUT) --report $(CPS_OUT)/metrics.md

cps-replay:                ## what a response policy WOULD have done on a finished run (CPS_RESPOND)
	$(PYTHON) -m $(M_CPS_RESPONDER) --replay $(CPS_OUT) \
		--policy $(if $(filter off,$(CPS_RESPOND)),rules,$(CPS_RESPOND)) --approval $(CPS_APPROVAL)

