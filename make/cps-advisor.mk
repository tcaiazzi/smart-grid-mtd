# cps-advisor.mk — the cyber-physical lab with a SOC that advises: every
# countermeasure is put to an operator, who approves or rejects it from the
# dashboard. Same lab and images as cps.mk (cps-image), whose CPS_* variables
# for durations, detectors and the attack apply here too.

CPS_ADVISOR_OUT     ?= $(OUTPUT_ROOT)/cps-advisor/run-1
# The policy that advises (rules | solver) and how long a suggestion waits.
CPS_ADVISOR_RESPOND ?= solver
CPS_ADVISOR_TIMEOUT ?= 120
# Long enough after the attack for a person to read a suggestion and answer it;
# PLAYGROUND=1 keeps the lab up for as long as it takes.
CPS_ADVISOR_POST    ?= 180
# Host port of the SOC's operator API. The dashboard on CPS_DASH_PORT is the
# console allowed to call it.
CPS_OPERATOR_PORT   ?= 8766
CPS_ADVISOR_FLAGS := --respond $(CPS_ADVISOR_RESPOND) --approval operator:$(CPS_ADVISOR_TIMEOUT) \
	--operator-port $(CPS_OPERATOR_PORT) \
	--operator-origin http://127.0.0.1:$(CPS_DASH_PORT) --operator-origin http://localhost:$(CPS_DASH_PORT)

cps-advisor-lab:           ## deploy the advisor lab, normal operation only (PLAYGROUND=1 to keep it up)
	$(PYTHON) -m $(M_CPS_ADVISOR_RUN) --out-dir $(CPS_ADVISOR_OUT) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_ADVISOR_FLAGS) $(CPS_IT_FLAG) $(PLAYGROUND_FLAG)

cps-advisor:               ## attack the advisor lab: the SOC suggests, you approve or reject on the dashboard
	$(PYTHON) -m $(M_CPS_ADVISOR_RUN) --out-dir $(CPS_ADVISOR_OUT) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --post-attack-duration $(CPS_ADVISOR_POST) \
		--step-interval $(CPS_STEP) --attack --attack-mode $(CPS_ATTACK_MODE) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_ADVISOR_FLAGS) $(CPS_ATTACK_FLAGS) $(CPS_IT_FLAG) \
		$(PLAYGROUND_FLAG)

cps-advisor-dashboard:     ## the dashboard restricted to the advisor runs: suggestions and their answers
	$(PYTHON) -m $(M_DASHBOARD) --root $(OUTPUT_ROOT) --scenario cps-advisor --port $(CPS_DASH_PORT)
