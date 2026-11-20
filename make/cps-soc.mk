# cps-soc.mk — the cps-advisor lab with a real SOC's tools for the blue team:
# Wazuh's indexer and dashboard as the SIEM, DFIR-IRIS as case management, where
# the SOC's suggestions wait as tasks. Same CPS_* and CPS_ADVISOR_* variables as
# cps.mk and cps-advisor.mk. Needs cps-image, then cps-soc-image.

CPS_SOC_OUT        ?= $(OUTPUT_ROOT)/cps-soc/run-1
# Host ports of the SIEM's dashboard and of IRIS (both HTTPS, lab certificates).
CPS_SIEM_PORT      ?= 8770
CPS_CASES_PORT     ?= 8771
CPS_SOC_FLAGS := --respond $(CPS_ADVISOR_RESPOND) --approval operator:$(CPS_ADVISOR_TIMEOUT) \
	--blue-shell-port $(CPS_BLUE_SHELL_PORT) --siem-port $(CPS_SIEM_PORT) --cases-port $(CPS_CASES_PORT)

cps-soc-image:             ## build the SOC tools' images (lab CA, SOC + shipper, Wazuh indexer/dashboard, IRIS); after cps-image
	docker build -t kathara/wazuh-pki docker/wazuh-pki/
	docker build -t kathara/soc-siem docker/soc-siem/
	docker build -t kathara/wazuh-indexer docker/wazuh-indexer/
	docker build -t kathara/wazuh-dashboard docker/wazuh-dashboard/
	docker build -t kathara/iris-app docker/iris-app/
	docker build -t kathara/iris-web docker/iris-web/
	docker pull ghcr.io/dfir-iris/iriswebapp_db:v2.4.29
	docker pull rabbitmq:3.13.7-management-alpine

cps-soc-lab:               ## deploy the cps-soc lab, normal operation only (PLAYGROUND=1 to keep it up)
	$(PYTHON) -m $(M_CPS_SOC_RUN) --out-dir $(CPS_SOC_OUT) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_SOC_FLAGS) $(CPS_IT_FLAG) $(PLAYGROUND_FLAG)

cps-soc:                   ## attack the cps-soc lab: the SOC's suggestions wait as tasks in IRIS
	$(PYTHON) -m $(M_CPS_SOC_RUN) --out-dir $(CPS_SOC_OUT) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --post-attack-duration $(CPS_ADVISOR_POST) \
		--step-interval $(CPS_STEP) --attack --attack-mode $(CPS_ATTACK_MODE) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_SOC_FLAGS) $(CPS_ATTACK_FLAGS) $(CPS_IT_FLAG) \
		$(PLAYGROUND_FLAG)

cps-soc-teams:             ## red team vs blue team on the cps-soc lab: up until Ctrl-C, links in teams.json
	$(PYTHON) -m $(M_CPS_SOC_RUN) --out-dir $(CPS_SOC_OUT) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		$(CPS_SEED_FLAG) $(CPS_SOC_FLAGS) $(CPS_IT_FLAG) --teams --playground \
		--red-port $(CPS_RED_PORT) --red-shell-port $(CPS_RED_SHELL_PORT)

cps-soc-dashboard:         ## the dashboard restricted to the cps-soc runs
	$(PYTHON) -m $(M_DASHBOARD) --root $(OUTPUT_ROOT) --scenario cps-soc --port $(CPS_DASH_PORT)
