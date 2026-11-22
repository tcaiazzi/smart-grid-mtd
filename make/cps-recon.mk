# cps-recon.mk — the cyber-physical lab with a recon-driven attacker: it is not
# handed the attack tree, it derives it by reconnaissance (nmap on its own box,
# then living off the land on the HMI). Same lab and CPS_* variables as cps.mk;
# the attacker runs on its own image (kathara/redteam), built by cps-recon-image.

CPS_RECON_OUT ?=

cps-recon-image:           ## build the attacker's red-team image (nmap); needs cps-image too
	docker build -t kathara/redteam docker/redteam/

cps-recon-lab:             ## deploy the recon lab, normal operation only (PLAYGROUND=1 to keep it up)
	$(PYTHON) -m $(M_CPS_RECON_RUN) $(call run_dir,$(CPS_RECON_OUT)) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_RESPOND_FLAGS) $(CPS_IT_FLAG) $(PLAYGROUND_FLAG)

cps-recon:                 ## attack the lab with the recon-driven attacker (it derives its own tree)
	$(PYTHON) -m $(M_CPS_RECON_RUN) $(call run_dir,$(CPS_RECON_OUT)) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --post-attack-duration $(CPS_POST) \
		--step-interval $(CPS_STEP) --attack \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_RESPOND_FLAGS) $(CPS_ATTACK_FLAGS) $(CPS_IT_FLAG) \
		$(PLAYGROUND_FLAG)

cps-recon-dashboard:       ## the dashboard restricted to the recon runs (what the attacker knows)
	$(PYTHON) -m $(M_DASHBOARD) --root $(OUTPUT_ROOT) --scenario cps-recon --port $(CPS_DASH_PORT)
