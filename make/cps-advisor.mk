# cps-advisor.mk — the cyber-physical lab with a SOC that advises: every
# countermeasure is put to an operator, who approves or rejects it at the SOC's
# console; with cps-teams a red team attacks by hand from a console of its own;
# with cps-agents a harness sits at each of the two seats and nobody has to.
# Same lab and images as cps.mk (cps-image), whose CPS_* variables for
# durations, detectors and the attack apply here too.

CPS_ADVISOR_OUT     ?=
# The policy that advises (rules | solver) and how long a suggestion waits.
CPS_ADVISOR_RESPOND ?= solver
CPS_ADVISOR_TIMEOUT ?= 120
# Long enough after the attack for a person to read a suggestion and answer it;
# PLAYGROUND=1 keeps the lab up for as long as it takes.
CPS_ADVISOR_POST    ?= 180
# Host ports of the consoles and shells: the SOC's for the blue team, the
# attacker's for the red team (cps-teams only).
CPS_BLUE_PORT       ?= 8766
CPS_BLUE_SHELL_PORT ?= 8767
CPS_RED_PORT        ?= 8768
CPS_RED_SHELL_PORT  ?= 8769
# A harness at a team's seat instead of a person: its name (claude-code |
# scripted) and the model it runs. cps-teams takes either seat's; cps-agents
# fills both. ENGAGEMENT_S is how long two harnesses play, at most; MAX_CALLS
# each one's budget of tool calls (empty: none).
RED_HARNESS         ?=
BLUE_HARNESS        ?=
RED_MODEL           ?=
BLUE_MODEL          ?=
ENGAGEMENT_S        ?= 900
MAX_CALLS           ?=
# Name servers of the players' nodes (empty: the scenario's default, public ones).
PLAYER_DNS          ?=
CPS_AGENTS_OUT      ?=
CPS_PLAYER_FLAGS := $(if $(RED_MODEL),--red-model $(RED_MODEL)) \
	$(if $(BLUE_MODEL),--blue-model $(BLUE_MODEL)) $(if $(MAX_CALLS),--max-calls $(MAX_CALLS)) \
	$(if $(PLAYER_DNS),--player-dns $(PLAYER_DNS))
CPS_ADVISOR_FLAGS := --respond $(CPS_ADVISOR_RESPOND) --approval operator:$(CPS_ADVISOR_TIMEOUT) \
	--blue-port $(CPS_BLUE_PORT) --blue-shell-port $(CPS_BLUE_SHELL_PORT)

cps-advisor-lab:           ## deploy the advisor lab, normal operation only (PLAYGROUND=1 to keep it up)
	$(PYTHON) -m $(M_CPS_ADVISOR_RUN) $(call run_dir,$(CPS_ADVISOR_OUT)) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_ADVISOR_FLAGS) $(CPS_IT_FLAG) $(PLAYGROUND_FLAG)

cps-advisor:               ## attack the advisor lab: the SOC suggests, you approve or reject at its console
	$(PYTHON) -m $(M_CPS_ADVISOR_RUN) $(call run_dir,$(CPS_ADVISOR_OUT)) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --post-attack-duration $(CPS_ADVISOR_POST) \
		--step-interval $(CPS_STEP) --attack --attack-mode $(CPS_ATTACK_MODE) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_ADVISOR_FLAGS) $(CPS_ATTACK_FLAGS) $(CPS_IT_FLAG) \
		$(PLAYGROUND_FLAG)

cps-advisor-dashboard:     ## the dashboard restricted to the advisor runs: suggestions and their answers
	$(PYTHON) -m $(M_DASHBOARD) --root $(OUTPUT_ROOT) --scenario cps-advisor --port $(CPS_DASH_PORT)

cps-teams:                 ## red team vs blue team on the advisor lab: stays up until Ctrl-C, links in teams.json
	$(PYTHON) -m $(M_CPS_ADVISOR_RUN) $(call run_dir,$(CPS_ADVISOR_OUT)) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		$(CPS_SEED_FLAG) $(CPS_ADVISOR_FLAGS) $(CPS_IT_FLAG) --teams --playground \
		--red-port $(CPS_RED_PORT) --red-shell-port $(CPS_RED_SHELL_PORT) \
		$(if $(RED_HARNESS),--red-harness $(RED_HARNESS)) \
		$(if $(BLUE_HARNESS),--blue-harness $(BLUE_HARNESS)) $(CPS_PLAYER_FLAGS)

# The benchmark (cps-bench): the harnesses under test, each <name>[:<model>],
# the seats they are tried at, the seeds, and optionally which of the scripted
# opponents (default: all three of the other side). BENCH_ENGAGEMENT_S is each
# game's length, BENCH_MAX_CALLS each harness's budget of tool calls.
BENCH               ?= $(shell date +%Y%m%d-%H%M)
BENCH_HARNESS       ?= claude-code
BENCH_SIDES         ?= red,blue
BENCH_SEEDS         ?= 1-3
BENCH_OPPONENTS     ?=
BENCH_ENGAGEMENT_S  ?= 300
BENCH_MAX_CALLS     ?= 60

cps-bench:                 ## benchmark harnesses: each one as red and blue vs graded scripted opponents, over seeds (DRY=1 lists the games)
	$(PYTHON) -m $(M_CPS_BENCH) --name $(BENCH) --harness $(BENCH_HARNESS) \
		--sides $(BENCH_SIDES) --seeds $(BENCH_SEEDS) \
		$(if $(BENCH_OPPONENTS),--opponents $(BENCH_OPPONENTS)) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		--respond $(CPS_ADVISOR_RESPOND) --approval operator:$(CPS_ADVISOR_TIMEOUT) \
		--engagement-s $(BENCH_ENGAGEMENT_S) --max-calls $(BENCH_MAX_CALLS) \
		$(if $(PLAYER_DNS),--player-dns $(PLAYER_DNS)) $(CPS_IT_FLAG) $(if $(DRY),--dry-run)

cps-players-image:         ## build the images of the players' nodes (the sandbox a harness plays from)
	docker build -t kathara/player docker/player/
	docker build -t kathara/player-claude docker/player-claude/

cps-agents:                ## harness vs harness on the advisor lab: plays ENGAGEMENT_S at most, then scores itself
	$(PYTHON) -m $(M_CPS_ADVISOR_RUN) $(call run_dir,$(CPS_AGENTS_OUT)) \
		--normal-duration $(CPS_NORMAL) --learn-seconds $(CPS_LEARN) \
		--detectors $(CPS_DETECTORS) --step-interval $(CPS_STEP) \
		$(CPS_SEED_FLAG) $(DASHBOARD_FLAG) $(CPS_ADVISOR_FLAGS) $(CPS_IT_FLAG) --teams \
		--red-port $(CPS_RED_PORT) --red-shell-port $(CPS_RED_SHELL_PORT) \
		--red-harness $(or $(RED_HARNESS),claude-code) \
		--blue-harness $(or $(BLUE_HARNESS),claude-code) \
		--engagement-s $(ENGAGEMENT_S) $(CPS_PLAYER_FLAGS) $(PLAYGROUND_FLAG)
