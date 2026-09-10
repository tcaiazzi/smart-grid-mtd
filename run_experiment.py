#!/usr/bin/env python3
"""Back-compat entrypoint. Real code: network_scenario/run_experiment.py.
Kept at repo root so Makefile / run_single.sh / run_sweep.sh keep working."""
from network_scenario.run_experiment import main

if __name__ == "__main__":
    main()
