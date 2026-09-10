#!/usr/bin/env python3
"""Back-compat entrypoint. Real code: defense_plane/train_rl_coordinator.py.
Kept at repo root so Makefile / run_single.sh / run_sweep.sh keep working."""
from defense_plane.train_rl_coordinator import main

if __name__ == "__main__":
    main()
