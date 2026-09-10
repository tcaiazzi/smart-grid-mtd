#!/usr/bin/env python3
"""Back-compat entrypoint. Real code: defense_plane/plot_tradeoff.py.
Kept at repo root so Makefile / run_single.sh / run_sweep.sh keep working."""
from defense_plane.plot_tradeoff import main

if __name__ == "__main__":
    main()
