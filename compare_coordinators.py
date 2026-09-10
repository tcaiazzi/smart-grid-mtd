#!/usr/bin/env python3
"""Back-compat entrypoint. Real code: monitor/compare_coordinators.py.
Kept at repo root so Makefile / run_single.sh / run_sweep.sh keep working."""
from monitor.compare_coordinators import main

if __name__ == "__main__":
    main()
