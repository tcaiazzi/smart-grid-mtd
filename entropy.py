#!/usr/bin/env python3
"""Back-compat entrypoint. Real code: monitor/entropy.py.
Kept at repo root so Makefile / run_single.sh / run_sweep.sh keep working."""
from monitor.entropy import main

if __name__ == "__main__":
    main()
