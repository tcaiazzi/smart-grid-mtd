#!/usr/bin/env python3
"""Back-compat entrypoint. Real code: traffic_generator/split_trace.py.
Kept at repo root so Makefile / run_single.sh / run_sweep.sh keep working."""
from traffic_generator.split_trace import main

if __name__ == "__main__":
    main()
