#!/usr/bin/env python3
"""Back-compat entrypoint. Real code: attack_plane/classify.py.
Kept at repo root so Makefile / run_single.sh / run_sweep.sh keep working."""
from attack_plane.classify import main

if __name__ == "__main__":
    main()
