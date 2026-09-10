#!/usr/bin/env python3
"""Back-compat entrypoint. Real code: monitor/plot_architecture.py.
Kept at repo root so it keeps working when invoked directly. plot_architecture.py
runs entirely at module scope (no main()), so importing it reproduces the exact
behavior of running it directly."""
import monitor.plot_architecture  # noqa: F401  (executes the figure generation)
