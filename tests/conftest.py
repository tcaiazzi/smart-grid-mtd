"""Shared pytest configuration.

Two jobs, both aimed at a failure mode plain test runs do not have:

1. **A floor on how many tests exist.** The old `make selftest` derived module
   names from a non-recursive `$(wildcard tests/test_*.py)`: moving a test into
   a subdirectory dropped it from the suite *without a single red test*. A
   runner that silently runs less is worse than one that fails, so a full run
   that collects fewer than MIN_TESTS is an error.

2. **The `slow` marker**, applied by module name rather than by editing eight
   test files, so `make selftest-fast` can deselect the heavy ones (torch,
   pandapower, matplotlib, subprocesses, sleeps).
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"

# Also needed when a test module is run directly (`python -m unittest tests.x`),
# where pytest's own `pythonpath` ini setting does not apply.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Raise this deliberately whenever the suite genuinely grows (261 before the
# guardrail tests of the structure refactor were added).
MIN_TESTS = 278

SLOW_MODULES = {
    "test_active_attack",       # spawns modbus_engine, sleeps
    "test_delivery_detector",   # dpkt + pandas + sklearn
    "test_grid_sim",            # pandapower
    "test_guest_imports",       # one subprocess per guest module
    "test_main_dry_run",        # subprocesses + `make -n`
    "test_modbus_roundtrip",    # spawns the engine
    "test_seeding",             # pymgrid, torch
    "test_telemetry",           # matplotlib + sklearn, sockets
}


def pytest_collection_modifyitems(items):
    for item in items:
        if Path(str(item.fspath)).stem in SLOW_MODULES:
            item.add_marker(pytest.mark.slow)


def _is_full_run(config):
    """True when this run is meant to be the whole suite (no -k/-m, no path)."""
    if config.option.keyword or config.option.markexpr:
        return False
    targets = [Path(a.split("::")[0]).resolve() for a in config.args]
    return all(t == TESTS_DIR for t in targets) if targets else True


def pytest_collection_finish(session):
    if not _is_full_run(session.config):
        return
    n = len(session.items)
    if n < MIN_TESTS:
        raise pytest.UsageError(
            f"collected {n} tests, fewer than the floor of {MIN_TESTS}. Tests went "
            f"missing rather than failing — check for a test directory that is no "
            f"longer collected. Lower MIN_TESTS in tests/conftest.py only on purpose."
        )
