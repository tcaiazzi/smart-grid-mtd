"""Shared test fixtures and lookups — everything the tests need that is not a test.

``REPO_ROOT`` is resolved here, once, by walking up to the marker, rather than
counted in level-ups from each test file: tests live in subdirectories now, and
``Path(__file__).parents[N]`` is the kind of thing that keeps pointing
somewhere plausible after a move instead of failing.
"""

from pathlib import Path

MARKERS = ("pyproject.toml", "Makefile", ".git")


def _find_repo_root(start):
    here = Path(start).resolve()
    for candidate in (here, *here.parents):
        if candidate.is_dir() and any((candidate / m).exists() for m in MARKERS):
            return candidate
    raise RuntimeError(f"no repo root above {here}")


REPO_ROOT = _find_repo_root(__file__)
SNAPSHOT_DIR = REPO_ROOT / "tests" / "snapshots"
