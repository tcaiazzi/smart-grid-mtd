"""The code-size accounting must stay true by construction, not by diligence.

`core/loc.py` produces the paper's "cost of a scenario" table from hardcoded
path globs (CORE, COMPONENTS) plus the SOURCES dict each scenario declares. A
stale glob does not fail: `glob.glob` returns an empty list, the file silently
stops being counted, and the table reports that a scenario costs less than it
does. That is the one defect here that is invisible in the repo and wrong in
print.

Two assertions:

* every declared pattern must still match at least one file — a pattern that
  matches nothing is a path that moved;
* every source file in the measured tree must be counted by *someone* — a file
  that belongs to no pattern is a file the table forgot.

Plus a snapshot of the four headline totals, so a move between categories is
free but a move out of the accounting is not.

Run: `.venv/bin/python -m pytest tests/test_loc_coverage.py`
Update the totals on purpose: `UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/test_loc_coverage.py`
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.core import loc, registry            # noqa: E402

from tests.helpers import SNAPSHOT_DIR  # noqa: E402

SNAPSHOT = SNAPSHOT_DIR / "loc-totals.json"
UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"

# Directories that are not part of the platform/scenario accounting at all.
OUT_OF_SCOPE = ("tests", "docker", "assets", "docs", "make", "scripts", "tools",
                "output", ".venv", ".git", "__pycache__")

# Source files deliberately counted by nobody. Keep this list short and
# justified: every entry is a file the paper's table does not see.
EXEMPT = {
    # A cross-scenario illustration, not part of either scenario's cost.
    "tools/plot_architecture.py",
    "tools/plot_architecture.py",
}


def tracked_sources():
    """Repo .py/.js/.html files inside the measured tree, per git."""
    out = subprocess.run(["git", "ls-files", "*.py", "*.js", "*.html"],
                         cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    files = []
    for rel in out.stdout.split():
        parts = Path(rel).parts
        if parts[0] in OUT_OF_SCOPE or rel == "main.py":
            continue
        if Path(rel).name == "__init__.py":      # package markers carry no cost
            continue
        files.append(rel)
    return sorted(files)


def declared_patterns():
    """{where: [patterns]} over CORE, COMPONENTS and every scenario's SOURCES."""
    import importlib
    patterns = {}
    for label, pats in loc.CORE.items():
        patterns[f"CORE[{label}]"] = pats
    for label, pats in loc.COMPONENTS.items():
        patterns[f"COMPONENTS[{label}]"] = pats
    for name in registry.names():
        module = registry.SCENARIOS[name].split(":")[0].rsplit(".", 1)[0]
        pkg = importlib.import_module(module)
        for label, pats in getattr(pkg, "SOURCES", {}).items():
            patterns[f"{name}.SOURCES[{label}]"] = pats
    return patterns


class PatternsStillMatch(unittest.TestCase):
    def test_no_pattern_matches_nothing(self):
        for where, pats in sorted(declared_patterns().items()):
            for pattern in pats:
                with self.subTest(where=where, pattern=pattern):
                    self.assertTrue(
                        loc.expand([pattern]),
                        f"{where} declares {pattern!r}, which matches no file. The code it "
                        f"was counting is now counted by nobody, and the paper's table "
                        f"silently understates it.")


class CategoriesAreDisjoint(unittest.TestCase):
    """loc sums each category independently, so a file matched by two patterns of
    the same scenario is added twice and the scenario looks more expensive than
    it is. Nothing in loc prevents it; this does."""

    def test_no_file_counted_twice_in_the_platform(self):
        """Same trap on the platform side: CORE's glob and an explicit entry can
        cover the same file, inflating the platform total."""
        seen = {}
        for group, categories in (("CORE", loc.CORE), ("COMPONENTS", loc.COMPONENTS)):
            for category, patterns in categories.items():
                for f in loc.expand(patterns):
                    if f in seen:
                        with self.subTest(file=f):
                            self.fail(
                                f"{f} is matched by both {seen[f]!r} and "
                                f"{group}[{category!r}], so its lines are counted twice.")
                    seen[f] = f"{group}[{category!r}]"

    def test_no_file_counted_twice_within_a_scenario(self):
        for name in registry.names():
            seen = {}
            for category, files in loc.scenario_files(name).items():
                for f in files:
                    if f in seen:
                        with self.subTest(scenario=name, file=f):
                            self.fail(
                                f"{f} is matched by both {seen[f]!r} and {category!r} in the "
                                f"{name} scenario, so its lines are counted twice. Keep the "
                                f"SOURCES categories disjoint (one directory each).")
                    seen[f] = category


class EveryFileIsCounted(unittest.TestCase):
    def test_no_source_file_is_invisible(self):
        counted = set(loc.report()["files"])
        missing = [f for f in tracked_sources() if f not in counted and f not in EXEMPT]
        self.assertEqual(
            [], missing,
            f"these source files are counted by no pattern: {missing}. Either add them to a "
            f"scenario's SOURCES / loc.CORE, or list them in EXEMPT with a reason.")


class TotalsAreStable(unittest.TestCase):
    """Moving a file between categories is free; moving it out of the table is not."""

    def test_headline_totals(self):
        r = loc.report()
        totals = {
            "platform": sum(r["core"].values()) + sum(r["components"].values()),
            "shared": r["shared"]["sloc"],
            **{name: sum(cats.values()) for name, cats in r["scenarios"].items()},
        }
        if UPDATE:
            SNAPSHOT.parent.mkdir(exist_ok=True)
            SNAPSHOT.write_text(json.dumps(totals, indent=1, sort_keys=True) + "\n")
            return
        self.assertTrue(SNAPSHOT.exists(), f"missing {SNAPSHOT}; regenerate with UPDATE_SNAPSHOTS=1")
        self.assertEqual(
            json.loads(SNAPSHOT.read_text()), totals,
            "the code-size totals changed. A refactor that only moves files must leave them "
            "identical; if code was genuinely added or removed, update the snapshot on purpose.")


if __name__ == "__main__":
    unittest.main()
