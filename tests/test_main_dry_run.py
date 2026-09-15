"""Regression test for main.py --dry-run.

Guards against a real bug found while writing main.py: network_scenario.slug's
experiment_slug() already returns the FULL directory name (prefix included,
e.g. "mtd-hop4-..."), but plot_results.py / compare_coordinators.py instead
want the bare hop/pool suffix and the prefix as two separate flags
(--mtd-params-slug / --mtd-prefix, --slug). Combining them the wrong way once
double-prefixed every directory name main.py computed (e.g. "mtd-mtd-hop4-...").

This test runs the real CLI as a subprocess (matching how a user invokes it)
and checks the printed directory names and flags against the actual on-disk
output/ layout the Makefile produces — so a reintroduced double-prefix, or a
slug/prefix drifting apart again, fails here instead of only showing up as a
silently-empty "reuse existing run" guard or a compare_coordinators.py that
can't find its inputs.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_DIRS = [
    "mtd-hop4-padint3-ips6-ports7-pads7-srcips6-mbps2-freqint5-freqs6",
    "mtdrl-hop4-padint3-ips6-ports7-pads7-srcips6-mbps2-freqint5-freqs6",
    "mtdrl-entropy-hop4-padint3-ips6-ports7-pads7-srcips6-mbps2-freqint5-freqs6",
]


class MainDryRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            [sys.executable, "main.py", "--dry-run"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        cls.returncode = result.returncode
        cls.stdout = result.stdout
        cls.stderr = result.stderr

    def test_exits_cleanly(self) -> None:
        self.assertEqual(self.returncode, 0, f"main.py --dry-run failed:\n{self.stderr}")

    def test_no_double_prefixed_directories(self) -> None:
        # A double-prefix bug produces "mtd-mtd-...", "mtdrl-mtdrl-...", etc.
        for bad in ("mtd-mtd-", "mtdrl-mtdrl-", "mtdrl-entropy-mtdrl-entropy-"):
            self.assertNotIn(bad, self.stdout, f"double-prefixed slug found: {bad!r}")

    def test_experiment_directories_match_expected(self) -> None:
        for expected in EXPECTED_DIRS:
            with self.subTest(dir=expected):
                self.assertIn(
                    f"output/{expected}", self.stdout,
                    f"expected experiment dir output/{expected} not found in dry-run output",
                )

    def test_plot_results_slug_has_no_prefix(self) -> None:
        # --mtd-params-slug must be the bare hop/pool suffix, never prefixed.
        for m in re.finditer(r"--mtd-params-slug (\S+)", self.stdout):
            slug = m.group(1)
            self.assertTrue(slug.startswith("hop"), f"--mtd-params-slug should start with 'hop', got {slug!r}")
            self.assertFalse(slug.startswith(("mtd-", "mtdrl-")), f"--mtd-params-slug is prefixed: {slug!r}")

    def test_compare_coordinators_slug_has_no_prefix(self) -> None:
        m = re.search(r"monitor\.compare_coordinators --slug (\S+)", self.stdout)
        self.assertIsNotNone(m, "monitor.compare_coordinators --slug not found in dry-run output")
        slug = m.group(1)
        self.assertTrue(slug.startswith("hop"))
        self.assertFalse(slug.startswith(("mtd-", "mtdrl-")))


if __name__ == "__main__":
    unittest.main()
