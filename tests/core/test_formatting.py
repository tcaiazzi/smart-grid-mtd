"""Formatting and lint as part of the suite, not as a habit.

`make fmt` and `make lint` only help the person who remembers to run them. This
makes the repo's own rules a test: the diff a reviewer reads is then about the
change, never about where someone put a bracket.

What it enforces lives in pyproject.toml ([tool.ruff]): 100 columns, double
quotes, pycodestyle errors, pyflakes and warnings. Import order (I) is
deliberately not enforced — local imports here are grouped by meaning, core
before planes before scenarios, which alphabetising would destroy.

Run: `.venv/bin/python -m pytest tests/core/test_formatting.py`
Fix:  `make fmt` (reformats) then `make lint` (reports what is left).
"""

import subprocess
import sys
import unittest

from tests.helpers import REPO_ROOT

RUFF = [sys.executable, "-m", "ruff"]


def run(*args):
    return subprocess.run(RUFF + list(args), cwd=REPO_ROOT, capture_output=True, text=True)


class RepoIsFormatted(unittest.TestCase):
    def test_every_file_is_formatted(self):
        result = run("format", "--check", ".")
        self.assertEqual(
            0,
            result.returncode,
            "these files are not formatted:\n"
            f"{result.stdout.strip()}\n"
            "Run `make fmt`. It rewrites nothing but layout.",
        )


class RepoPassesLint(unittest.TestCase):
    def test_no_lint_findings(self):
        result = run("check", ".", "--output-format", "concise")
        self.assertEqual(
            0,
            result.returncode,
            "lint findings:\n"
            f"{result.stdout.strip()}\n"
            "Unused imports and dead variables should go. An import that must stay out of "
            "order (a backend set before it is imported, a path fixed before a flat guest "
            "import) takes a `# noqa: <code>` with the reason in the same line.",
        )


if __name__ == "__main__":
    unittest.main()
