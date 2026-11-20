"""The command record of the teams' shells (nodes/common/command_audit.sh): a
real interactive bash, on a pseudo-terminal, with the hook loaded — what is
typed must come out as one JSON line per command. No Docker.

Run: `.venv/bin/python -m pytest tests/nodes/test_command_audit.py`.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from tests.helpers import guest_paths

HOOK = guest_paths.NODES / "common" / "command_audit.sh"
ACCESS = guest_paths.NODES / "common" / "team-access.sh"


@unittest.skipIf(
    shutil.which("script") is None or shutil.which("bash") is None,
    "bash and script(1) are needed to open an interactive shell",
)
class Audit(unittest.TestCase):
    def typed(self, *lines):
        """Type ``lines`` into an interactive bash; returns the recorded rows."""
        log = os.path.join(tempfile.mkdtemp(prefix="audit-"), "commands.jsonl")
        subprocess.run(
            ["script", "-qec", f"bash --rcfile {HOOK} -i", "/dev/null"],
            input="\n".join(lines) + "\nexit\n",
            env={**os.environ, "AUDIT_LOG": log, "SSH_CONNECTION": "10.30.0.20 5 10.30.0.1 22"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        with open(log) as f:
            return [json.loads(line) for line in f]  # every line must be valid JSON

    def test_every_command_is_recorded_when_it_starts_and_when_it_ends(self):
        rows = self.typed("true", "false")
        started = [r for r in rows if r["kind"] == "command"]
        self.assertEqual([r["cmd"] for r in started], ["true", "false", "exit"])
        ended = {r["cmd"]: r["rc"] for r in rows if r["kind"] == "command_end"}
        self.assertEqual(ended, {"true": 0, "false": 1})
        self.assertEqual(started[0]["from"], "10.30.0.20", "where an SSH session came from is lost")

    def test_where_the_shell_came_from_is_recorded_without_its_secrets(self):
        row = self.typed("true")[0]
        self.assertTrue(
            any(a.startswith("script ") for a in row["ancestry"]),
            f"the process the shell was started by is not among its ancestors: {row['ancestry']}",
        )
        self.assertFalse(
            any("--rcfile" in a for a in row["ancestry"]),
            "an ancestor's later arguments are recorded: a token passed there would leak",
        )
        self.assertIsInstance(row["orphan"], bool)

    def test_an_empty_line_is_not_a_command(self):
        self.assertEqual(
            [r["cmd"] for r in self.typed("", "true", "") if r["kind"] == "command"],
            ["true", "exit"],
        )

    def test_what_is_typed_survives_as_json(self):
        nasty = 'echo "a \\"quoted\\" \\\\ back" | cat'
        rows = [r for r in self.typed(nasty) if r["kind"] == "command"]
        self.assertEqual(rows[0]["cmd"], nasty)


class Access(unittest.TestCase):
    def test_the_script_parses_and_refuses_what_it_does_not_know(self):
        self.assertEqual(subprocess.run(["bash", "-n", str(ACCESS)]).returncode, 0)
        done = subprocess.run(["bash", str(ACCESS), "nonsense"], capture_output=True, text=True)
        self.assertEqual(done.returncode, 2)
        self.assertIn("usage", done.stderr)


if __name__ == "__main__":
    unittest.main()
