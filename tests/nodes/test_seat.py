"""A team's seat (nodes/common/seat.py): what a console serves a player that is
not a browser, and the shell it runs for it — real commands in a real bash, the
node's command record a file in a scratch directory. No Docker.

Run: `.venv/bin/python -m pytest tests/nodes/test_seat.py`.
"""

import json
import os
import tempfile
import time
import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.COMMON)

import seat as S  # noqa: E402  (flat guest import, needs the path set above)


class TheSeat(unittest.TestCase):
    def setUp(self):
        self.log = os.path.join(tempfile.mkdtemp(prefix="seat-"), "commands.jsonl")
        self.seat = S.Seat(
            "red", ["run_step"], knowledge="tree", briefing="# Red", audit_log=self.log
        )

    def rows(self):
        with open(self.log) as f:
            return [json.loads(line) for line in f]

    def test_it_says_what_a_client_must_know_to_sit_down(self):
        doc = self.seat.describe()
        self.assertEqual(doc["version"], S.VERSION, "a client checks this before anything else")
        self.assertEqual((doc["team"], doc["knowledge"]), ("red", "tree"))
        self.assertEqual(doc["actions"], ["run_step", "shell"])

    def test_a_command_runs_from_the_root_and_starts_afresh(self):
        self.assertEqual(self.seat.shell("cd /tmp && pwd")["stdout"], "/tmp\n")
        out = self.seat.shell("pwd; echo oops >&2; exit 3")
        self.assertEqual(
            (out["rc"], out["stdout"], out["stderr"]),
            (3, "/\n", "oops\n"),
            "a command inherited the directory of the one before it",
        )

    def test_a_command_is_on_the_nodes_record_as_the_teams(self):
        self.seat.shell("true", operator="agent:scripted", note="looking around")
        start, end = self.rows()
        self.assertEqual((start["kind"], end["kind"]), ("command", "command_end"))
        self.assertEqual(
            (start["seat"], start["cmd"], start["operator"], start["note"]),
            ("red", "true", "agent:scripted", "looking around"),
            "the range attributes a command to the team by this mark",
        )
        self.assertEqual(end["rc"], 0)
        for field in ("t", "host", "cwd", "from", "ancestry", "orphan"):
            self.assertIn(field, start, "the range reads command_audit.sh's fields from this row")

    def test_a_command_that_hangs_is_cut_with_what_it_started(self):
        seat = S.Seat("red", [], audit_log=self.log, run=lambda cmd: S.run_bash(cmd, timeout=0.5))
        began = time.monotonic()
        out = seat.shell("sleep 30 & sleep 30")
        self.assertLess(
            time.monotonic() - began,
            5,
            "the answer waited for a process the command left in the background",
        )
        self.assertEqual(out["rc"], -1)
        self.assertIn("timed out", out["stderr"])

    def test_long_output_is_cut_and_says_so(self):
        out = self.seat.shell(f"head -c {S.OUTPUT_MAX * 2} /dev/zero | tr '\\0' x")
        self.assertEqual(len(out["stdout"]), S.OUTPUT_MAX)
        self.assertTrue(out["truncated"], "a player would take a cut output for the whole of it")

    def test_a_node_without_the_record_still_runs_the_command(self):
        seat = S.Seat("red", [], audit_log="/nonexistent/dir/commands.jsonl")
        self.assertEqual(seat.shell("echo hi")["stdout"], "hi\n")

    def test_a_note_is_cut_short(self):
        self.assertEqual(len(S.note_of({"note": "x" * 9999})), S.NOTE_MAX)
        self.assertIsNone(S.note_of({"note": ""}))
        self.assertIsNone(S.note_of({}))


if __name__ == "__main__":
    unittest.main()
