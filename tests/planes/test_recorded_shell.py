"""Whose shell a recorded command came from (monitor.RecordedShell): the team
is read from how the shell got onto the node, so that a referee's own shell is
never scored as the attack and an attacker's is never taken for the defenders'.

Run: `.venv/bin/python -m pytest tests/planes/test_recorded_shell.py`.
"""

import unittest

from cyberrange.planes.monitor.components import RecordedShell

SOC, HMI = "10.30.0.20", "10.30.0.30"


def row(src="", ancestry=(), orphan=False):
    return {
        "kind": "command",
        "cmd": "id",
        "from": src,
        "ancestry": list(ancestry),
        "orphan": orphan,
    }


class Whose(unittest.TestCase):
    def setUp(self):
        self.defended = RecordedShell("hmi", "blue", intruder="red", jump=SOC, entry="vuln_app.py")

    def test_the_defenders_come_in_from_their_jump_host(self):
        self.assertEqual(self.defended.whose(row(SOC, ["sshd: root@pts/0"])), "blue")

    def test_ssh_from_anywhere_else_is_the_intruder(self):
        self.assertEqual(
            self.defended.whose(row(HMI, ["sshd: root@pts/0"])),
            "red",
            "SSH from a host the attacker took was counted as the defenders'",
        )

    def test_a_shell_got_through_the_entry_service_is_the_intruder(self):
        got = self.defended.whose(row(ancestry=["sh -c", "python3 vuln_app.py", "sh -c"]))
        self.assertEqual(got, "red")

    def test_a_shell_a_service_left_behind_is_the_intruder(self):
        self.assertEqual(self.defended.whose(row(ancestry=["sleep 60"], orphan=True)), "red")

    def test_the_referee_is_neither_team(self):
        self.assertEqual(
            self.defended.whose(row(ancestry=["bash"])),
            RecordedShell.CONTROL,
            "a shell opened from outside the lab was scored as the attack",
        )

    def test_a_teams_own_node_knows_its_terminal_from_the_referee(self):
        own = RecordedShell("attacker", "red", witnessed=True)
        terminal = ["script -qaf", "/usr/local/bin/ttyd -p"]
        self.assertEqual(own.whose(row(ancestry=terminal)), "red")
        self.assertEqual(own.whose(row(ancestry=["bash"])), RecordedShell.CONTROL)


class GroundTruth(unittest.TestCase):
    """Only what a team did is the attack's record."""

    class Ctx:
        def __init__(self, rows):
            self.rows, self.events, self.truth = rows, [], []
            self.gt = self

        def exec_text(self, node, cmd):
            import json

            out, self.rows = self.rows, []
            return "".join(json.dumps(r) + "\n" for r in out)

        def emit(self, kind, **fields):
            self.events.append(fields)

        def record(self, kind, **fields):
            self.truth.append(fields)

    def polled(self, shell, *rows):
        ctx = self.Ctx(list(rows))
        shell.poll(ctx)
        return ctx

    def test_the_referee_is_on_the_ledger_and_not_in_the_ground_truth(self):
        shell = RecordedShell("hmi", "blue", intruder="red", jump=SOC, entry="vuln_app.py")
        ctx = self.polled(shell, row(ancestry=["bash"]), row(ancestry=["python3 vuln_app.py"]))
        self.assertEqual([e["team"] for e in ctx.events], ["control", "red"])
        self.assertEqual([t["team"] for t in ctx.truth], ["red"])

    def test_a_witnessed_team_is_not_witnessed_for_the_referee(self):
        shell = RecordedShell("attacker", "red", witnessed=True)
        ctx = self.polled(shell, row(ancestry=["bash"]), row(ancestry=["ttyd -p"]))
        self.assertEqual([t["team"] for t in ctx.truth], ["red"])


if __name__ == "__main__":
    unittest.main()
