"""The red team's console (nodes/redteam/red_console.py): the bench that runs
the attack's steps and keeps what came of them, and the HTTP server a browser
drives it through — a real server on a free port, with a fake in place of the
shell. No Docker.

Run: `.venv/bin/python -m pytest tests/nodes/test_red_console.py`.
"""

import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request

from tests.helpers import guest_paths

guest_paths.add(guest_paths.REDTEAM)

import red_console as R  # noqa: E402  (flat guest import, needs the path set above)

TOKEN = "r3d"
STEPS = [
    {"id": "it_access", "label": "Exploit the web app", "stage": "it_access", "needs": []},
    {"id": "pivot", "label": "Reach the plant", "stage": "pivot", "needs": ["it_access"]},
    {"id": "breaker_open", "label": "Open the breaker", "stage": "impact", "needs": ["pivot"]},
]
for _s in STEPS:
    _s["command"] = f"run {_s['id']}"


class FakeShell:
    """Answers each step's command with canned output, as exploit_client prints it."""

    def __init__(self):
        self.ran = []
        self.fail = set()

    def __call__(self, cmd):
        self.ran.append(cmd)
        step = cmd.split()[-1]
        ok = step not in self.fail
        stage = {s["id"]: s["stage"] for s in STEPS}[step]
        lines = [f"[*] {step}"]
        if stage == "impact":
            write = {"t": 5.0, "phase": "modbus_write", "register": 1, "value": 1.0, "ok": ok}
            lines.append(json.dumps(write))
        lines.append(json.dumps({"t": 5.1, "phase": stage, "ok": ok}))
        return (0 if ok else 1), "\n".join(lines) + "\n"


class TheBench(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="red-")
        self.record = os.path.join(self.dir, "red_actions.jsonl")
        self.shell = FakeShell()
        self.bench = R.Bench(STEPS, self.record, run=self.shell, clock=lambda: 100.0)

    def test_a_step_runs_its_command_and_is_put_on_record(self):
        row = self.bench.launch("breaker_open", "eve")
        self.assertEqual(self.shell.ran, ["run breaker_open"])
        self.assertTrue(row["ok"])
        self.assertEqual([p["phase"] for p in row["phases"]], ["modbus_write", "impact"])
        with open(self.record) as f:
            on_file = [json.loads(line) for line in f]
        self.assertEqual(
            [(r["kind"], r["step"], r["operator"]) for r in on_file],
            [("red_step", "breaker_open", "eve")],
            "the range reads this file to know what the red team did",
        )

    def test_a_step_that_says_it_failed_has_failed(self):
        self.shell.fail.add("pivot")
        self.assertFalse(self.bench.launch("pivot")["ok"])

    def test_only_the_steps_it_was_given(self):
        self.assertIsNone(self.bench.launch("rm -rf /"))
        self.assertEqual(self.shell.ran, [], "the console ran something that is not a step")

    def test_readiness_follows_what_succeeded(self):
        ready = lambda: {s["id"]: s["ready"] for s in self.bench.state()["steps"]}  # noqa: E731
        self.assertEqual(ready(), {"it_access": True, "pivot": False, "breaker_open": False})
        self.bench.launch("it_access")
        self.assertTrue(ready()["pivot"])
        self.shell.fail.add("pivot")
        self.bench.launch("pivot")
        self.assertFalse(ready()["breaker_open"], "a failed prerequisite opened the next step")


class TheConsole(unittest.TestCase):
    def setUp(self):
        self.shell = FakeShell()
        self.console = R.RedConsole(
            R.Bench(STEPS, run=self.shell), TOKEN, host="127.0.0.1", terminal="http://t/"
        ).start()
        self.addCleanup(self.console.shutdown)

    def call(self, method, path, token=TOKEN, body=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.console.port}{path}", data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_the_page_is_served_but_holds_nothing(self):
        status, page = self.call("GET", "/", token=None)
        self.assertEqual(status, 200)
        self.assertIn(b"Red team console", page)
        self.assertNotIn(TOKEN.encode(), page)

    def test_no_token_no_attack(self):
        for token in (None, "blue-team-token"):
            self.assertEqual(self.call("GET", "/state", token=token)[0], 401)
            self.assertEqual(self.call("POST", "/steps/it_access", token=token)[0], 401)
        self.assertEqual(self.shell.ran, [], "a step ran for a caller without the red team's token")

    def test_a_step_is_run_from_the_console(self):
        status, body = self.call("POST", "/steps/it_access", body={"operator": "eve"})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        status, body = self.call("GET", "/state")
        state = json.loads(body)
        self.assertEqual(state["terminal"], "http://t/")
        self.assertEqual([r["operator"] for r in state["history"]], ["eve"])
        self.assertEqual(self.call("POST", "/steps/nope")[0], 404)
        self.assertEqual(self.call("POST", "/elsewhere/it_access")[0], 404)

    def test_a_console_without_a_token_is_refused(self):
        with self.assertRaises(ValueError):
            R.RedConsole(R.Bench(STEPS), "", host="127.0.0.1")


if __name__ == "__main__":
    unittest.main()
