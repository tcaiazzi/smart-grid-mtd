"""The red team's console (nodes/redteam/red_console.py): the bench that runs
the attack's steps and keeps what came of them, and the HTTP server a browser
drives it through — a real server on a free port, with a fake in place of the
shell. No Docker.

Run: `.venv/bin/python -m pytest tests/nodes/test_red_console.py`.
"""

import json
import os
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from tests.helpers import guest_paths

# The console of a team that reconnoitres derives its tree with the generator:
# ATTACK_AGENTS and DEFENSE supply what that imports (the steps' client, the
# register map).
guest_paths.add(
    guest_paths.REDTEAM, guest_paths.COMMON, guest_paths.ATTACK_AGENTS, guest_paths.DEFENSE
)

import belief_tree  # noqa: E402  (flat guest import, needs the path set above)
import red_console as R  # noqa: E402  (flat guest import, needs the path set above)
import seat  # noqa: E402  (flat guest import, needs the path set above)

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

    def test_the_reason_given_for_a_step_is_kept_with_it(self):
        self.assertEqual(
            self.bench.launch("pivot", "agent:x", "the web app gave a shell")["note"],
            "the web app gave a shell",
        )
        self.assertNotIn(
            "note", self.bench.launch("pivot"), "a step nobody explained gained an empty reason"
        )

    def test_readiness_follows_what_succeeded(self):
        ready = lambda: {s["id"]: s["ready"] for s in self.bench.state()["steps"]}  # noqa: E731
        self.assertEqual(ready(), {"it_access": True, "pivot": False, "breaker_open": False})
        self.bench.launch("it_access")
        self.assertTrue(ready()["pivot"])
        self.shell.fail.add("pivot")
        self.bench.launch("pivot")
        self.assertFalse(ready()["breaker_open"], "a failed prerequisite opened the next step")

    def test_each_step_says_where_it_stands(self):
        outcome = lambda: {s["id"]: s["outcome"] for s in self.bench.state()["steps"]}  # noqa: E731
        self.assertEqual(
            outcome(), {"it_access": "ready", "pivot": "waiting", "breaker_open": "waiting"}
        )
        self.bench.launch("it_access")
        self.shell.fail.add("pivot")
        self.bench.launch("pivot")
        self.assertEqual(
            outcome(), {"it_access": "done", "pivot": "failed", "breaker_open": "waiting"}
        )


class TheShell(unittest.TestCase):
    """What the console runs a step with — a real shell, here."""

    def test_a_step_cut_at_the_timeout_keeps_what_it_did_until_then(self):
        rc, out = R.run_shell('echo \'{"phase": "modbus_write", "ok": true}\'; sleep 30', 0.5)
        self.assertEqual(rc, -1)
        self.assertEqual(
            R.phases_of(out),
            [{"phase": "modbus_write", "ok": True}],
            "the writes the plant took before the step was cut are on no record",
        )
        self.assertIn("timed out", out)

    def test_a_step_cut_at_the_timeout_leaves_nothing_running(self):
        mark = os.path.join(tempfile.mkdtemp(prefix="red-"), "still-writing")
        R.run_shell(f"(sleep 1; touch {mark}) & sleep 30", 0.3)
        time.sleep(1.5)
        self.assertFalse(
            os.path.exists(mark),
            "a step the console called over went on acting on the plant in the background",
        )


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

    def test_the_state_does_not_carry_the_terminals_secret(self):
        console = R.RedConsole(
            R.Bench(STEPS, run=self.shell),
            TOKEN,
            host="127.0.0.1",
            terminal=f"http://red:{TOKEN}@127.0.0.1:8769/",
        ).start()
        self.addCleanup(console.shutdown)
        self.console = console
        _status, body = self.call("GET", "/state")
        self.assertNotIn(
            TOKEN.encode(),
            body,
            "whoever reads the console's state is handed the team's token in a link: a harness "
            "gets it in a tool result, and its log is kept with the run",
        )
        state = json.loads(body)
        self.assertEqual(
            (state["terminal"], state["terminal_user"]), ("http://127.0.0.1:8769/", "red")
        )

    def test_a_console_without_a_token_is_refused(self):
        with self.assertRaises(ValueError):
            R.RedConsole(R.Bench(STEPS), "", host="127.0.0.1")


class TheSeatAtTheConsole(TheConsole):
    """A player that is not a browser sits at the same console, behind the same
    token: a seat reachable without it, or a shell that queues behind a running
    step, would make an agent a different kind of player from a person."""

    def setUp(self):
        self.shell = FakeShell()
        self.typed = []

        def run(cmd):
            self.typed.append(cmd)
            return 0, "out", ""

        place = seat.Seat("red", R.ACTIONS, "tree", "# Red team", audit_log=os.devnull, run=run)
        self.console = R.RedConsole(
            R.Bench(STEPS, run=self.shell),
            TOKEN,
            host="127.0.0.1",
            terminal="http://t/",
            seat=place,
        ).start()
        self.addCleanup(self.console.shutdown)

    def test_the_seat_and_the_briefing_are_served_to_the_team_only(self):
        for path in ("/seat", "/briefing"):
            self.assertEqual(self.call("GET", path, token=None)[0], 401)
        doc = json.loads(self.call("GET", "/seat")[1])
        self.assertEqual((doc["team"], doc["actions"]), ("red", ["run_step", "shell"]))
        self.assertEqual(json.loads(self.call("GET", "/briefing")[1]), {"briefing": "# Red team"})

    def test_a_command_is_run_for_the_team_only(self):
        self.assertEqual(self.call("POST", "/shell", token=None, body={"cmd": "id"})[0], 401)
        self.assertEqual(self.call("POST", "/shell", body={"operator": "eve"})[0], 400)
        self.assertEqual(self.typed, [], "a command ran for a caller it should have refused")
        status, body = self.call("POST", "/shell", body={"cmd": "id", "operator": "agent:x"})
        self.assertEqual((status, json.loads(body)["stdout"]), (200, "out"))
        self.assertEqual(self.typed, ["id"])

    def test_a_note_given_at_the_console_reaches_the_record(self):
        body = {"operator": "agent:x", "note": "first way in"}
        self.assertEqual(
            json.loads(self.call("POST", "/steps/it_access", body=body)[1])["note"], "first way in"
        )


class AConsoleNobodyGaveASeat(TheConsole):
    def test_it_serves_no_seat(self):
        for method, path in (("GET", "/seat"), ("GET", "/briefing"), ("POST", "/shell")):
            self.assertEqual(
                self.call(method, path, body={"cmd": "id"} if method == "POST" else None)[0], 404
            )


if __name__ == "__main__":
    unittest.main()


class ATeamThatFindsItsOwnTree(TheConsole):
    """--knowledge recon: no tree is given; the steps come from what the team
    reports, through the real generator."""

    HMI = {"foothold_ip": "10.10.0.20", "foothold_port": 8080}
    ENGINE = {"engine_ip": "10.20.0.10", "engine_port": 502}

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="recon-")
        self.record = os.path.join(self.dir, "red_actions.jsonl")
        self.belief = os.path.join(self.dir, "belief_tree.json")
        self.ran = []
        self.shell = self  # the inherited tests ask the shell what ran

        def run(cmd):
            self.ran.append(cmd)
            return 0, json.dumps({"phase": cmd.split()[-1], "ok": True})

        bench = R.Bench([], self.record, run=run)
        self.recon = R.Recon(bench, belief_tree.build, belief_path=self.belief)
        place = seat.Seat("red", (*R.ACTIONS, R.REPORT), "recon", "# Red", audit_log=os.devnull)
        self.console = R.RedConsole(
            bench, TOKEN, host="127.0.0.1", seat=place, recon=self.recon
        ).start()
        self.addCleanup(self.console.shutdown)

    def report(self, **found):
        code, body = self.call("POST", "/findings", body=found)
        return code, json.loads(body)

    def listed(self):
        return [s["id"] for s in json.loads(self.call("GET", "/state")[1])["steps"]]

    def rows(self, kind):
        with open(self.record) as f:
            return [r for r in map(json.loads, f) if r["kind"] == kind]

    # The inherited tests are of a console that was given its steps.
    test_a_step_is_run_from_the_console = None
    test_the_state_does_not_carry_the_terminals_secret = None

    def test_nothing_is_listed_before_anything_is_found(self):
        self.assertEqual(
            self.listed(), [], "a step was listed for a team that has found nothing yet"
        )
        self.assertEqual(json.loads(self.call("GET", "/seat")[1])["knowledge"], "recon")

    def test_each_finding_lists_the_steps_it_makes_possible(self):
        code, said = self.report(**self.HMI)
        self.assertEqual((code, said["new"]), (200, ["it_access", "it_exec"]))
        _code, said = self.report(**self.ENGINE)
        self.assertEqual(said["new"], ["pivot"], "the engine alone gave a step that writes to it")
        _code, said = self.report(registers="1")
        self.assertEqual(sorted(said["new"]), ["breaker_chatter", "breaker_open"])
        self.assertNotIn("setpoint_oor", self.listed(), "a register never read gave its step")
        _code, said = self.report(workstation_ip="10.20.0.30")
        self.assertEqual(said["new"], ["ot_foothold", "ot_aitm", "meas_fdi"])

    def test_a_step_is_aimed_at_what_was_reported_and_at_nothing_else(self):
        self.report(foothold_ip="10.10.0.99", foothold_port=81)
        self.assertEqual(self.call("POST", "/steps/it_access", body={})[0], 200)
        self.assertIn("--target-url http://10.10.0.99:81 ", self.ran[-1])

    def test_a_report_is_put_on_record_with_the_tree_it_gave(self):
        self.report(**self.HMI, operator="agent:x", note="nmap")
        (told,) = self.rows("recon")
        self.assertEqual(told["reported"], self.HMI)
        self.assertEqual((told["operator"], told["note"]), ("agent:x", "nmap"))
        self.assertEqual(told["steps"], ["it_access", "it_exec"])
        (belief,) = self.rows("belief")
        with open(self.belief) as f:
            self.assertEqual(json.load(f), belief["tree"])

    def test_the_tree_credits_the_team_with_nothing_it_did_not_find(self):
        self.report(**self.HMI)
        with open(self.belief) as f:
            idx = R.tree_doc.index(json.load(f))
        open_ = {i for i, n in idx.items() if R.steps.is_step(n) and R.tree_doc.feasible(n)}
        self.assertEqual(
            open_, {"it_access", "it_exec"}, "the fidelity would count a way never found"
        )

    def test_the_runs_so_far_outlive_a_new_list(self):
        self.report(**self.HMI)
        self.call("POST", "/steps/it_access", body={})
        self.report(**self.ENGINE)
        state = json.loads(self.call("GET", "/state")[1])
        self.assertEqual([r["step"] for r in state["history"]], ["it_access"])
        self.assertEqual(state["steps"][0]["outcome"], "done")
        self.assertEqual(state["known"]["engine_ip"], "10.20.0.10")

    def test_a_report_that_cannot_be_read_changes_nothing(self):
        for wrong in (
            {},
            {"foothold_ip": "the hmi"},
            {"foothold_ip": "10.10.0.20", "foothold_port": "8080"},
            {"registers": "one,two"},
        ):
            code, said = self.report(**wrong)
            self.assertEqual(code, 400, f"the console took {wrong}")
            self.assertIn("must be" if wrong else "at least one", said["error"])
        self.assertEqual((self.listed(), self.recon.known), ([], {}))

    def test_a_console_that_was_given_its_tree_takes_no_report(self):
        given = R.RedConsole(R.Bench(STEPS, run=FakeShell()), TOKEN, host="127.0.0.1").start()
        self.addCleanup(given.shutdown)
        self.console = given
        self.assertEqual(self.report(**self.HMI)[0], 404)
