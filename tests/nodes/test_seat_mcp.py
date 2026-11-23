"""The seat's MCP adapter (nodes/players/seat_mcp.py), played against the two
real consoles on free ports — so that a tool and the route it calls cannot
drift apart — and once over stdio, as a harness starts it. No Docker, no model.

Run: `.venv/bin/python -m pytest tests/nodes/test_seat_mcp.py`.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.REDTEAM, guest_paths.PLAYERS)

import red_console as R  # noqa: E402  (flat guest import, needs the path set above)
import seat  # noqa: E402  (flat guest import, needs the path set above)
import seat_mcp as M  # noqa: E402  (flat guest import, needs the path set above)
import soc_operator as O  # noqa: E402  (flat guest import, needs the path set above)

TOKEN = "t0ken"
STEPS = [
    {"id": "it_access", "label": "Exploit the web app", "stage": "it_access", "needs": []},
    {"id": "pivot", "label": "Reach the plant", "stage": "pivot", "needs": ["it_access"]},
]
for _s in STEPS:
    _s["command"] = f"run {_s['id']}"


def typed(cmd):
    return 0, f"ran {cmd}", ""


def red_console():
    place = seat.Seat("red", R.ACTIONS, "tree", "# Red", audit_log=os.devnull, run=typed)
    bench = R.Bench(STEPS, run=lambda cmd: (0, json.dumps({"phase": cmd.split()[-1], "ok": True})))
    return R.RedConsole(bench, TOKEN, host="127.0.0.1", seat=place).start()


def soc_console(desk):
    place = seat.Seat("blue", O.ACTIONS, briefing="# Blue", audit_log=os.devnull, run=typed)
    return O.OperatorApi(desk, TOKEN, host="127.0.0.1", seat=place).start()


class Seated(unittest.TestCase):
    """A player at a console, its transcript in a scratch file."""

    def sit(self, console, **terms):
        self.addCleanup(console.shutdown)
        self.transcript = os.path.join(tempfile.mkdtemp(prefix="mcp-"), "player.jsonl")
        client = M.Seat(f"http://127.0.0.1:{console.port}", TOKEN, "scripted")
        return M.Player(client, client.wait(5), transcript=self.transcript, **terms)

    def every(self):
        with open(self.transcript) as f:
            return [json.loads(line) for line in f]

    def rows(self):
        """The calls as they ended: what the range scores."""
        return [r for r in self.every() if r["kind"] == "player_call"]


class TheRedSeat(Seated):
    def setUp(self):
        self.console = red_console()
        self.player = self.sit(self.console)

    def test_a_team_is_shown_its_own_levers_only(self):
        self.assertEqual(
            sorted(self.player.tools),
            ["get_state", "list_steps", "read_briefing", "run_step", "shell", "time_left", "wait"],
            "the red team was offered a tool of the SOC's, or lacks one of its own",
        )

    def test_a_step_is_run_in_the_agents_name_with_its_reason(self):
        row, failed = self.player.call("run_step", {"id": "it_access", "note": "the way in"})
        self.assertFalse(failed)
        self.assertEqual(
            (row["ok"], row["operator"], row["note"]),
            (True, "agent:scripted", "the way in"),
            "the console's record cannot tell this player from a person",
        )
        steps, _failed = self.player.call("list_steps", {})
        self.assertEqual({s["id"]: s["outcome"] for s in steps}["it_access"], "done")

    def test_the_briefing_and_the_shell_are_the_seats(self):
        self.assertEqual(self.player.call("read_briefing", {}), ("# Red", False))
        out, failed = self.player.call("shell", {"cmd": "id"})
        self.assertEqual((out["stdout"], failed), ("ran id", False))

    def test_every_call_is_on_the_transcript_with_how_it_ended(self):
        self.player.call("run_step", {"id": "it_access", "note": "first"})
        self.player.call("run_step", {"id": "no_such_step"})
        self.player.call("run_step", {})
        self.player.call("run_step", {"id": 7})
        with self.assertRaises(KeyError):
            self.player.call("apply_countermeasure", {"id": "block_flow"})
        rows = self.rows()
        self.assertEqual(
            [(r["tool"], r["outcome"]) for r in rows],
            [
                ("run_step", "ok"),
                ("run_step", "seat_error"),
                ("run_step", "bad_arguments"),
                ("run_step", "bad_arguments"),
                ("apply_countermeasure", "unknown_tool"),
            ],
            "the range scores a harness on these outcomes",
        )
        self.assertEqual(
            (rows[0]["id"], rows[0]["note"], rows[0]["team"]), ("it_access", "first", "red")
        )
        self.assertTrue(all(r["kind"] == "player_call" and r["duration_s"] >= 0 for r in rows))
        self.assertEqual(
            [r.get("result_ok") for r in rows],
            [True, None, None, None, None],
            "a call the seat refused was given an outcome of the action it never took",
        )

    def test_a_step_that_ran_and_failed_is_told_from_one_that_worked(self):
        self.console.bench.run = lambda cmd: (
            1,
            json.dumps({"phase": cmd.split()[-1], "ok": False}),
        )
        self.player.call("run_step", {"id": "pivot"})
        self.player.call("shell", {"cmd": "id"})
        self.player.call("list_steps", {})
        self.assertEqual(
            [(r["tool"], r["outcome"], r.get("result_ok")) for r in self.rows()],
            [("run_step", "ok", False), ("shell", "ok", True), ("list_steps", "ok", None)],
            "the transcript says the seat took the call, not whether the step worked: "
            "a harness repeating a failed step cannot be told from one that is getting on",
        )

    def test_a_call_is_on_record_when_asked_and_when_answered_with_all_it_gave(self):
        self.player.call("shell", {"cmd": "id", "note": "who am I"})
        self.player.call("run_step", {"id": "no_such_step"})
        asked, answered, _again, refused = [r for r in self.every() if r.get("event")]
        self.assertEqual(
            (asked["event"], asked["tool"], json.loads(asked["input"])),
            ("tool_start", {"name": "shell"}, {"cmd": "id", "note": "who am I"}),
        )
        self.assertEqual((answered["event"], answered["phase"]), ("tool_end", "engagement"))
        self.assertEqual(asked["tool_call_id"], answered["tool_call_id"])
        self.assertTrue(answered["timestamp"].endswith("+00:00"))
        self.assertIn("ran id", answered["output"], "what the player saw is not on its record")
        self.assertEqual(json.loads(answered["output"])["stdout"], "ran id")
        self.assertEqual(refused["event"], "tool_error", "a refused call reads as one that worked")
        self.assertNotEqual(refused["tool_call_id"], answered["tool_call_id"])

    def test_a_reader_of_nikas_format_counts_the_calls_the_range_counts(self):
        for name, args in (("list_steps", {}), ("shell", {"cmd": "id"}), ("run_step", {})):
            self.player.call(name, args)
        events = [r.get("event") for r in self.every()]
        self.assertEqual(events.count("tool_start"), len(self.rows()), "NIKA counts tool_start")
        self.assertEqual((events.count("tool_end"), events.count("tool_error")), (2, 1))

    def test_a_call_keeps_the_id_the_harness_gave_it(self):
        self.player.call("list_steps", {}, {"claudecode/toolUseId": "toolu_1", "other": 1})
        self.player.call("wait", {"seconds": 1})
        self.player.call("list_steps", {})
        ids = [r["tool_call_id"] for r in self.every() if r.get("event") == "tool_start"]
        self.assertEqual(ids, ["toolu_1", "red-2", "red-3"], "a wait shares an id with a call")

    def test_the_tools_of_the_seat_are_on_record(self):
        tools = [r for r in self.every() if r["kind"] == "player_tools"]
        self.assertEqual(len(tools), 1)
        names = {t["name"] for t in tools[0]["tools"]}
        self.assertLessEqual({"run_step", "shell", "wait"}, names)
        self.assertNotIn("answer_suggestion", names, "the other seat's tools are on this record")

    def test_the_teams_token_is_not_kept_in_what_came_back_either(self):
        self.console.seat.run = lambda cmd: (0, f"Authorization: Bearer {TOKEN}", "")
        self.player.call("shell", {"cmd": "env"})
        with open(self.transcript) as f:
            kept = f.read()
        self.assertNotIn(TOKEN, kept, "a token a command printed is in a file kept with the run")
        self.assertIn("Bearer <token>", kept)

    def test_the_teams_token_is_not_kept_in_the_transcript(self):
        self.player.call("shell", {"cmd": f"curl http://red:{TOKEN}@x/", "note": f"with {TOKEN}"})
        with open(self.transcript) as f:
            kept = f.read()
        self.assertNotIn(TOKEN, kept, "a token the harness typed is in a file kept with the run")
        self.assertIn("<token>", kept)

    def test_a_wrong_call_is_told_to_the_harness_so_it_can_correct_itself(self):
        said, failed = self.player.call("run_step", {"step": "pivot"})
        self.assertTrue(failed)
        self.assertIn("id is required", said)
        said, failed = self.player.call("run_step", {"id": "no_such_step"})
        self.assertEqual((said, failed), ("no such step", True))


class TheTerms(Seated):
    """The budget and the deadline are the adapter's to keep: left to each
    harness, two harnesses would not have played the same game."""

    def test_past_the_budget_nothing_reaches_the_seat(self):
        player = self.sit(red_console(), max_calls=2)
        player.call("run_step", {"id": "it_access"})
        self.assertEqual(player.call("time_left", {})[0]["calls_left"], 0)
        said, failed = player.call("run_step", {"id": "pivot"})
        self.assertTrue(failed)
        self.assertIn("budget", said)
        self.assertEqual(self.rows()[-1]["outcome"], "over_budget")
        steps = {s["id"]: s["outcome"] for s in player.seat.call("GET", "/state")["steps"]}
        self.assertEqual(steps["pivot"], "ready", "a step ran for a player out of budget")

    def test_past_the_deadline_nothing_reaches_the_seat(self):
        now = [100.0]
        player = self.sit(red_console(), deadline=160.0, clock=lambda: now[0])
        self.assertEqual(player.call("time_left", {})[0]["seconds_left"], 60)
        now[0] = 161.0
        said, failed = player.call("run_step", {"id": "it_access"})
        self.assertTrue(failed)
        self.assertEqual(self.rows()[-1]["outcome"], "past_deadline")
        self.assertEqual(player.seat.call("GET", "/state")["history"], [])

    def test_a_wait_is_free_and_recorded_for_what_it_is(self):
        now, slept = [100.0], []

        def sleep(s):
            slept.append(s)
            now[0] += s

        player = self.sit(red_console(), max_calls=1, clock=lambda: now[0], sleep=sleep)
        said, failed = player.call("wait", {"seconds": 20})
        self.assertFalse(failed)
        self.assertEqual((sum(slept), said["waited_s"], said["calls_left"]), (20, 20, 1))
        self.assertNotIn(
            "woken_by", said, "the red console woke its player: nothing comes up there"
        )
        row = self.rows()[-1]
        self.assertEqual((row["tool"], row["seconds"], row["duration_s"]), ("wait", 20, 20.0))
        self.assertNotIn("result_ok", row, "a wait was scored as an action that worked")
        player.call("run_step", {"id": "it_access"})
        said, failed = player.call("wait", {"seconds": 5})
        self.assertFalse(failed, "a player out of budget could no longer wait for the end")

    def test_a_wait_ends_with_the_engagement(self):
        now, slept = [100.0], []

        def sleep(s):
            slept.append(s)
            now[0] += s

        player = self.sit(red_console(), deadline=110.0, clock=lambda: now[0], sleep=sleep)
        said, _failed = player.call("wait", {"seconds": 60})
        self.assertEqual(sum(slept), 10.0, "a wait ran past the deadline: the harness is cut off")
        self.assertEqual(said["waited_s"], 10)

    def test_a_wait_takes_a_whole_number_of_seconds_within_bounds(self):
        player = self.sit(red_console(), sleep=lambda s: self.fail("a wrong wait was slept"))
        for seconds in ("20", 2.5, True, 0, M.WAIT_MAX_S + 1):
            said, failed = player.call("wait", {"seconds": seconds})
            self.assertTrue(failed, f"wait took seconds={seconds!r}")
            self.assertIn("seconds must be", said)

    def test_a_seat_that_is_not_up_yet_is_waited_for(self):
        client = M.Seat("http://127.0.0.1:9", TOKEN, "agent:x")
        slept = []
        with self.assertRaises(M.SeatError):
            client.wait(3, sleep=slept.append, clock=lambda: float(len(slept)))
        self.assertEqual(len(slept), 3, "the adapter gave up on a console that had not started")

    def test_a_wrong_token_is_not_waited_for(self):
        console = red_console()
        self.addCleanup(console.shutdown)
        client = M.Seat(f"http://127.0.0.1:{console.port}", "wrong", "agent:x")
        with self.assertRaises(M.SeatError) as refused:
            client.wait(60, sleep=lambda _s: self.fail("retried a seat that had answered no"))
        self.assertEqual(refused.exception.outcome, "seat_error")


class TheBlueSeat(Seated):
    def setUp(self):
        self.desk = O.ApprovalDesk(clock=lambda: 100.0)
        self.desk.publish({"mode": "advise", "countermeasures": [{"id": "block_flow"}]})
        self.desk.open("abc", {"action": "block_flow", "due_t": 160.0, "explanation": {}})
        self.player = self.sit(soc_console(self.desk))

    def test_a_team_is_shown_its_own_levers_only(self):
        self.assertNotIn("run_step", self.player.tools)
        for name in (
            "answer_suggestion",
            "apply_countermeasure",
            "revert_countermeasure",
            "set_mode",
        ):
            self.assertIn(name, self.player.tools)

    def test_a_suggestion_is_read_and_answered(self):
        listed, _failed = self.player.call("list_suggestions", {})
        self.assertEqual([s["request"] for s in listed["pending"]], ["abc"])
        self.assertEqual(listed["pending"][0]["expires_in_s"], 60, "the player needs a clock")
        args = {"id": "abc", "verdict": "approve", "note": "an unauthorized write"}
        self.assertFalse(self.player.call("answer_suggestion", args)[1])
        self.assertEqual(
            [(v["verdict"], v["operator"], v["note"]) for v in self.desk.take()],
            [("approve", "agent:scripted", "an unauthorized write")],
        )
        self.assertTrue(self.player.call("answer_suggestion", {"id": "abc", "verdict": "maybe"})[1])

    def waiting(self, during):
        """A player whose clock moves as it sleeps; ``during(now)`` is what
        happens at the desk meanwhile."""
        now = [100.0]

        def sleep(s):
            now[0] += s
            during(now[0])

        return self.sit(soc_console(self.desk), clock=lambda: now[0], sleep=sleep)

    def test_a_wait_ends_when_a_suggestion_comes_up(self):
        def during(now):
            if now == 106.0:
                self.desk.open("def", {"action": "isolate_ews", "due_t": 226.0})

        said, failed = self.waiting(during).call("wait", {"seconds": 60})
        self.assertFalse(failed)
        self.assertEqual(said["waited_s"], 6, "the player slept on with a suggestion waiting")
        self.assertEqual(
            [(n["what"], n["request"], n["action"]) for n in said["woken_by"]],
            [("suggestion_opened", "def", "isolate_ews")],
        )
        self.assertEqual(self.rows()[-1]["woken_by"], ["suggestion_opened"])

    def test_a_wait_ends_when_a_suggestion_lapses(self):
        def during(now):
            if now == 104.0:
                self.desk.close("abc", "expired")

        said, _failed = self.waiting(during).call("wait", {"seconds": 60})
        self.assertEqual([n["what"] for n in said["woken_by"]], ["suggestion_expired"])

    def test_what_the_player_saw_and_left_or_did_itself_does_not_end_a_wait(self):
        def during(now):
            if now == 104.0:
                self.desk.close("abc", "granted")

        said, _failed = self.waiting(during).call("wait", {"seconds": 10})
        self.assertEqual(said["waited_s"], 10, "a wait was cut short by nothing new")
        self.assertNotIn("woken_by", said)
        self.assertNotIn("woken_by", self.rows()[-1])

    def test_the_levers_reach_the_desk(self):
        self.assertEqual(self.player.call("list_countermeasures", {})[0], [{"id": "block_flow"}])
        self.player.call("apply_countermeasure", {"id": "block_flow"})
        self.player.call("revert_countermeasure", {"id": "block_flow", "note": "too costly"})
        self.player.call("set_mode", {"mode": "auto"})
        self.assertEqual(
            [
                (o["kind"], o.get("op") or o.get("mode"), o.get("note"))
                for o in self.desk.take_orders()
            ],
            [
                ("countermeasure", "apply", None),
                ("countermeasure", "revert", "too costly"),
                ("mode", "auto", None),
            ],
        )


class OverStdio(unittest.TestCase):
    """As a harness runs it: a subprocess, one JSON-RPC message per line."""

    def setUp(self):
        self.console = red_console()
        self.addCleanup(self.console.shutdown)
        self.dir = tempfile.mkdtemp(prefix="mcp-")
        with open(os.path.join(self.dir, "token"), "w") as f:
            f.write(TOKEN + "\n")

    def talk(self, *messages, url=None):
        cmd = [
            sys.executable,
            str(guest_paths.PLAYERS / "seat_mcp.py"),
            "--url",
            url or f"http://127.0.0.1:{self.console.port}",
            "--token-file",
            os.path.join(self.dir, "token"),
            "--operator",
            "agent:test",
            "--wait",
            "0",
        ]
        sent = "".join(json.dumps({"jsonrpc": "2.0", **m}) + "\n" for m in messages)
        p = subprocess.run(cmd, input=sent, capture_output=True, text=True, timeout=30)
        return p, [json.loads(line) for line in p.stdout.splitlines()]

    def test_a_session_from_the_handshake_to_a_tool_call(self):
        hello = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}
        call = {"name": "run_step", "arguments": {"id": "it_access"}}
        p, replies = self.talk(
            {"id": 1, "method": "initialize", "params": hello},
            {"method": "notifications/initialized"},
            {"id": 2, "method": "tools/list"},
            {"id": 3, "method": "tools/call", "params": call},
            {"id": 4, "method": "tools/call", "params": {"name": "set_mode", "arguments": {}}},
            {"id": 5, "method": "resources/read", "params": {"uri": "seat://briefing"}},
            {"id": 6, "method": "sampling/createMessage"},
            {"id": 7, "method": "ping"},
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(
            [r["id"] for r in replies],
            [1, 2, 3, 4, 5, 6, 7],
            "a notification was answered, or a request was not: the client would hang or desync",
        )
        by_id = {r["id"]: r for r in replies}
        self.assertEqual(by_id[1]["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("run_step", [t["name"] for t in by_id[2]["result"]["tools"]])
        done = by_id[3]["result"]
        self.assertFalse(done["isError"])
        self.assertTrue(json.loads(done["content"][0]["text"])["ok"])
        self.assertEqual(by_id[4]["error"]["code"], -32602, "a tool of the other team was called")
        self.assertEqual(by_id[5]["result"]["contents"][0]["text"], "# Red")
        self.assertEqual(by_id[6]["error"]["code"], -32601)
        self.assertEqual(by_id[7]["result"], {})

    def test_a_version_it_does_not_speak_is_answered_with_one_it_does(self):
        hello = {"protocolVersion": "2099-01-01", "capabilities": {}, "clientInfo": {"name": "t"}}
        _p, replies = self.talk({"id": 1, "method": "initialize", "params": hello})
        self.assertEqual(replies[0]["result"]["protocolVersion"], M.PROTOCOLS[0])

    def test_it_does_not_start_at_a_seat_it_cannot_reach(self):
        p, replies = self.talk({"id": 1, "method": "ping"}, url="http://127.0.0.1:9")
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(replies, [], "stdout must carry MCP messages and nothing else")
        self.assertIn("did not answer", p.stderr)


if __name__ == "__main__":
    unittest.main()


class ARedSeatThatFindsItsTree(Seated):
    def setUp(self):
        bench = R.Bench([], run=lambda cmd: (0, ""))
        said = {"known": {}, "steps": ["it_access"], "new": ["it_access"]}
        self.reports = []

        class Recon:
            known = {}

            def report(_self, doc, operator=None, note=None):
                self.reports.append((doc, operator, note))
                if doc.get("foothold_ip") == "nowhere":
                    raise ValueError("foothold_ip must be an IP address")
                return said

        place = seat.Seat("red", (*R.ACTIONS, R.REPORT), "recon", "# Red", audit_log=os.devnull)
        console = R.RedConsole(bench, TOKEN, host="127.0.0.1", seat=place, recon=Recon()).start()
        self.player = self.sit(console)

    def test_only_a_seat_that_finds_its_tree_is_offered_the_report(self):
        self.assertIn("report_findings", self.player.tools)
        given = self.sit(red_console())
        self.assertNotIn("report_findings", given.tools)

    def test_a_report_reaches_the_console_in_the_agents_name_and_the_transcript(self):
        found = {"foothold_ip": "10.10.0.20", "foothold_port": 8080, "note": "nmap"}
        said, failed = self.player.call("report_findings", found)
        self.assertFalse(failed)
        self.assertEqual(said["new"], ["it_access"])
        doc, operator, note = self.reports[-1]
        self.assertEqual((doc["foothold_port"], operator, note), (8080, "agent:scripted", "nmap"))
        row = self.rows()[-1]
        self.assertEqual((row["foothold_ip"], row["foothold_port"]), ("10.10.0.20", 8080))
        self.assertTrue(row["result_ok"])

    def test_a_report_the_console_cannot_read_is_told_to_the_harness(self):
        said, failed = self.player.call("report_findings", {"foothold_ip": "nowhere"})
        self.assertEqual((said, failed), ("foothold_ip must be an IP address", True))
        said, failed = self.player.call("report_findings", {"foothold_port": "8080"})
        self.assertIn("whole number", said)
