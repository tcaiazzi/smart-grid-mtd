"""A player's trajectory (cps/trajectory.py) from a transcript written by hand:
the document other benchmarks' tools read, and the rules it must keep to be
read — no lab, no harness.

Run: `.venv/bin/python -m pytest tests/scenarios/cps/test_trajectory.py`.
"""

import fnmatch
import json
import os
import tempfile
import unittest

from cyberrange.core import ledgers
from cyberrange.scenarios.cps import trajectory as T

T0 = 1_700_000_000.0


def asked(t, name, call_id, **args):
    row = {"t": T0 + t, "kind": "player_call_start", "event": "tool_start", "team": "red"}
    return row | {"tool": {"name": name}, "input": json.dumps(args), "tool_call_id": call_id}


def answered(t, name, call_id, output, n=1, **more):
    row = {"t": T0 + t, "kind": "player_call", "event": "tool_end", "team": "red", "tool": name}
    row |= {"n": n, "duration_s": 0.5, "outcome": "ok", "tool_call_id": call_id, "output": output}
    return row | {"input": "{}"} | more


def turn(t, text, calls=(), model="m1", **usage):
    row = {"t": T0 + t, "kind": "player_turn", "event": "llm_end", "text": text, "model": model}
    return row | {"tool_calls": list(calls), "usage_metadata": usage, "thinking_blocks": 1}


def used(name, call_id, **args):
    return {"id": call_id, "name": name, "args": args}


START = {"t": T0, "kind": "player_start", "harness": "h1", "harness_version": "1.2", "model": "m1"}
PROMPT = {"t": T0, "kind": "player_prompt", "text": "Play."}
TOOLS = {
    "t": T0,
    "kind": "player_tools",
    "tools": [{"name": "shell", "description": "run", "inputSchema": {"type": "object"}}],
}


class AModelsGame(unittest.TestCase):
    def setUp(self):
        self.rows = [
            START,
            PROMPT,
            TOOLS,
            asked(2, "shell", "c1", cmd="id"),
            answered(2, "shell", "c1", "uid=0", result_ok=True, note="who"),
            turn(1, "I look.", [used("shell", "c1", cmd="id")], input_tokens=10, output_tokens=4),
            {"t": T0 + 3, "kind": "player_event", "what": "refusal", "category": "cyber"},
            {"t": T0 + 3, "kind": "player_event", "what": "model_change", "was": "m1", "now": "m0"},
            turn(4, "Then.", [used("run_step", "c2", id="pivot")], model="m0", output_tokens=2),
            asked(5, "run_step", "c2", id="pivot"),
            {"t": T0 + 9, "kind": "player_usage", "input_tokens": 30, "output_tokens": 6},
        ]
        self.doc = T.build(self.rows, "run-1", "red", card={"calls": 2})

    def test_it_is_a_document_the_format_takes(self):
        self.assertEqual(T.check(self.doc), [])
        self.assertEqual(
            (self.doc["schema_version"], self.doc["session_id"], self.doc["trajectory_id"]),
            ("ATIF-v1.8", "run-1", "run-1-red"),
        )
        self.assertEqual([s["step_id"] for s in self.doc["steps"]], [1, 2, 3, 4, 5])
        self.assertEqual(
            [s["source"] for s in self.doc["steps"]], ["user", "agent", "system", "system", "agent"]
        )

    def test_who_played_with_what_tools_is_said_once(self):
        agent = self.doc["agent"]
        self.assertEqual(
            (agent["name"], agent["version"], agent["model_name"]), ("h1", "1.2", "m1")
        )
        self.assertEqual(agent["tool_definitions"][0]["function"]["name"], "shell")
        self.assertEqual(self.doc["steps"][0]["message"], "Play.")

    def test_a_turn_holds_its_calls_and_all_that_each_gave_back(self):
        step = self.doc["steps"][1]
        self.assertEqual((step["message"], step["model_name"]), ("I look.", "m1"))
        (call,) = step["tool_calls"]
        self.assertEqual((call["function_name"], call["arguments"]), ("shell", {"cmd": "id"}))
        self.assertEqual(
            call["extra"],
            {"outcome": "ok", "result_ok": True, "duration_s": 0.5, "note": "who", "n": 1}
            | {"timestamp": "2023-11-14T22:13:22.000+00:00"},
            "what the seat says of a call is not beside it",
        )
        self.assertNotEqual(
            call["extra"]["timestamp"],
            step["timestamp"],
            "a call is timed by its turn: a reader cannot tell when the seat was asked",
        )
        self.assertEqual(
            step["observation"]["results"], [{"source_call_id": "c1", "content": "uid=0"}]
        )
        self.assertEqual(step["metrics"], {"prompt_tokens": 10, "completion_tokens": 4})

    def test_a_change_of_model_is_a_step_and_the_later_turns_are_the_new_models(self):
        _refused, changed, after = self.doc["steps"][2:]
        self.assertEqual(changed["extra"], {"what": "model_change", "was": "m1", "now": "m0"})
        self.assertIn("from m1 to m0", changed["message"])
        self.assertEqual(after["model_name"], "m0")
        self.assertEqual(self.doc["extra"]["models"], ["m1", "m0"])

    def test_a_call_the_lab_went_down_under_has_no_result_made_up_for_it(self):
        last = self.doc["steps"][-1]
        self.assertEqual(last["tool_calls"][0]["extra"], {"answered": False})
        self.assertNotIn("observation", last)
        self.assertEqual(self.doc["extra"]["unmatched_calls"], 1)

    def test_the_totals_are_the_harnesss_own_and_the_card_goes_with_it(self):
        self.assertEqual(
            self.doc["final_metrics"],
            {"total_prompt_tokens": 30, "total_completion_tokens": 6, "total_steps": 5},
        )
        self.assertEqual(self.doc["extra"]["scorecard"], {"calls": 2})

    def test_without_the_harnesss_id_a_call_is_found_by_its_order_and_its_tool_only(self):
        rows = [
            START,
            turn(1, "", [used("shell", "toolu_a", cmd="id"), used("time_left", "toolu_b")]),
            answered(2, "shell", "red-1", "uid=0"),
            answered(3, "wait", "red-2", "{}", n=1),
        ]
        doc = T.build(rows, "r", "red")
        self.assertEqual(T.check(doc), [])
        step = doc["steps"][0]
        self.assertEqual(
            step["observation"]["results"], [{"source_call_id": "toolu_a", "content": "uid=0"}]
        )
        self.assertEqual(
            doc["extra"]["unmatched_calls"], 1, "a call was given the result of another tool's"
        )
        self.assertEqual(
            doc["steps"][1]["tool_calls"][0]["function_name"], "wait", "a call on no turn was lost"
        )


class AScriptedGame(unittest.TestCase):
    def test_every_call_is_a_step_that_no_model_inferred(self):
        rows = [
            START | {"harness": "scripted-loud", "model": None},
            asked(1, "run_step", "red-1", id="it_access"),
            answered(1, "run_step", "red-1", '{"ok": true}', result_ok=True),
            asked(2, "wait", "red-2", seconds=5),
            answered(2, "wait", "red-2", "{}", n=1),
        ]
        doc = T.build(rows, "r", "red")
        self.assertEqual(T.check(doc), [])
        self.assertEqual([s["llm_call_count"] for s in doc["steps"]], [0, 0])
        first = doc["steps"][0]
        self.assertEqual(first["tool_calls"][0]["arguments"], {"id": "it_access"})
        self.assertEqual(first["observation"]["results"][0]["content"], '{"ok": true}')
        self.assertNotIn("metrics", first)
        self.assertNotIn("model_name", doc["agent"])


class TheFormatsRules(unittest.TestCase):
    def setUp(self):
        self.doc = T.build([START, PROMPT, turn(1, "x", [used("shell", "c1")])], "r", "red")
        self.assertEqual(T.check(self.doc), [])

    def refused(self):
        return " ".join(T.check(self.doc))

    def test_steps_out_of_sequence_are_refused(self):
        self.doc["steps"][1]["step_id"] = 5
        self.assertIn("step_id is 5, not 2", self.refused())

    def test_a_field_of_the_ranges_own_outside_extra_is_refused(self):
        self.doc["steps"][1]["tool_calls"][0]["outcome"] = "ok"
        self.assertIn("outcome is not a field of the format", self.refused())

    def test_a_models_field_on_a_step_that_is_not_the_agents_is_refused(self):
        self.doc["steps"][0]["model_name"] = "m1"
        self.assertIn("step 1: model_name is not a field", self.refused())

    def test_a_result_that_answers_no_call_is_refused(self):
        self.doc["steps"][1]["observation"] = {"results": [{"source_call_id": "nope"}]}
        self.assertIn("a result answers 'nope'", self.refused())


class ARunsTrajectories(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="traj-")
        with open(os.path.join(self.d, "run.json"), "w") as f:
            json.dump({"run_id": "run-9"}, f)

    def transcript(self, team, rows):
        with open(os.path.join(self.d, f"player-{team}.jsonl"), "w") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)

    def test_one_file_per_player_under_the_runs_session(self):
        self.transcript("red", [START, turn(1, "x")])
        self.transcript("blue", [START, turn(1, "y")])
        written = T.write(self.d, {"red": {"calls": 0}})
        self.assertEqual(sorted(written), ["blue", "red"])
        docs = {}
        for team, path in written.items():
            with open(path) as f:
                docs[team] = json.load(f)
        self.assertEqual({d["session_id"] for d in docs.values()}, {"run-9"})
        self.assertEqual(docs["red"]["trajectory_id"], "run-9-red")
        self.assertNotIn("scorecard", docs["blue"]["extra"])

    def test_the_dashboard_finds_the_files_by_their_name(self):
        self.transcript("red", [START, turn(1, "x")])
        (path,) = T.write(self.d).values()
        self.assertTrue(
            fnmatch.fnmatch(os.path.basename(path), ledgers.TRAJECTORY_FILES),
            "the dashboard looks for another name: a scored run would show no trajectory",
        )

    def test_an_older_runs_turns_and_outputs_come_from_the_harnesss_stream(self):
        old = {"t": T0 + 2, "kind": "player_call", "tool": "shell", "n": 1, "outcome": "ok"}
        self.transcript("red", [START, old])
        stream = os.path.join(self.d, "redplayer.player.log")

        def said(block, **usage):
            message = {"id": "msg_1", "model": "m0", "content": [block], "usage": usage}
            return {"type": "assistant", "timestamp": "2023-11-14T22:13:21Z", "message": message}

        call = {"type": "tool_use", "id": "toolu_1", "name": "mcp__seat__shell"}
        result = {"type": "tool_result", "tool_use_id": "toolu_1"}
        events = [
            {"type": "system", "subtype": "model_refusal_fallback", "api_refusal_category": "cyber"}
            | {"original_model": "m1", "fallback_model": "m0"},
            said({"type": "text", "text": "I look."}, output_tokens=1),
            said(call | {"input": {"cmd": "id"}}, output_tokens=3),
            {"type": "user", "message": {"content": [result | {"content": [{"text": "uid=0"}]}]}},
        ]
        with open(stream, "w") as f:
            f.write("not json\n")
            f.writelines(json.dumps(e) + "\n" for e in events)
        with open(T.write(self.d, harness_logs={"red": stream})["red"]) as f:
            doc = json.load(f)
        agent = next(s for s in doc["steps"] if s["source"] == "agent")
        self.assertEqual((agent["message"], agent["model_name"]), ("I look.", "m0"))
        self.assertEqual(agent["tool_calls"][0]["extra"]["outcome"], "ok")
        self.assertEqual(agent["observation"]["results"][0]["content"], "uid=0")
        self.assertEqual(agent["metrics"]["completion_tokens"], 3)
        self.assertEqual(doc["extra"]["models"], ["m1", "m0"])


if __name__ == "__main__":
    unittest.main()
