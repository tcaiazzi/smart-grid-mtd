"""Two players' transcripts written by hand, and the trajectories the range
builds from them, for the tests of the dashboard's card of the players' games.

The card draws what cps/trajectory.py writes. A document written by hand for
its test would hold what its author thinks the builder writes, and the card
would go on passing after the builder changed; these go through the builder.

The times are those of the run the panels' drawing harness folds
(tests/core/panel_draw_harness.js): it starts at 100 and is attacked from 131.
"""

import json

from cyberrange.scenarios.cps import trajectory


def _row(t, kind, team, **more):
    return {"t": t, "kind": kind, "team": team} | more


def _asked(t, team, name, call_id, **args):
    more = {"tool": {"name": name}, "input": json.dumps(args), "tool_call_id": call_id}
    return _row(t, "player_call_start", team, **more)


def _answered(t, team, name, call_id, output, took, outcome="ok", **more):
    more |= {"tool": name, "duration_s": took, "outcome": outcome, "tool_call_id": call_id}
    return _row(t, "player_call", team, output=output, **more)


def _turn(t, text, calls, model="m1", **usage):
    calls = [{"id": call_id, "name": name, "args": args} for name, call_id, args in calls]
    more = {"text": text, "model": model, "tool_calls": calls, "usage_metadata": usage}
    return _row(t, "player_turn", "red", **more)


def a_models_game():
    """Red, played by a model: two calls on one answer, a refusal that changes
    the model, a step that does not work, and a call the lab never answered."""
    looked = [("shell", "c1", {"cmd": "id"}), ("get_state", "c2", {})]
    return [
        _row(131, "player_start", "red", harness="claude-code", harness_version="2.1", model="m1"),
        _row(131, "player_prompt", "red", text="Play red."),
        _turn(
            133, "I look at the lab first.", looked, input_tokens=400, cache_read_input_tokens=800
        ),
        _asked(133.2, "red", "shell", "c1", cmd="id"),
        _answered(133.2, "red", "shell", "c1", "uid=0(root)", 1.5, result_ok=True, n=1),
        _answered(134.8, "red", "get_state", "c2", '{"steps": []}', 0.01, n=2),
        _row(136, "player_event", "red", what="refusal", category="cyber"),
        _row(136, "player_event", "red", what="model_change", was="m1", now="m0"),
        _turn(138, "", [("run_step", "c3", {"id": "it_access"})], model="m0", input_tokens=900),
        _answered(138.1, "red", "run_step", "c3", '{"ok": false}', 0.4, result_ok=False, n=3),
        _turn(141, "Now I wait.", [("wait", "c4", {"seconds": 5})], model="m0", input_tokens=950),
        _asked(141.1, "red", "wait", "c4", seconds=5),
        _row(150, "player_usage", "red", input_tokens=3050, output_tokens=40, cost_usd=0.02),
        _row(150, "player_exit", "red", rc=0),
    ]


def a_scripted_game():
    """Blue, played by a script: every move is a call with no model behind it,
    one of them refused by the seat."""
    return [
        _row(131, "player_start", "blue", harness="scripted-slow", harness_version="2", model=None),
        _row(131, "player_prompt", "blue", text="Play blue."),
        _answered(132, "blue", "list_suggestions", "blue-1", '{"pending": ["q1"]}', 0.002, n=1),
        _answered(
            140, "blue", "answer_suggestion", "blue-2", "no such suggestion", 0.05, "error", n=2
        ),
        _answered(141, "blue", "wait", "blue-3", '{"waited_s": 8}', 8.0, n=3),
        _row(150, "player_exit", "blue", rc=0),
    ]


def of_a_run(run_id="r1") -> dict:
    """{team: document}, as the dashboard hands a scored run's to its panels."""
    games = {"red": a_models_game(), "blue": a_scripted_game()}
    docs = {team: trajectory.build(rows, run_id, team) for team, rows in games.items()}
    for team, doc in docs.items():
        broken = trajectory.check(doc)
        assert not broken, f"the {team} fixture is not a trajectory the range would write: {broken}"
    return docs
