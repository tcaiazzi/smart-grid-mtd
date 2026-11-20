#!/usr/bin/env python3
"""scripted_player.py — the launcher of the scripted harness: a player with no
model, that follows one fixed policy.

It is the yardstick the other harnesses are held against, and the opponent
that stays the same while they change: a red team that runs the attack's steps
in order as each becomes ready, a blue team that approves whatever the SOC
suggests. It plays through the same adapter as a model does (seat_mcp.Player),
so its calls are counted, timed and limited like anyone's.

Copied flat onto a player's node, next to seat_mcp.py and harness_kit.py.
Stdlib only.
"""

import time

import harness_kit
import seat_mcp

HARNESS = "scripted"
VERSION = "1"
PACE_S = 2.0  # between two looks at the seat


def red(player, sleep, tries=2):
    """Every step, in the order given, once what it needs is done; a step that
    fails is tried again once. Ends when nothing is left to try."""
    tried = {}
    while True:
        steps, failed = player.call("list_steps", {})
        if failed:
            return "out_of_terms" if over(player) else "seat_lost"
        todo = [
            s
            for s in steps
            if s["outcome"] != "done" and s.get("ready") and tried.get(s["id"], 0) < tries
        ]
        if not todo:
            return "done" if all(s["outcome"] == "done" for s in steps) else "stuck"
        step = todo[0]
        tried[step["id"]] = tried.get(step["id"], 0) + 1
        _row, failed = player.call("run_step", {"id": step["id"], "note": "next step ready"})
        if failed and over(player):
            return "out_of_terms"
        sleep(PACE_S)


def blue(player, sleep):
    """Approve every suggestion as it comes, until the engagement ends."""
    while not over(player):
        listed, failed = player.call("list_suggestions", {})
        if failed:
            return "out_of_terms" if over(player) else "seat_lost"
        for s in listed.get("pending") or []:
            if s.get("state") == "requested":
                args = {"id": s["request"], "verdict": "approve", "note": "approve everything"}
                player.call("answer_suggestion", args)
        sleep(PACE_S)
    return "out_of_terms"


def over(player):
    left = player.left()
    spent = left["calls_left"] is not None and left["calls_left"] <= 0
    late = left["seconds_left"] is not None and left["seconds_left"] <= 0
    return spent or late


def play(player, sleep=time.sleep):
    if "run_step" in player.tools:
        return red(player, sleep)
    if "answer_suggestion" in player.tools:
        return blue(player, sleep)
    return "no_policy_for_this_seat"


def main():
    terms = harness_kit.Terms()
    terms.started(HARNESS, VERSION)
    with open(terms.token_file) as f:
        token = f.read().strip()
    seat = seat_mcp.Seat(terms.seat_url, token, terms.operator)
    try:
        described = seat.wait(120.0)
    except seat_mcp.SeatError as e:
        terms.used(stop_reason="seat_unreachable")
        raise SystemExit(f"scripted_player: {e}") from e
    player = seat_mcp.Player(seat, described, terms.deadline, terms.max_calls, terms.transcript)
    terms.used(turns=None, stop_reason=play(player))


if __name__ == "__main__":
    main()
