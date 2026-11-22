#!/usr/bin/env python3
"""scripted_player.py — the launcher of the scripted harnesses: players with no
model, each following one fixed policy.

They are the yardstick the other harnesses are held against, and the opponents
that stay the same while those change. One opponent would measure one thing
only — against a defender that approves everything within two seconds a quiet
attack never has the time to work, so only speed would count — hence a few, of
different strength (--policy):

    red   loud    the attack's steps in the order given, as each becomes ready
          quiet   the same, the least noticeable ready step first
          idle    no attack at all: what a defender does with nothing to defend
    blue  fast    approves every suggestion as soon as it sees it
          slow    approves each one only after it has waited 20 seconds
          absent  answers nothing: the suggestions expire unapplied

They play through the same adapter as a model does (seat_mcp.Player), so their
calls are counted, timed and limited like anyone's.

Copied flat onto a player's node, next to seat_mcp.py and harness_kit.py.
Stdlib only.
"""

import argparse
import time

import harness_kit
import seat_mcp

HARNESS = "scripted"
VERSION = "2"
PACE_S = 2.0  # between two looks at the seat
SLOW_S = 20.0  # how long the slow defender lets a suggestion wait
POLICIES = {"red": ("loud", "quiet", "idle"), "blue": ("fast", "slow", "absent")}


def wait_out(player, sleep):
    """Stay at the seat doing nothing until the engagement ends: a player that
    left at once would end an engagement the other side is still playing."""
    while not over(player):
        left = player.left()["seconds_left"]
        if left is None:
            return "no_deadline"
        sleep(min(PACE_S, max(0.0, left)))
    return "out_of_terms"


def red(player, sleep, policy="loud", tries=2):
    """Every step once what it needs is done; a step that fails is tried again
    once. Ends when nothing is left to try."""
    if policy == "idle":
        return wait_out(player, sleep)
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
        if policy == "quiet":
            # The order given breaks ties: among equally quiet steps, the earlier stage.
            todo.sort(key=lambda s: s.get("detectability") or 0.0)
        step = todo[0]
        tried[step["id"]] = tried.get(step["id"], 0) + 1
        why = "quietest step ready" if policy == "quiet" else "next step ready"
        _row, failed = player.call("run_step", {"id": step["id"], "note": why})
        if failed and over(player):
            return "out_of_terms"
        sleep(PACE_S)


def blue(player, sleep, policy="fast"):
    """Approve every suggestion — at once, or once it has waited — until the
    engagement ends."""
    if policy == "absent":
        return wait_out(player, sleep)
    wait = SLOW_S if policy == "slow" else 0.0
    while not over(player):
        listed, failed = player.call("list_suggestions", {})
        if failed:
            return "out_of_terms" if over(player) else "seat_lost"
        now = listed.get("now") or 0.0
        for s in listed.get("pending") or []:
            if s.get("state") == "requested" and now - (s.get("requested_t") or now) >= wait:
                why = "approve everything" + (f", after {wait:.0f}s" if wait else "")
                args = {"id": s["request"], "verdict": "approve", "note": why}
                player.call("answer_suggestion", args)
        sleep(PACE_S)
    return "out_of_terms"


def over(player):
    left = player.left()
    spent = left["calls_left"] is not None and left["calls_left"] <= 0
    late = left["seconds_left"] is not None and left["seconds_left"] <= 0
    return spent or late


def play(player, sleep=time.sleep, policy=None):
    """Play the seat's side with ``policy`` (default: the side's first). A
    policy of the other side's is refused: a defender cannot run the attack."""
    side = (
        "red"
        if "run_step" in player.tools
        else "blue"
        if "answer_suggestion" in player.tools
        else None
    )
    if side is None:
        return "no_policy_for_this_seat"
    policy = policy or POLICIES[side][0]
    if policy not in POLICIES[side]:
        return f"{policy}_is_not_a_{side}_policy"
    return red(player, sleep, policy) if side == "red" else blue(player, sleep, policy)


def main():
    ap = argparse.ArgumentParser(description="A player with no model: one fixed policy")
    ap.add_argument("--policy", default=None, choices=sorted(sum(POLICIES.values(), ())))
    args = ap.parse_args()
    terms = harness_kit.Terms()
    name = f"{HARNESS}-{args.policy}" if args.policy else HARNESS
    terms.started(name, VERSION)
    with open(terms.token_file) as f:
        token = f.read().strip()
    seat = seat_mcp.Seat(terms.seat_url, token, terms.operator)
    try:
        described = seat.wait(120.0)
    except seat_mcp.SeatError as e:
        terms.used(stop_reason="seat_unreachable")
        raise SystemExit(f"scripted_player: {e}") from e
    player = seat_mcp.Player(seat, described, terms.deadline, terms.max_calls, terms.transcript)
    terms.used(turns=None, stop_reason=play(player, policy=args.policy))


if __name__ == "__main__":
    main()
