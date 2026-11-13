#!/usr/bin/env python3
"""red_steps.py — the attack tree's executable steps, as data for a red operator.

Every executable, feasible node of the attack tree (a document), in the order
the steps build on each other, each with the command that realises it on this
node. The autonomous planner (planner.py) and the human console (red_console.py)
both read the same registry (steps.py); this is the human-facing view of it.

Copied flat onto the attacker node (see the scenario's guest_files.py), where
red_console.py ``import red_steps``. Stdlib only.
"""

import steps as S
import tree_doc


def build_steps(tree, target_url, engine_ip, engine_port, interval=0.5):
    """The steps a person may run: every executable, feasible node of the attack
    ``tree``, in stage order, each with its command and its prerequisites."""
    ctx = {
        "target_url": target_url,
        "engine_ip": engine_ip,
        "engine_port": engine_port,
        "interval": interval,
    }
    nodes = [n for n in tree_doc.walk(tree) if S.is_step(n["id"]) and tree_doc.feasible(n)]
    nodes.sort(key=lambda n: S.STAGE_INDEX[S.stage_of(n["id"])])
    known = {n["id"] for n in nodes}
    return [
        {
            "id": n["id"],
            "label": n.get("label") or n["id"],
            "attck": n.get("attck"),
            "attck_name": n.get("attck_name"),
            "stage": S.stage_of(n["id"]),
            "detectability": S.DETECTABILITY.get(n["id"]),
            "needs": [p for p in tree_doc.prerequisites(tree, n["id"]) if p in known],
            "command": S.step_command(n["id"], ctx),
        }
        for n in nodes
    ]
