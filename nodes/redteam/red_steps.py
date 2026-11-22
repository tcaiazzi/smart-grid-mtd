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


def needs(tree, node_id):
    """What must have succeeded before ``node_id``: its prerequisites in the
    tree, and what those need in the lab (steps.REQUIRES) — on the tree's first
    way in, when the lab has several."""
    idx, places = tree_doc.index(tree), S.places(tree)
    out = list(tree_doc.prerequisites(tree, node_id))
    for node in [node_id] + list(out):
        for kind in S.REQUIRES.get(S.kind_of(idx[node]), ()):
            if kind in [S.kind_of(idx[n]) for n in out]:
                continue
            on_a_way = [n for n, d in idx.items() if S.kind_of(d) == kind and places[n]["via"]]
            out += on_a_way[:1]
    return out


def build_steps(
    tree, target_url, engine_ip, engine_port, interval=0.5, ways=None, plant_b64=None, give_up=0
):
    """The steps a person may run: every executable, feasible node of the attack
    ``tree``, in stage order, each with its command and its prerequisites.
    ``ways`` ({host: URL}) are the applications of the tree's ways in, for a lab
    with several; a step that names none uses ``target_url``. ``give_up`` is
    how many writes refused in a row end a step early (0: it tries them all)."""
    ctx = {
        "target_url": target_url,
        "engine_ip": engine_ip,
        "engine_port": engine_port,
        "interval": interval,
        "ways": ways or {},
        "plant_b64": plant_b64,
        "give_up": give_up,
    }
    places = S.places(tree)
    nodes = [n for n in tree_doc.walk(tree) if S.is_step(n) and tree_doc.feasible(n)]
    nodes.sort(key=lambda n: S.STAGE_INDEX[S.stage_of(n)])
    known = {n["id"] for n in nodes}
    return [
        {
            "id": n["id"],
            "label": n.get("label") or n["id"],
            "attck": n.get("attck"),
            "attck_name": n.get("attck_name"),
            "stage": S.stage_of(n),
            # How far into the attack the stage is: the range has the order of
            # the stages from here, not a copy of its own to keep in step.
            "stage_rank": S.STAGE_INDEX[S.stage_of(n)],
            **places[n["id"]],
            "detectability": S.DETECTABILITY.get(S.kind_of(n)),
            "needs": [p for p in needs(tree, n["id"]) if p in known],
            "command": S.step_command(n, ctx, places[n["id"]]),
        }
        for n in nodes
    ]
