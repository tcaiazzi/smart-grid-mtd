#!/usr/bin/env python3
"""planner.py — tree-guided attacker (pure: no Kathará, no network).

AttackPlanner picks an impact goal per its profile, walks the prerequisite steps
to it, and executes each by calling the injected ``exec_step(node) -> outcome``.
When a step fails (a countermeasure closed its path) it marks the branch blocked
and tries another feasible impact, or stops ("defended"). Deterministic given
the seed, so an episode can be replayed.

Copied flat onto the attacker node with steps.py, tree_doc.py and red_agent.py
(see the scenario's guest_files.py). Stdlib only.
"""

import random

import steps as S
import tree_doc

PROFILES = ("opportunistic", "targeted", "stealthy")


class AttackPlanner:
    def __init__(
        self, tree, profile="opportunistic", goal=None, seed=None, max_steps=12, via=None, unit=None
    ):
        """``tree`` is the attack tree as a document (see tree_doc): the attacker
        plans on what it knows of the target, not on the defender's live graph.
        ``goal`` is the kind of impact a targeted attacker aims for (or one
        node's id); ``via`` and ``unit`` narrow any profile to one way in and
        one feeder of a lab that has several."""
        if profile not in PROFILES:
            raise ValueError(f"unknown profile {profile!r}")
        self.tree = tree
        self.idx = tree_doc.index(tree)
        self.places = S.places(tree)
        self.profile, self.goal = profile, goal
        self.via, self.unit = via, unit
        if profile == "targeted" and not self._impacts(goal):
            raise ValueError(f"targeted profile needs a goal in {sorted(S.IMPACT_MODE)}")
        self.rng = random.Random(seed)
        self.max_steps = max_steps

    # ── planning ───────────────────────────────────────────────────────────────
    def kind(self, node):
        return S.kind_of(self.idx[node])

    def _impacts(self, goal=None):
        """The tree's impact leaves, in its order; with ``goal``, those of that
        kind (or the one of that id)."""
        return [
            n["id"]
            for n in tree_doc.walk(self.tree)
            if S.kind_of(n) in S.IMPACT_MODE and goal in (None, n["id"], S.kind_of(n))
        ]

    def _aimed(self, node):
        """Whether ``node`` is on the way in and the feeder this attacker was
        narrowed to. A step that goes by no way of its own fits any."""
        place = self.places[node]
        return (self.via is None or place["via"] in (None, self.via)) and (
            self.unit is None or place["unit"] == self.unit
        )

    def impact_candidates(self):
        """Feasible impact leaves of the tree, ordered by profile; among equals,
        in the tree's order (its first way in, its first feeder)."""
        goal = self.goal if self.profile == "targeted" else None
        leaves = [
            n for n in self._impacts(goal) if tree_doc.feasible(self.idx[n]) and self._aimed(n)
        ]
        if self.profile == "targeted":
            return leaves
        if self.profile == "stealthy":

            def key(n):
                return (S.DETECTABILITY.get(self.kind(n), 0.5), -self.idx[n]["impact"])
        else:  # opportunistic: the biggest impact first

            def key(n):
                return (-self.idx[n]["impact"], S.DETECTABILITY.get(self.kind(n), 0.5))

        return sorted(leaves, key=key)

    def _way_for(self, kinds, failed):
        """The ids of the steps of ``kinds`` on one way in: the first way (the
        one this attacker was narrowed to before the others) none of whose
        steps has failed, or the first way at all when every one is closed."""
        by_way = {}
        for n in tree_doc.walk(self.tree):
            via = self.places[n["id"]]["via"]
            if S.kind_of(n) in kinds and via is not None:
                by_way.setdefault(via, []).append(n["id"])
        ways = sorted(by_way, key=lambda w: w != self.via)  # stable: the tree's order
        open_ways = [w for w in ways if not set(by_way[w]) & set(failed)]
        return by_way[(open_ways or ways)[0]] if ways else []

    def sequence_for(self, leaf, failed=()):
        """Ordered executable steps to reach ``leaf``: its prerequisite steps
        (in stage order) then the leaf itself. What the lab requires beyond the
        tree (steps.REQUIRES) is taken on one way in, avoiding the ``failed``."""
        pre = list(tree_doc.prerequisites(self.tree, leaf))
        for node in list(pre):
            needed = [
                k for k in S.REQUIRES.get(self.kind(node), ()) if k not in map(self.kind, pre)
            ]
            pre += self._way_for(needed, failed) if needed else []
        steps = [n for n in dict.fromkeys(pre) if S.is_step(self.idx[n])]
        return sorted(steps, key=lambda n: S.PREREQ_ORDER.index(self.kind(n))) + [leaf]

    # ── execution ──────────────────────────────────────────────────────────────
    def run(self, exec_step, sleep=lambda s: None, record=None, dwell=0.0, on_plan=None):
        """Drive the episode. ``exec_step(node) -> {"ok", "writes", ...}``.
        ``record(**step)`` is told every step, ``on_plan(**plan)`` every choice
        of an impact to aim at: what was open, what was closed, and the steps
        that lead there. Returns a summary dict."""
        record = record or (lambda **f: None)
        on_plan = on_plan or (lambda **f: None)
        done, failed, log = set(), set(), []
        writes_ok = 0
        steps_run = 0
        success = False
        tried_leaves = set()

        while steps_run < self.max_steps:
            open_leaves = [
                c
                for c in self.impact_candidates()
                if c not in tried_leaves and not (set(self.sequence_for(c, failed)) & failed)
            ]
            if not open_leaves:
                break  # no feasible impact left: defended
            leaf = open_leaves[0]
            sequence = self.sequence_for(leaf, failed)
            on_plan(
                target=leaf,
                sequence=sequence,
                candidates=[
                    {
                        "node": c,
                        "impact": self.idx[c].get("impact"),
                        "detectability": S.DETECTABILITY.get(self.kind(c)),
                    }
                    for c in open_leaves
                ],
                blocked=sorted(failed),
                reason="replan" if tried_leaves else "initial",
            )
            tried_leaves.add(leaf)
            for node in sequence:
                if node in done:
                    continue
                if steps_run >= self.max_steps:
                    break
                if dwell and steps_run:
                    sleep(dwell)
                outcome = exec_step(node) or {}
                steps_run += 1
                ok = bool(outcome.get("ok"))
                writes_ok += int(outcome.get("writes", 0))
                entry = {
                    "node": node,
                    # Not "kind": that names the row itself in the agent's record.
                    "step_kind": self.kind(node),
                    **self.places[node],
                    "stage": S.stage_of(self.idx[node]),
                    "attck": self.idx[node].get("attck"),
                    "ok": ok,
                    "chosen_among": open_leaves,
                    "target": leaf,
                    "writes": outcome.get("writes", 0),
                }
                log.append(entry)
                record(**entry)
                if ok:
                    done.add(node)
                    if node == leaf:
                        success = True
                else:
                    failed.add(node)
                    break  # this path is blocked; re-plan
            if success:
                break

        stage_reached = max((S.STAGE_INDEX[e["stage"]] for e in log if e["ok"]), default=-1)
        stages = ["none"] + S.STAGES
        return {
            "profile": self.profile,
            "goal": self.goal,
            "success": success,
            "writes_ok": writes_ok,
            "steps": log,
            "stage_reached": stages[stage_reached + 1],
            "defended": not success,
        }
