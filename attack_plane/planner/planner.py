"""planner.py — tree-guided attacker (host-side, pure: no Kathará, no network).

AttackPlanner picks an impact goal per its profile, walks the prerequisite steps
to it, and executes each by calling the injected ``exec_step(node) -> outcome``.
When a step fails (a countermeasure closed its path) it marks the branch blocked
and tries another feasible impact, or stops ("defended"). Deterministic given
the seed, so an episode can be replayed.
"""

import random

from attack_plane.planner import steps as S
from defense_plane.soar import trees

PROFILES = ("opportunistic", "targeted", "stealthy")


class AttackPlanner:
    def __init__(self, tree, kg, profile="opportunistic", goal=None, seed=None,
                 max_steps=12):
        if profile not in PROFILES:
            raise ValueError(f"unknown profile {profile!r}")
        if profile == "targeted" and goal not in S.IMPACT_MODE:
            raise ValueError(f"targeted profile needs a goal in {sorted(S.IMPACT_MODE)}")
        self.tree, self.kg = tree, kg
        self.idx = trees.index(tree)
        self.profile, self.goal = profile, goal
        self.rng = random.Random(seed)
        self.max_steps = max_steps

    # ── planning ───────────────────────────────────────────────────────────────
    def impact_candidates(self):
        """Feasible impact leaves on the current graph, ordered by profile."""
        leaves = [n for n in S.IMPACT_MODE if n in self.idx
                  and trees.feasible(self.idx[n], self.kg)]
        if self.profile == "targeted":
            return [self.goal] if self.goal in leaves else []
        if self.profile == "stealthy":
            key = lambda n: (S.DETECTABILITY.get(n, 0.5), -self.idx[n].impact)
        else:  # opportunistic: the biggest impact first
            key = lambda n: (-self.idx[n].impact, S.DETECTABILITY.get(n, 0.5))
        return sorted(leaves, key=key)

    def sequence_for(self, leaf):
        """Ordered executable steps to reach ``leaf``: its prerequisite steps
        (in stage order) then the leaf itself."""
        pre = set(trees.prerequisites(self.tree, leaf))
        ordered = [n for n in S.PREREQ_ORDER if n in pre and S.is_step(n)]
        return ordered + [leaf]

    # ── execution ──────────────────────────────────────────────────────────────
    def run(self, exec_step, sleep=lambda s: None, record=None, dwell=0.0):
        """Drive the episode. ``exec_step(node) -> {"ok", "writes", ...}``.
        Returns a summary dict."""
        record = record or (lambda **f: None)
        done, failed, log = set(), set(), []
        writes_ok = 0
        steps_run = 0
        success = False
        tried_leaves = set()

        while steps_run < self.max_steps:
            leaf = next((c for c in self.impact_candidates() if c not in tried_leaves
                         and not (set(self.sequence_for(c)) & failed)), None)
            if leaf is None:
                break                       # no feasible impact left: defended
            tried_leaves.add(leaf)
            for node in self.sequence_for(leaf):
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
                entry = {"node": node, "stage": S.stage_of(node), "attck": self.idx[node].attck,
                         "ok": ok, "chosen_among": [leaf], "target": leaf,
                         "writes": outcome.get("writes", 0)}
                log.append(entry)
                record(**entry)
                if ok:
                    done.add(node)
                    if node == leaf:
                        success = True
                else:
                    failed.add(node)
                    break               # this path is blocked; re-plan
            if success:
                break

        stage_reached = max((S.STAGE_INDEX[S.stage_of(e["node"])] for e in log if e["ok"]),
                            default=-1)
        stages = ["none", "it_access", "it_exec", "pivot", "impact"]
        return {"profile": self.profile, "goal": self.goal, "success": success,
                "writes_ok": writes_ok, "steps": log,
                "stage_reached": stages[stage_reached + 1], "defended": not success}
