"""policy.py — response policies over the campaign state (mapping.snapshot()).

Two policies with the same interface, ``decide(snapshot, t) -> Decision|None``:

RulesPolicy   the static playbook (the MTM baseline of WP3): a fixed table from
              *confirmed* impact leaves to countermeasures, each fired once.
SolverPolicy  a first solver: picks the subset of countermeasures that
              minimises expected loss + weighted operational / time / energy
              cost, by exhaustive enumeration (5 countermeasures -> <= 32
              subsets). Also returns the Pareto front (risk vs disruption vs
              energy) for inspection.

Every Decision carries its justification — the tree nodes each action covers
and the cost terms — which is what "explainable decision coverage" counts.

Countermeasures already applied stay in effect: both policies only ever add
actions (reverting is an operator decision, out of scope for v0).
"""

import itertools
from dataclasses import asdict, dataclass, field
from typing import Optional

from cyberrange.planes.defense.soar import mapping, trees

APPROVAL_MODES = ("auto", "deny")   # plus "delay:<seconds>", handled by the responder


@dataclass
class Decision:
    t: Optional[float]
    policy: str
    actions: list                      # countermeasure ids, in execution order
    covers: dict                       # action -> {"prevents": [...], "restores": [...]}
    cost_terms: dict
    rationale: str
    needs_approval: list = field(default_factory=list)
    active_impacts: list = field(default_factory=list)
    pareto: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    @property
    def explained(self):
        """Every action names at least one covered node (notify excepted) and a
        rationale is given."""
        if not self.rationale:
            return False
        return all(a == "notify" or self.covers.get(a, {}).get("prevents")
                   or self.covers.get(a, {}).get("restores") for a in self.actions)


class _Base:
    name = "base"

    def __init__(self, countermeasures, allowed=None):
        self.cms = {c.id: c for c in countermeasures}
        self.allowed = set(allowed) if allowed is not None else set(self.cms)
        self.applied = set()          # countermeasures already in effect
        self.notified = False

    def mark_applied(self, ids):
        self.applied.update(ids)

    def _order(self, ids):
        return sorted(ids, key=lambda a: (self.cms[a].order, a))

    def _covers(self, ids, nodes):
        # What each action addresses: believed nodes it prevents/restores, plus
        # the impact leaves it pre-emptively guards (a block before the plant is
        # touched is justified by the impact it prevents, even if not yet seen).
        relevant = set(nodes) | set(mapping.IMPACT_LEAVES)
        out = {}
        for a in ids:
            cm = self.cms[a]
            out[a] = {"prevents": [n for n in cm.prevents if n in relevant],
                      "restores": [n for n in cm.restores if n in relevant]}
        return out

    def _notify(self, snapshot, t, why):
        # Once a countermeasure is in effect the operator already knows.
        if self.notified or self.applied or not snapshot["nodes"]:
            return None
        self.notified = True
        return Decision(t, self.name, ["notify"], {"notify": {"prevents": [], "restores": []}},
                        {}, why, active_impacts=list(snapshot["active_impacts"]))


class RulesPolicy(_Base):
    """Static playbook: confirmed impact leaf -> fixed countermeasures."""

    name = "rules"
    PLAYBOOK = {
        # Early IT steps (observed only with the IT sensor): stop the foothold
        # and pre-emptively block the pivot before the plant is touched.
        "it_access": ["block_web_src"],
        "it_exec": ["kill_proc_tree", "block_flow"],
        # Impact leaves (OT sensor): block the flow and undo the effect.
        "setpoint_oor": ["block_flow"],          # the PLC rejects the value and recovers
        "breaker_open": ["block_flow", "restore_breaker"],
        "mode_hijack": ["block_flow", "force_auto"],
    }
    TRIGGERS = ["it_access", "it_exec"] + list(mapping.IMPACT_LEAVES)

    def decide(self, snapshot, t=None):
        nodes = snapshot["nodes"]
        confirmed = [n for n in self.TRIGGERS
                     if nodes.get(n, {}).get("state") == mapping.CONFIRMED]
        if not confirmed:
            return self._notify(snapshot, t, "suspicious activity below the confirmation "
                                "threshold: operator notified, no automatic action")
        want = []
        for node in confirmed:
            for a in self.PLAYBOOK.get(node, []):
                if a not in want:
                    want.append(a)
        new = [a for a in want if a not in self.applied and a in self.allowed]
        if not new:
            return None
        new = self._order(new)
        rationale = "; ".join(f"{node} confirmed ({', '.join(nodes[node]['classes'])}) "
                              f"-> {', '.join(self.PLAYBOOK.get(node, []))}" for node in confirmed)
        return Decision(t, self.name, new, self._covers(new, nodes), {}, rationale,
                        needs_approval=[a for a in new if self.cms[a].requires_approval],
                        active_impacts=[n for n in confirmed if n in mapping.IMPACT_LEAVES])


@dataclass
class Weights:
    op: float = 1.0          # operational disruption
    time: float = 0.05       # per second of time-to-effect (slowest action)
    energy: float = 0.5


class SolverPolicy(_Base):
    """Expected-loss minimisation over countermeasure subsets."""

    name = "solver"

    def __init__(self, countermeasures, tree, weights=None, allowed=None):
        super().__init__(countermeasures, allowed)
        self.tree = tree
        self.w = weights or Weights()
        self.impact = {n.id: n.impact for n in tree.walk() if n.impact > 0}

    # J(A) = residual + future + w.op*op + w.time*time + w.energy*energy
    def cost(self, subset, scores):
        A = set(subset) | self.applied
        restored = {n for a in A for n in self.cms[a].restores}
        prevented = {n for a in A for n in self.cms[a].prevents}
        # Impact already achieved (or under way) that nothing undoes.
        residual = sum(scores.get(n, 0.0) * imp for n, imp in self.impact.items()
                       if n in mapping.IMPACT_LEAVES and n not in restored)
        # The attacker still holds the path: further manipulation is possible
        # unless the path or the manipulations themselves are prevented.
        exposure = max((imp for n, imp in self.impact.items()
                        if n in mapping.IMPACT_LEAVES and n not in prevented), default=0.0)
        future = 0.0 if "pivot" in prevented else scores.get("pivot", 0.0) * exposure
        new = [a for a in subset if a not in self.applied]
        op = sum(self.cms[a].op_cost for a in new)
        time = max((self.cms[a].time_to_effect_s for a in new), default=0.0)
        energy = sum(self.cms[a].energy_cost for a in new)
        total = residual + future + self.w.op * op + self.w.time * time + self.w.energy * energy
        return {"residual": round(residual, 4), "future": round(future, 4),
                "op": round(op, 4), "time": round(time, 4), "energy": round(energy, 4),
                "total": round(total, 4)}

    def candidates(self):
        pool = [a for a in self.cms if a != "notify" and a in self.allowed
                and a not in self.applied]
        for k in range(len(pool) + 1):
            yield from itertools.combinations(sorted(pool), k)

    def unpaired_restores(self, subset, scores):
        """Causal pairing (from the attack-defense tree): restoring an impact
        leaf the policy believes in, without preventing the leaf or one of the
        steps that lead to it, only undoes the effect and leaves the cause in
        place. Early restores also suppress the voltage evidence that would
        later raise the belief in the path, so the path would never be cut.
        Returns the leaves restored without such a prevention — only those for
        which some allowed countermeasure could provide it."""
        A = set(subset) | self.applied
        restored = {n for a in A for n in self.cms[a].restores}
        prevented = {n for a in A for n in self.cms[a].prevents}
        preventable = {n for a in self.allowed for n in self.cms[a].prevents}
        out = []
        for leaf in sorted(restored):
            if leaf not in mapping.IMPACT_LEAVES or scores.get(leaf, 0.0) <= 0.0:
                continue
            path = [leaf] + trees.prerequisites(self.tree, leaf)
            if any(n in prevented for n in path):
                continue
            if any(n in preventable for n in path):
                out.append(leaf)
        return out

    def decide(self, snapshot, t=None):
        nodes = snapshot["nodes"]
        if not nodes:
            return None
        scores = {n: v["score"] for n, v in nodes.items()}
        evaluated = [(subset, self.cost(subset, scores)) for subset in self.candidates()
                     if not self.unpaired_restores(subset, scores)]
        best, best_cost = min(evaluated, key=lambda x: (x[1]["total"], len(x[0]), x[0]))
        # Was the pairing binding? (the unconstrained optimum restored alone)
        free = min(((s, self.cost(s, scores)) for s in self.candidates()),
                   key=lambda x: (x[1]["total"], len(x[0]), x[0]))
        paired = self.unpaired_restores(free[0], scores)
        if not best:
            return self._notify(snapshot, t, "no countermeasure is worth its cost at the "
                                f"current belief (J={best_cost['total']}): operator notified")
        new = self._order(best)
        idle = self.cost((), scores)
        rationale = (f"chosen {'+'.join(new)}: J {idle['total']} -> {best_cost['total']} "
                     f"(residual {idle['residual']}->{best_cost['residual']}, "
                     f"future {idle['future']}->{best_cost['future']}, "
                     f"op +{best_cost['op']}, energy +{best_cost['energy']}); "
                     "beliefs " + ", ".join(f"{n}={scores[n]}" for n in
                                            list(mapping.IMPACT_LEAVES) + ["pivot"]
                                            if n in scores))
        if paired:
            rationale += (f"; causal pairing: restoring {', '.join(paired)} also requires "
                          f"cutting its path (cheapest alone was {'+'.join(free[0])}, "
                          f"J={free[1]['total']})")
        return Decision(t, self.name, new, self._covers(new, nodes), best_cost, rationale,
                        needs_approval=[a for a in new if self.cms[a].requires_approval],
                        active_impacts=list(snapshot["active_impacts"]),
                        pareto=pareto_front(evaluated))


def pareto_front(evaluated):
    """Non-dominated subsets on (risk = residual + future, op, energy)."""
    pts = [(list(s), round(c["residual"] + c["future"], 4), c["op"], c["energy"])
           for s, c in evaluated]
    front = []
    for i, (s, r, o, e) in enumerate(pts):
        dominated = any((r2 <= r and o2 <= o and e2 <= e) and (r2, o2, e2) != (r, o, e)
                        for j, (_s2, r2, o2, e2) in enumerate(pts) if j != i)
        if not dominated:
            front.append({"actions": s, "risk": r, "op": o, "energy": e})
    return sorted(front, key=lambda p: (p["risk"], p["op"]))


def make_policy(kind, countermeasures, tree, approval="auto", weights=None):
    """'rules' | 'solver'. With approval 'deny', countermeasures that need an
    operator's approval are never proposed."""
    allowed = {c.id for c in countermeasures
               if not (approval == "deny" and c.requires_approval)}
    if kind == "rules":
        return RulesPolicy(countermeasures, allowed=allowed)
    if kind == "solver":
        return SolverPolicy(countermeasures, tree, weights=weights, allowed=allowed)
    raise ValueError(f"unknown policy {kind!r}")
