#!/usr/bin/env python3
"""soar_trees.py — the model of an attack-defense tree: the attack tree's nodes,
the countermeasures that annotate them, and the operations both the SOC and the
attacker run on a tree (index, feasibility, prerequisites, the document).

Copied flat onto the SOC node and onto the attacker; stdlib + networkx (through
soar_kg). The tree of a lab is generated from its knowledge graph by
attack_graph.py.

A tree's steps reference knowledge-graph nodes and their preconditions are
checked against the graph (``feasible``): change the graph — e.g. drop the
boundary allow rule — and the branch that needs it becomes infeasible.

Gates: AND children are ordered steps that must all succeed; OR children are
alternatives. ATT&CK ids are a first mapping and carry ``review`` notes where
they still need validation.

Countermeasures split their effect in two, because a response has two jobs:
    prevents   nodes the action stops from (re)occurring  (e.g. block a flow)
    restores   impact nodes the action undoes             (e.g. back to AUTO)
Commands are shell strings run on ``machine`` (a lab host name).
"""

from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

import soar_kg as kgmod

AND, OR, LEAF = "AND", "OR", "LEAF"


@dataclass
class Node:
    id: str
    label: str
    gate: str = LEAF
    children: list = field(default_factory=list)
    attck: Optional[str] = None  # ATT&CK (Enterprise or ICS) technique id
    attck_name: Optional[str] = None
    targets: list = field(default_factory=list)  # knowledge-graph node ids
    impact: float = 0.0  # loss weight if this node is achieved
    observable: bool = True  # can the OT sensor see this step at all?
    review: Optional[str] = None  # open question on the mapping
    kind: Optional[str] = None  # the step it is (techniques.py): the id, unless it recurs
    precondition: Optional[Callable] = field(default=None, repr=False)
    # What the step needs of the graph to be carried out (a graph -> bool): a
    # response that makes it false prevents the step. Not its precondition — the
    # foothold on a host stays possible when that host is cut off the plant.
    uses: Optional[Callable] = field(default=None, repr=False)

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def to_dict(self, g=None):
        """With a graph, every node also says whether it is ``feasible`` on it:
        a reader of the document (the dashboard, an attacker's planner) cannot
        evaluate a precondition, which is code."""
        skip = ("children", "precondition", "uses")
        d = {k: v for k, v in asdict(self).items() if k not in skip}
        if g is not None:
            d["feasible"] = feasible(self, g)
        d["children"] = [c.to_dict(g) for c in self.children]
        return d


@dataclass
class Countermeasure:
    id: str
    label: str
    d3fend: Optional[str]  # D3FEND technique name (id to be checked)
    machine: Optional[str]  # lab host the commands run on
    apply: list
    revert: list
    prevents: list = field(default_factory=list)
    restores: list = field(default_factory=list)
    time_to_effect_s: float = 1.0  # from the request to its effect
    op_cost: float = 0.0  # disturbance of running it once, 0..1 (what it cuts is in ``cuts``)
    energy_cost: float = 0.0  # relative energy cost, 0..1
    requires_approval: bool = False
    order: int = 50  # execution order: preventive first
    effect: list = field(
        default_factory=list
    )  # the graph while it is in effect (soar_kg.with_effects)
    cuts: list = field(
        default_factory=list
    )  # functions of the lab lost meanwhile (soar_kg.functions)
    kind: Optional[str] = None  # the response it is: the id, unless it recurs

    def to_dict(self):
        return asdict(self)


# From the SOC's request to its outcome on the host: the manager's active
# response to the agent, the same way for every countermeasure. A round figure
# for what the lab measures (a campaign's summary, table "Countermeasure
# times": median 0.07 s, three quarters under 0.26 s).
DISPATCH_S = 0.1

# What a function of the lab weighs when a response cuts it, by kind (the
# prefix of its id, soar_kg.functions): the operator's control of one register,
# a host's presence on one network.
FUNCTION_WEIGHTS = {kgmod.WRITE: 0.25, kgmod.PRESENCE: 0.3}


def disruption(functions):
    """Operational cost of losing ``functions``. Over a set: a function two
    responses both cut is lost once, and is charged once."""
    return sum(FUNCTION_WEIGHTS[f.split(":", 1)[0]] for f in set(functions))


def charged(g, cms):
    """``cms`` with what each cuts on ``g``: the functions the graph has, and
    no longer has while the countermeasure is in effect."""
    before = kgmod.functions(g)
    for cm in cms:
        if cm.effect:
            cm.cuts = sorted(before - kgmod.functions(kgmod.with_effects(g, cm.effect)))
    return cms


# ── Tree helpers ─────────────────────────────────────────────────────────────


def index(root):
    return {n.id: n for n in root.walk()}


def parents(root):
    out = {}
    for n in root.walk():
        for c in n.children:
            out[c.id] = n
    return out


def leaves(root):
    return [n for n in root.walk() if n.gate == LEAF]


def feasible(node, g):
    """Node achievable on graph ``g``: a leaf by its precondition, AND when all
    children are, OR when any child is."""
    if node.gate == LEAF:
        return node.precondition(g) if node.precondition else True
    results = [feasible(c, g) for c in node.children]
    return all(results) if node.gate == AND else any(results)


def prerequisites(root, node_id):
    """Steps that must already have succeeded for ``node_id`` to be reached:
    the earlier siblings in every AND ancestor (with their whole subtrees)."""
    par, idx = parents(root), index(root)
    out, cur = [], idx[node_id]
    while cur.id in par:
        p = par[cur.id]
        if p.gate == AND:
            for sib in p.children[: p.children.index(cur)]:
                out.extend(n.id for n in sib.walk())
        cur = p
    return out


def ancestors(root, node_id):
    par, out, cur = parents(root), [], node_id
    while cur in par:
        cur = par[cur].id
        out.append(cur)
    return out


def to_json(root, countermeasures, g=None):
    """Attack-defense tree: the attack tree plus, per node, the countermeasures
    that prevent or restore it (what WP4 consumes for explanations). ``g`` adds
    each node's feasibility on that graph."""
    defense = {}
    for cm in countermeasures:
        for nid in cm.prevents:
            defense.setdefault(nid, {"prevented_by": [], "restored_by": []})["prevented_by"].append(
                cm.id
            )
        for nid in cm.restores:
            defense.setdefault(nid, {"prevented_by": [], "restored_by": []})["restored_by"].append(
                cm.id
            )
    return {
        "attack_tree": root.to_dict(g),
        "defense": defense,
        "countermeasures": [c.to_dict() for c in countermeasures],
    }
