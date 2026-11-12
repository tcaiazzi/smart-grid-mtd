"""tree_doc.py — reading an attack tree as a document.

The attacker plans on what it knows of the target: an attack tree handed to it
as data (the ``attack_tree`` of a run's tree.json), where every node already
says whether it is feasible. It does not run the defender's code to find out.

A node is a dict: ``id``, ``gate`` (AND | OR | LEAF), ``children``, ``impact``,
``attck``, ``feasible``. AND children are ordered steps; OR children are
alternatives.
"""

AND = "AND"


def walk(node):
    yield node
    for child in node.get("children") or []:
        yield from walk(child)


def index(root):
    return {n["id"]: n for n in walk(root)}


def feasible(node):
    """Whether the step can be reached on the lab the tree was written for. A
    document without the flag predates it: everything in it was assumed open."""
    return bool(node.get("feasible", True))


def prerequisites(root, node_id):
    """Steps that must already have succeeded for ``node_id`` to be reached:
    the earlier siblings in every AND ancestor, with their whole subtrees."""
    parent = {c["id"]: n for n in walk(root) for c in n.get("children") or []}
    out, cur = [], index(root)[node_id]
    while cur["id"] in parent:
        p = parent[cur["id"]]
        if p.get("gate") == AND:
            for sibling in p["children"][: p["children"].index(cur)]:
                out.extend(n["id"] for n in walk(sibling))
        cur = p
    return out
