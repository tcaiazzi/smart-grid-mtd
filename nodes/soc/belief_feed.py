#!/usr/bin/env python3
"""belief_feed.py — what the SOC knows and believes, as events of its own SIEM.

The analytics (soc_analytics.py) reasons on a knowledge graph of the lab and
keeps a belief for every step of the attack tree, and the manager's alerts say
nothing of either: an analyst on the Wazuh dashboard sees the findings, not what
the SOC makes of them. This feed hands both to the manager as events, the way
Wazuh's own integrations do (its analysis queue), so that a rule turns each into
an alert (soc_belief_rules.xml), the indexer holds it, and the dashboard draws
the tree and the graph from them (nodes/wazuh/dashboard/*.vega.json).

One event per tree node, per graph node and per graph edge, flat: the manager's
JSON decoder keeps scalar fields, not lists of objects. An event carries its
element's place in the drawing with its state, so the latest event of every
element is the whole picture, and a view needs no other source. Everything is
sent once at the start, then only what changes. An event the manager did not
take (it starts after the SOC's node does) is sent again at the next step: the
queue says whether it was delivered, which a log file the manager tails would
not.

Copied flat onto the SOC node (the cps-soc lab), imported by soc_analytics.py
and by iris_desk.py, which reads the same tree and the same graph. Stdlib only:
the graph is taken as soar_kg.to_json gives it, not as a networkx object.
"""

import json
import socket
import time

KIND = "soc_belief"  # an attack tree node, as soc_belief_rules.xml matches it
KG_KIND = "soc_kg"  # a node or an edge of the knowledge graph
# Where the manager's analysis daemon takes events from this host's programs.
QUEUE = "/var/ossec/queue/sockets/queue"
UNKNOWN = "unknown"
# The graph is drawn in columns, one per node type, in this order.
LAYERS = ("zone", "host", "ip", "service", "flow_rule", "register")
ZONE_ORDER = ("IT", "OT", "MGMT")
# What the attack and the response make of a graph element, strongest first.
BLOCKED, ISOLATED, INVOLVED, QUIET = "blocked", "isolated", "involved", "none"
# A tree step in one of these states is taken to have happened.
HAPPENED = ("confirmed", "inferred")


# ── the attack tree ──────────────────────────────────────────────────────────
def in_effect(view):
    """The countermeasures the SOC's view says are applied and not reverted."""
    return [c for c in view.get("countermeasures") or [] if c.get("in_effect_since") is not None]


def rows(view):
    """The SOC's view (soc_analytics.Service.view) as one flat event per tree
    node, parents before children: ``order`` is the node's place in that walk,
    which keeps siblings in the tree's own order."""
    belief = {n["node"]: n for n in view.get("tree") or []}
    countered = {}  # node -> the countermeasures in effect that prevent or undo it
    for cm in in_effect(view):
        for node in (cm.get("prevents") or []) + (cm.get("restores") or []):
            countered.setdefault(node, set()).add(cm["id"])
    out = []

    def walk(n, parent):
        seen = belief.get(n["id"]) or {}
        row = {
            "kind": KIND,
            "node": n["id"],
            "order": len(out),
            "label": n.get("label") or n["id"],
            "gate": n.get("gate") or "LEAF",
            "belief": seen.get("state") or UNKNOWN,
            "score": round(float(seen.get("belief") or 0.0), 2),
        }
        # Absent rather than empty: the root is the node with no parent, and
        # the decoder would keep an empty string as a parent named "".
        if parent:
            row["parent"] = parent
        if n.get("attck"):
            row["attck"] = n["attck"]
        if n["id"] in countered:
            row["defended_by"] = ", ".join(sorted(countered[n["id"]]))
        out.append(row)
        for child in n.get("children") or []:
            walk(child, n["id"])

    if view.get("structure"):
        walk(view["structure"], None)
    return out


def steps(view):
    """{tree node id: its node in the view's structure}."""
    out = {}

    def walk(n):
        out[n["id"]] = n
        for child in n.get("children") or []:
            walk(child)

    if view.get("structure"):
        walk(view["structure"])
    return out


def earlier(view, ident):
    """The steps that come before ``ident``, nearest first: the earlier
    siblings, with their subtrees, in every AND gate above it."""
    out = []

    def subtree(n):
        return [n["id"]] + [i for c in n.get("children") or [] for i in subtree(c)]

    def walk(n):
        """True when ``ident`` is in ``n``'s subtree; collects on the way up."""
        if n["id"] == ident:
            return True
        children = n.get("children") or []
        for i, child in enumerate(children):
            if walk(child):
                if n.get("gate") == "AND":
                    for sibling in reversed(children[:i]):
                        out.extend(reversed(subtree(sibling)))
                return True
        return False

    if view.get("structure"):
        walk(view["structure"])
    return out


# ── the knowledge graph ──────────────────────────────────────────────────────
class Graph:
    """The knowledge graph as soar_kg.to_json gives it (node-link data), indexed
    for the few questions asked of it here."""

    def __init__(self, kg):
        self.nodes = {n["id"]: n for n in kg.get("nodes") or []}
        self.edges = [(e["source"], e["rel"], e["target"]) for e in kg.get("links") or []]
        self._in, self._out = {}, {}
        for source, rel, target in self.edges:
            self._in.setdefault((target, rel), []).append(source)
            self._out.setdefault((source, rel), []).append(target)

    def out(self, ident, rel):
        """The nodes ``ident`` points at with relation ``rel``."""
        return [self.nodes[t] for t in self._out.get((ident, rel), [])]

    def hosts(self):
        return sorted(n["name"] for n in self.nodes.values() if n["type"] == "host")

    def host_of(self, ident):
        """The name of the host a graph element is on: a host itself, the one
        with that address or service, the one whose service exposes a register.
        None for what is on no host an attack lands on (a zone, a rule)."""
        n = self.nodes.get(ident) or {}
        if n.get("type") == "host":
            return n["name"]
        if n.get("type") in ("ip", "service"):
            return n.get("host")
        if n.get("type") == "register":
            for service in self._in.get((ident, "exposes"), []):
                return self.nodes[service].get("host")
        return None

    def layers(self):
        """The nodes in the order they are drawn: one list per LAYERS type."""
        hosts = self.hosts()

        def owner(n):
            return hosts.index(n["host"]) if n.get("host") in hosts else len(hosts)

        def zone(n):
            name = n.get("name") or ""
            return (ZONE_ORDER.index(name) if name in ZONE_ORDER else len(ZONE_ORDER), name)

        keys = {
            "zone": zone,
            "host": lambda n: n["name"],
            "ip": lambda n: (owner(n), n["addr"]),
            "service": lambda n: (owner(n), n["name"]),
            "flow_rule": lambda n: n.get("order") or 0,
            "register": lambda n: (n["kind"] != "holding", n["addr"]),
        }
        return [
            sorted((n for n in self.nodes.values() if n["type"] == kind), key=keys[kind])
            for kind in LAYERS
        ]


def step_hosts(graph, view, ident):
    """The hosts an attack step links: the ones it is aimed at, and where it
    comes from — the hosts of the nearest earlier step aimed elsewhere, or,
    with none, the hosts the SOC holds implicated (the sources it has seen)."""
    tree = steps(view)

    def aimed(step):
        hosts = {graph.host_of(t) for t in (tree.get(step) or {}).get("targets") or []}
        return hosts - {None}

    own = aimed(ident)
    for step in earlier(view, ident):
        origin = aimed(step) - own
        if origin:
            return sorted(own | origin)
    return sorted(own | set(view.get("hosts_implicated") or []))


def label_of(n):
    kind = n["type"]
    if kind == "ip":
        return n["addr"]
    if kind == "service":
        return f"{n['host']}/{n['name']}"
    if kind == "register":
        return f"{'HR' if n['kind'] == 'holding' else 'IR'}{n['addr']} {n['name']}"
    if kind == "flow_rule":
        return f"{n['action']} {n.get('proto') or 'any'}/{n.get('dport') or '*'}"
    return n.get("name") or n["id"]


def detail_of(n):
    kind = n["type"]
    if kind == "host":
        return f"{n.get('role') or 'host'}, image {n.get('image') or '-'}"
    if kind == "ip":
        return f"{n['iface']} of {n['host']}, /{n['prefix']}"
    if kind == "service":
        return f"{n.get('app') or n['name']} on {n['proto']}/{n['port']}"
    if kind == "register":
        if n["kind"] == "holding":
            return f"holding register, {n.get('lo')}..{n.get('hi')}"
        return f"input register, {n.get('unit') or '-'}"
    if kind == "flow_rule":
        return f"{n.get('src') or 'any'} -> {n.get('dst') or 'any'}"
    return kind


def kg_state(graph, view):
    """What the SOC's view makes of the graph: {node id: BLOCKED | ISOLATED |
    INVOLVED} and {host node id: the countermeasures in effect that run there}.

    Involved is every host the SOC holds implicated and everything a step it
    takes to have happened, or an impact it holds active, is aimed at. A
    countermeasure is read by what it is (its D3FEND technique), not by its
    name: traffic filtering blocks the flow rules the steps it prevents go
    through, isolation cuts its host off."""
    tree = steps(view)
    state = {n["node"]: n.get("state") for n in view.get("tree") or []}
    involved = {f"host:{h}" for h in view.get("hosts_implicated") or []}
    active = set(view.get("active_impacts") or [])
    for ident, step in tree.items():
        if state.get(ident) in HAPPENED or ident in active:
            involved.update(step.get("targets") or [])
    blocked, isolated, defended = set(), set(), {}
    for cm in in_effect(view):
        technique = cm.get("d3fend") or ""
        if "Traffic Filtering" in technique:
            for ident in cm.get("prevents") or []:
                for target in (tree.get(ident) or {}).get("targets") or []:
                    if (graph.nodes.get(target) or {}).get("type") == "flow_rule":
                        blocked.add(target)
        if "Isolation" in technique and cm.get("machine"):
            isolated.add(f"host:{cm['machine']}")
        if cm.get("machine"):
            defended.setdefault(f"host:{cm['machine']}", set()).add(cm["id"])
    status = {n: INVOLVED for n in involved if n in graph.nodes}
    status.update({n: ISOLATED for n in isolated if n in graph.nodes})
    status.update({n: BLOCKED for n in blocked})
    return status, defended


def kg_rows(graph, view):
    """The knowledge graph as one flat event per node and per edge. A node
    says where it is drawn (``layer``, its type's column, and ``row`` in it)
    and what the attack and the response make of it; an edge names its ends."""
    status, defended = kg_state(graph, view)
    out = []
    for layer, nodes in enumerate(graph.layers()):
        for row, n in enumerate(nodes):
            event = {
                "kind": KG_KIND,
                "element": "node",
                "kg_id": n["id"],
                "kg_type": n["type"],
                "layer": layer,
                "row": row,
                "label": label_of(n),
                "detail": detail_of(n),
                "status": status.get(n["id"], QUIET),
            }
            if n.get("sensitive"):
                event["sensitive"] = "yes"
            if n["id"] in defended:
                event["defended_by"] = ", ".join(sorted(defended[n["id"]]))
            out.append(event)
    for source, rel, target in graph.edges:
        cut = BLOCKED in (status.get(source), status.get(target))
        out.append(
            {
                "kind": KG_KIND,
                "element": "edge",
                "kg_id": f"{source}>{rel}>{target}",
                "kg_src": source,
                "kg_dst": target,
                "rel": rel,
                "status": BLOCKED if cut else QUIET,
            }
        )
    return out


# ── delivery ─────────────────────────────────────────────────────────────────
def to_manager(line, queue=QUEUE):
    """One event into the manager's analysis queue: "1:<location>:<log>", the
    format its own modules use. Raises OSError while the manager is not up."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect(queue)
        s.send(f"1:{KIND}:{line}".encode())
    finally:
        s.close()


class BeliefFeed:
    """Sends the tree's nodes, and with ``kg`` (soar_kg.to_json) the graph's
    nodes and edges, whose state changed since they were last delivered.
    ``path`` keeps what was delivered, for the run's record; ``send`` (line)
    raises OSError when the event could not be handed over."""

    def __init__(self, path=None, send=to_manager, clock=time.time, log=print, kg=None):
        self.send, self.clock, self.log = send, clock, log
        self.graph = Graph(kg) if kg else None
        self._f = open(path, "w") if path else None
        self._delivered = {}  # (kind, element id) -> the row the manager last took
        self._down = False

    def publish(self, view):
        events = rows(view)
        if self.graph is not None:
            events += kg_rows(self.graph, view)
        for row in events:
            key = (row["kind"], row.get("node") or row.get("kg_id"))
            if self._delivered.get(key) == row:
                continue
            try:
                self.send(json.dumps(row))
            except OSError as e:
                # Said once per outage: the feed retries at every step.
                if not self._down:
                    self.log(f"belief feed: the manager does not take events yet: {e}")
                self._down = True
                return
            self._down = False
            self._delivered[key] = row
            if self._f:
                self._f.write(json.dumps({"t": round(self.clock(), 3), **row}) + "\n")
                self._f.flush()

    def close(self):
        if self._f:
            self._f.close()
            self._f = None
