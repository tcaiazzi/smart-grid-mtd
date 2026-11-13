#!/usr/bin/env python3
"""belief_feed.py — the SOC's belief on the attack tree, as events of its own SIEM.

The analytics (soc_analytics.py) keeps a belief for every step of the attack
tree, and the manager's alerts say nothing of it: an analyst on the Wazuh
dashboard sees the findings, not what the SOC makes of them. This feed hands the
belief to the manager as events, the way Wazuh's own integrations do (its
analysis queue), so that a rule turns each into an alert (soc_belief_rules.xml),
the indexer holds it, and the dashboard draws the tree from it
(nodes/wazuh/dashboard/attack-tree.vega.json).

One event per tree node, flat: the manager's JSON decoder keeps scalar fields,
not lists of objects. An event carries the node's place in the tree with its
belief, so the latest event of every node is the whole tree, and the view needs
no other source. Every node is sent once at the start, then only the ones that
change. An event the manager did not take (it starts after the SOC's node does)
is sent again at the next step: the queue says whether it was delivered, which
a log file the manager tails would not.

Copied flat onto the SOC node (the cps-soc lab), imported by soc_analytics.py.
Stdlib only.
"""

import json
import socket
import time

KIND = "soc_belief"  # what soc_belief_rules.xml matches
# Where the manager's analysis daemon takes events from this host's programs.
QUEUE = "/var/ossec/queue/sockets/queue"
UNKNOWN = "unknown"


def rows(view):
    """The SOC's view (soc_analytics.Service.view) as one flat event per tree
    node, parents before children: ``order`` is the node's place in that walk,
    which keeps siblings in the tree's own order."""
    belief = {n["node"]: n for n in view.get("tree") or []}
    countered = {}  # node -> the countermeasures in effect that prevent or undo it
    for cm in view.get("countermeasures") or []:
        if cm.get("in_effect_since") is None:
            continue
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
    """Sends the tree's nodes whose belief changed since they were last
    delivered. ``path`` keeps what was delivered, for the run's record;
    ``send`` (line) raises OSError when the event could not be handed over."""

    def __init__(self, path=None, send=to_manager, clock=time.time, log=print):
        self.send, self.clock, self.log = send, clock, log
        self._f = open(path, "w") if path else None
        self._delivered = {}  # node -> the row the manager last took
        self._down = False

    def publish(self, view):
        for row in rows(view):
            if self._delivered.get(row["node"]) == row:
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
            self._delivered[row["node"]] = row
            if self._f:
                self._f.write(json.dumps({"t": round(self.clock(), 3), **row}) + "\n")
                self._f.flush()

    def close(self):
        if self._f:
            self._f.close()
            self._f = None
