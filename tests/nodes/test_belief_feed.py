"""The feed of the SOC's belief on the attack tree to its SIEM (nodes/soc/
belief_feed.py).

The Wazuh dashboard of the cps-soc lab draws the attack tree from these events
alone: each must say where its node is in the tree, be flat enough for the
manager's JSON decoder, and reach the manager even when it starts after the
SOC's analytics does.

Run: `.venv/bin/python -m pytest tests/nodes/test_belief_feed.py`
"""

import json
import os
import tempfile
import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)

import belief_feed as B  # noqa: E402  (flat guest import, needs the path set above)
import soc_analytics  # noqa: E402  (flat guest import)

from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402  (after the guest path)


def leaf(ident, label, attck=None):
    return {"id": ident, "label": label, "gate": "LEAF", "attck": attck, "children": []}


VIEW = {
    "structure": {
        "id": "impact",
        "label": "Impact",
        "gate": "OR",
        "attck": None,
        "children": [
            {
                "id": "via_hmi",
                "label": "Through the HMI",
                "gate": "AND",
                "attck": None,
                "children": [leaf("it_access", "Web access", "T1190"), leaf("pivot", "Pivot")],
            },
            leaf("direct_ot", "Direct"),
        ],
    },
    "tree": [{"node": "it_access", "state": "confirmed", "belief": 0.923}],
    "countermeasures": [
        {"id": "block_flow", "prevents": ["pivot"], "restores": [], "in_effect_since": 3.0},
        {"id": "isolate_hmi", "prevents": ["it_access"], "restores": [], "in_effect_since": None},
    ],
}


class Rows(unittest.TestCase):
    def setUp(self):
        self.rows = {r["node"]: r for r in B.rows(VIEW)}

    def test_every_node_is_there_before_the_soc_believes_anything(self):
        rows = B.rows({"structure": VIEW["structure"]})
        self.assertEqual(
            [r["node"] for r in rows],
            ["impact", "via_hmi", "it_access", "pivot", "direct_ot"],
            "a step with no belief yet is missing: the tree is drawn with a hole",
        )
        self.assertEqual({r["belief"] for r in rows}, {B.UNKNOWN})

    def test_a_row_places_its_node_in_the_tree(self):
        self.assertNotIn("parent", self.rows["impact"], "the view's root is the node with none")
        self.assertEqual(self.rows["pivot"]["parent"], "via_hmi")
        self.assertEqual(self.rows["direct_ot"]["parent"], "impact")
        order = [r["order"] for r in B.rows(VIEW)]
        self.assertEqual(order, sorted(order), "siblings would be drawn out of the tree's order")

    def test_a_row_carries_the_belief_and_the_technique(self):
        seen = self.rows["it_access"]
        self.assertEqual(
            (seen["belief"], seen["score"], seen["attck"]), ("confirmed", 0.92, "T1190")
        )
        self.assertNotIn("attck", self.rows["pivot"])

    def test_only_a_countermeasure_in_effect_counters_a_step(self):
        self.assertEqual(self.rows["pivot"]["defended_by"], "block_flow")
        self.assertNotIn("defended_by", self.rows["it_access"], "isolate_hmi was never applied")

    def test_a_row_is_flat(self):
        # The manager's JSON decoder keeps scalars; a list of objects is lost.
        for row in self.rows.values():
            for field, value in row.items():
                self.assertIsInstance(value, (str, int, float), f"{row['node']}.{field}")
            self.assertEqual(row["kind"], B.KIND)

    def test_the_labs_own_view_feeds_its_whole_tree(self):
        """Against the analytics' real view: a field renamed there would empty
        the dashboard with no error anywhere."""
        g = soc_analytics.kgmod.build_kg(cps_inv.inventory())
        engine = soc_analytics.ResponseEngine("rules", g, it=True)
        service = soc_analytics.Service(engine, None, None, lambda *a, **k: None)
        service._in_effect["block_flow"] = 5.0
        rows = B.rows(service.view())
        self.assertEqual(len(rows), len(list(engine.tree.walk())))
        self.assertEqual(sum("parent" not in r for r in rows), 1, "the tree has one root")
        self.assertIn(
            "block_flow",
            {r.get("defended_by") for r in rows},
            "the view no longer says what a countermeasure prevents",
        )


class KnowledgeGraph(unittest.TestCase):
    """The lab's own graph and tree, with the SOC's view set by hand."""

    def setUp(self):
        g = soc_analytics.kgmod.build_kg(cps_inv.inventory())
        engine = soc_analytics.ResponseEngine("rules", g, it=True)
        self.service = soc_analytics.Service(engine, None, None, lambda *a, **k: None)
        self.g, self.kg = g, soc_analytics.kgmod.to_json(g)
        self.graph = B.Graph(self.kg)

    def view(self, states=(), implicated=(), applied=(), active=()):
        for cm in applied:
            self.service._in_effect[cm] = 1.0
        view = self.service.view()
        view["tree"] = [{"node": n, "state": s, "belief": 0.9} for n, s in states]
        view["hosts_implicated"], view["active_impacts"] = list(implicated), list(active)
        return view

    def status(self, view):
        return {r["kg_id"]: r["status"] for r in B.kg_rows(self.graph, view)}

    def test_every_node_and_edge_is_an_event_and_flat(self):
        rows = B.kg_rows(self.graph, self.view())
        nodes = [r for r in rows if r["element"] == "node"]
        edges = [r for r in rows if r["element"] == "edge"]
        self.assertEqual(len(nodes), self.g.number_of_nodes())
        self.assertEqual(len(edges), self.g.number_of_edges())
        self.assertEqual(len({r["kg_id"] for r in rows}), len(rows), "two elements, one event")
        for row in rows:
            self.assertEqual(row["kind"], B.KG_KIND)
            for field, value in row.items():
                self.assertIsInstance(value, (str, int, float), f"{row['kg_id']}.{field}")

    def test_no_two_nodes_are_drawn_in_one_place(self):
        nodes = [r for r in B.kg_rows(self.graph, self.view()) if r["element"] == "node"]
        places = [(r["layer"], r["row"]) for r in nodes]
        self.assertEqual(len(set(places)), len(places), "a node is drawn over another")
        for r in nodes:
            self.assertEqual(B.LAYERS[r["layer"]], r["kg_type"], "a node in another type's column")

    def test_an_edge_joins_two_nodes_that_are_sent(self):
        rows = B.kg_rows(self.graph, self.view())
        sent = {r["kg_id"] for r in rows if r["element"] == "node"}
        for r in rows:
            if r["element"] == "edge":
                self.assertLessEqual({r["kg_src"], r["kg_dst"]}, sent, "an edge to nowhere")

    def test_a_quiet_lab_has_nothing_marked(self):
        self.assertEqual(set(self.status(self.view()).values()), {B.QUIET})

    def test_what_the_attack_touches_is_involved(self):
        marked = self.status(self.view(states=[("breaker_open", "confirmed")], implicated=["hmi"]))
        switch = next(i for i, n in self.graph.nodes.items() if n.get("name") == "switch_cmd")
        self.assertEqual(marked["host:hmi"], B.INVOLVED)
        self.assertEqual(marked[switch], B.INVOLVED, "the register the step writes")
        self.assertEqual(marked["host:plc"], B.QUIET)
        # A step only suspected has not happened; an impact held active has.
        self.assertEqual(
            self.status(self.view(states=[("breaker_open", "suspected")]))[switch], B.QUIET
        )
        active = self.view(states=[("breaker_open", "suspected")], active=["breaker_open"])
        self.assertEqual(self.status(active)[switch], B.INVOLVED)

    def test_filtering_the_flow_blocks_its_rule_and_isolating_cuts_the_host(self):
        marked = self.status(self.view(applied=["block_flow"]))
        (rule,) = [i for i, n in self.graph.nodes.items() if n["type"] == "flow_rule"]
        self.assertEqual(marked[rule], B.BLOCKED)
        cut = [i for i, s in marked.items() if s == B.BLOCKED and ">" in i]
        self.assertEqual(len(cut), 3, "the rule's edges (enforces, src, dst) are not shown cut")
        rows = {r["kg_id"]: r for r in B.kg_rows(self.graph, self.view())}
        self.assertEqual(rows["host:firewall"]["defended_by"], "block_flow")
        self.assertEqual(self.status(self.view(applied=["isolate_hmi"]))["host:hmi"], B.ISOLATED)

    def test_a_countermeasure_that_filters_nothing_blocks_no_rule(self):
        # kill_proc_tree prevents the pivot too, whose path the rule is on.
        marked = self.status(self.view(applied=["kill_proc_tree", "force_auto"]))
        self.assertNotIn(B.BLOCKED, marked.values())
        self.assertNotIn(B.ISOLATED, marked.values())

    def test_a_graph_element_is_on_the_host_an_attack_lands_on(self):
        (rule,) = [i for i, n in self.graph.nodes.items() if n["type"] == "flow_rule"]
        self.assertEqual(self.graph.host_of("svc:hmi/diag-http"), "hmi")
        self.assertEqual(self.graph.host_of("reg:1:hr:0"), "engine", "the plant exposes it")
        self.assertEqual(self.graph.host_of("host:plc"), "plc")
        self.assertIsNone(self.graph.host_of(rule), "a rule is enforced, not attacked")

    def test_a_step_links_where_it_lands_and_where_it_comes_from(self):
        view = self.view(implicated=["attacker"])
        hosts = lambda step: B.step_hosts(self.graph, view, step)  # noqa: E731
        self.assertEqual(hosts("it_access"), ["attacker", "hmi"], "the source the SOC saw")
        self.assertEqual(hosts("pivot"), ["engine", "hmi"])
        self.assertEqual(hosts("breaker_open"), ["engine", "hmi"], "not straight from the source")

    def test_the_feed_sends_the_graph_once_then_only_what_changes(self):
        sent = []
        feed = B.BeliefFeed(None, send=lambda line: sent.append(json.loads(line)), kg=self.kg)
        feed.publish(self.view())
        graph = [r for r in sent if r["kind"] == B.KG_KIND]
        self.assertEqual(len(graph), self.g.number_of_nodes() + self.g.number_of_edges())
        self.assertEqual(len(sent) - len(graph), len(list(self.service.engine.tree.walk())))
        before = len(sent)
        feed.publish(self.view())
        self.assertEqual(len(sent), before, "an unchanged graph is sent again at every step")
        feed.publish(self.view(implicated=["hmi"]))
        self.assertEqual([r["kg_id"] for r in sent[before:]], ["host:hmi"])


class Feed(unittest.TestCase):
    def setUp(self):
        self.sent, self.logged, self.up = [], [], True

        def send(line):
            if not self.up:
                raise OSError("no manager")
            self.sent.append(json.loads(line))

        self.feed = B.BeliefFeed(None, send=send, log=self.logged.append)

    def test_the_whole_tree_once_then_only_what_changes(self):
        self.feed.publish(VIEW)
        self.assertEqual(len(self.sent), 5)
        self.feed.publish(VIEW)
        self.assertEqual(len(self.sent), 5, "an unchanged tree floods the SIEM at every step")
        suspected = {"node": "pivot", "state": "suspected", "belief": 0.4}
        later = dict(VIEW, tree=VIEW["tree"] + [suspected])
        self.feed.publish(later)
        self.assertEqual([r["node"] for r in self.sent[5:]], ["pivot"])

    def test_a_manager_not_up_yet_is_retried_and_said_once(self):
        self.up = False
        self.feed.publish(VIEW)
        self.feed.publish(VIEW)
        self.assertEqual(self.sent, [])
        self.assertEqual(len(self.logged), 1, "one line per step would bury the SOC's log")
        self.up = True
        self.feed.publish(VIEW)
        self.assertEqual(len(self.sent), 5, "what the manager missed at its start is never drawn")

    def test_what_was_delivered_is_kept_for_the_runs_record(self):
        path = os.path.join(tempfile.mkdtemp(prefix="belief-"), "soc_belief.jsonl")
        feed = B.BeliefFeed(path, send=lambda line: None, clock=lambda: 12.5)
        feed.publish(VIEW)
        feed.close()
        with open(path) as f:
            rows = [json.loads(line) for line in f]
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows[0]["t"], 12.5)


if __name__ == "__main__":
    unittest.main()
