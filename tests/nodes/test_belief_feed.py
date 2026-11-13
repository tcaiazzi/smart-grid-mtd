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
