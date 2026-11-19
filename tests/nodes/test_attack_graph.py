"""The attack tree generator (nodes/common/attack_graph.py) where a step recurs:
a lab with two HMIs, each a way in, and a plant of two feeders. On the lab every
scenario runs the generated tree is the one frozen in tests/snapshots/tree-cps.json
(tests/nodes/test_tree_snapshot.py); here, what the same generator does when
the graph has more than one of something — and what the SOC's belief and its
rules make of a tree like that.

Run: `.venv/bin/python -m pytest tests/nodes/test_attack_graph.py`.
"""

import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)

import attack_graph as ag  # noqa: E402  (flat guest imports, need the path set above)
import ot_registers as reg  # noqa: E402
import soar_kg as kg  # noqa: E402
import soar_mapping as mapping  # noqa: E402
import soar_policy as policy  # noqa: E402
import soar_trees as trees  # noqa: E402

from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402
from cyberrange.scenarios.cps import lab as L  # noqa: E402

HMIB_IP = "10.10.0.21"


def two_ways_two_feeders():
    d = L.default_spec()
    hosts = list(d.hosts)
    at = [h.name for h in hosts].index("hmi") + 1
    web = L.Service("diag-http", "tcp", L.APP_PORT, "http")
    hosts.insert(at, L.Host("hmib", "hmi", [L.Nic(L.IT, 21), L.Nic(L.MGMT, 31)], [web], unit=2))
    spec = L.LabSpec(
        name="cps",
        zones=d.zones,
        hosts=tuple(hosts),
        boundary=d.boundary,
        flows=(*d.flows, L.Flow("hmib", "engine", "modbus")),
    )
    plant = reg.plant()
    plant["feeders"].append(dict(plant["feeders"][0], unit=2))
    return kg.build_kg(cps_inv.inventory(spec, plant=plant))


class Recurring(unittest.TestCase):
    def setUp(self):
        self.g = two_ways_two_feeders()
        self.tree = ag.attack_tree(self.g)
        self.idx = trees.index(self.tree)
        self.cms = {c.id: c for c in ag.countermeasures(self.g)}

    def test_a_way_in_per_host_an_action_per_feeder(self):
        self.assertIn("via_hmi", self.idx)
        self.assertIn("via_hmib", self.idx)
        self.assertEqual(len(self.idx), len(list(self.tree.walk())), "duplicate node ids")
        breaker = [n for n in self.tree.walk() if n.kind == "breaker_open"]
        self.assertEqual(
            sorted(n.id for n in breaker),
            ["breaker_open@hmi:u1", "breaker_open@hmi:u2", "breaker_open@hmib:u1",
             "breaker_open@hmib:u2"],
        )  # fmt: skip
        self.assertEqual(
            self.idx["breaker_open@hmib:u2"].targets, [kg.reg_id(2, "hr", reg.HR_SWITCH_CMD)]
        )

    def test_each_way_s_pivot_needs_its_own_flow(self):
        self.assertTrue(trees.feasible(self.idx["via_hmib"], self.g))
        rules = self.idx["pivot@hmib"].targets[1:]
        self.assertEqual(len(rules), 1, "the pivot names every rule, not the one it goes through")

    def test_a_block_per_way_preventing_that_way_only(self):
        block = self.cms["block_flow@hmib"]
        self.assertEqual(block.kind, "block_flow")
        self.assertIn("pivot@hmib", block.prevents)
        self.assertNotIn("pivot@hmi", block.prevents)
        self.assertIn(f"-s {HMIB_IP} ", block.apply[0])

    def test_a_restore_per_feeder_undoing_that_feeder_s_impacts(self):
        restore = self.cms["restore_breaker@u2"]
        self.assertEqual(
            sorted(restore.restores),
            ["breaker_chatter@hmi:u2", "breaker_chatter@hmib:u2", "breaker_open@hmi:u2",
             "breaker_open@hmib:u2"],
        )  # fmt: skip
        self.assertIn("--unit=2", restore.apply[0], "the response would re-close feeder 1")
        self.assertNotIn("--unit", self.cms["restore_breaker@u1"].apply[0])

    def test_the_soc_places_a_finding_on_its_feeder_and_its_way(self):
        st = mapping.CampaignState(self.tree, self.g)
        finding = {
            "kind": "ot_finding",
            "t": 1.0,
            "klass": "policy_violation",
            "detector": "rules",
            "confidence": 0.95,
            "entities": {"src": HMIB_IP, "unit": 2, "register": 1, "name": "switch_cmd"},
            "evidence": {"value": 1},
        }
        self.assertEqual(st.update(finding), ["breaker_open@hmib:u2"])
        snap = st.snapshot(1.0)
        self.assertEqual(snap["active_impacts"], ["breaker_open@hmib:u2"])
        self.assertIn("hmib", snap["hosts_implicated"])

    def test_the_rules_answer_on_that_feeder_and_that_way(self):
        st = mapping.CampaignState(self.tree, self.g)
        st.update({
            "kind": "ot_finding", "t": 1.0, "klass": "policy_violation", "detector": "rules",
            "confidence": 0.95, "evidence": {"value": 1},
            "entities": {"src": HMIB_IP, "unit": 2, "register": 1, "name": "switch_cmd"},
        })  # fmt: skip
        p = policy.make_policy("rules", list(self.cms.values()), self.tree)
        d = p.decide(st.snapshot(1.0), 1.0)
        self.assertEqual(sorted(d.actions), ["block_flow@hmib", "restore_breaker@u2"])


if __name__ == "__main__":
    unittest.main()
