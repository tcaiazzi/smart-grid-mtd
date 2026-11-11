"""Attack tree + countermeasures of the CPS chain (defense_plane.soar.trees),
grounded on the knowledge graph — no Docker.

Run: `.venv/bin/python -m unittest tests.test_soar_trees`.
"""

import json
import sys
import types
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from defense_plane.soar import kg, trees  # noqa: E402
from network_scenario.scenarios.cps import topology as cps  # noqa: E402


class CPSTrees(unittest.TestCase):
    def setUp(self):
        self.g = kg.build_cps_kg()
        self.tree = trees.cps_attack_tree(self.g)
        self.cms = trees.cps_countermeasures(self.g)

    def test_well_formed(self):
        idx = trees.index(self.tree)
        self.assertEqual(len(idx), len(list(self.tree.walk())), "duplicate node ids")
        for n in self.tree.walk():
            self.assertIn(n.gate, (trees.AND, trees.OR, trees.LEAF), n.id)
            self.assertEqual(n.gate == trees.LEAF, not n.children, n.id)

    def test_leaves_mapped_and_grounded(self):
        for leaf in trees.leaves(self.tree):
            self.assertTrue(leaf.attck or leaf.review, f"{leaf.id}: no ATT&CK id nor review note")
            for t in leaf.targets:
                self.assertIn(t, self.g, f"{leaf.id}: target {t} not in the KG")

    def test_feasible_on_the_lab(self):
        idx = trees.index(self.tree)
        self.assertTrue(trees.feasible(self.tree, self.g))
        self.assertTrue(trees.feasible(idx["via_hmi"], self.g))
        # No host outside the Modbus roles reaches the plant.
        self.assertFalse(trees.feasible(idx["direct_ot"], self.g))

    def test_without_allow_rule_the_pivot_is_infeasible(self):
        rules = [r for r in cps.firewall_rules() if "--dport" not in r]
        services, roles = kg.cps_catalog()
        lab, _m, _s = cps.build_lab(types.SimpleNamespace(dashboard_port=0))
        g2 = kg.build_kg(lab, rules, services=services, roles=roles,
                         plant_service=("engine", "modbus"))
        idx = trees.index(self.tree)
        self.assertFalse(trees.feasible(idx["via_hmi"], g2))
        self.assertFalse(trees.feasible(self.tree, g2))

    def test_prerequisites(self):
        pre = trees.prerequisites(self.tree, "mode_hijack")
        self.assertEqual(pre[:3], ["it_access", "it_exec", "pivot"])
        self.assertEqual(trees.prerequisites(self.tree, "it_access"), [])
        self.assertIn("via_hmi", trees.ancestors(self.tree, "breaker_open"))

    def test_countermeasures(self):
        ids = {c.id for c in self.cms}
        self.assertEqual(ids, {"notify", "block_flow", "isolate_hmi", "force_auto",
                               "restore_breaker"})
        nodes = trees.index(self.tree)
        for c in self.cms:
            for nid in c.prevents + c.restores:
                self.assertIn(nid, nodes, f"{c.id} -> {nid}")
            if c.id in ("block_flow", "isolate_hmi"):
                self.assertTrue(c.revert, f"{c.id} changes network state: needs a revert")
        by = {c.id: c for c in self.cms}
        # Inserted before the ESTABLISHED accept, with the KG's addresses.
        self.assertIn("iptables -I FORWARD 1", by["block_flow"].apply[0])
        self.assertIn(f"-s {cps.HMI_IP} -d {cps.ENGINE_IP}", by["block_flow"].apply[0])
        self.assertIn("127.0.0.1", by["force_auto"].apply[0])
        self.assertTrue(by["isolate_hmi"].requires_approval)
        # Every impact leaf can be undone by some countermeasure.
        restorable = {n for c in self.cms for n in c.restores}
        self.assertTrue({"setpoint_oor", "breaker_open", "mode_hijack"} <= restorable)

    def test_json(self):
        data = json.loads(json.dumps(trees.to_json(self.tree, self.cms)))
        self.assertEqual(data["attack_tree"]["id"], "impact")
        self.assertIn("force_auto", data["defense"]["mode_hijack"]["restored_by"])
        self.assertIn("block_flow", data["defense"]["pivot"]["prevented_by"])


if __name__ == "__main__":
    unittest.main()
