"""Attack tree + countermeasures of the CPS chain (nodes/soc/soar_trees.py),
grounded on the knowledge graph — the node's code, run on the host.

Run: `.venv/bin/python -m pytest tests/nodes/test_soar_trees.py`.
"""

import json
import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)

import soar_kg as kg  # noqa: E402  (flat guest imports, need the path set above)
import soar_trees as trees  # noqa: E402

from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402
from cyberrange.scenarios.cps import topology as cps  # noqa: E402


class CPSTrees(unittest.TestCase):
    def setUp(self):
        self.g = kg.build_kg(cps_inv.inventory())
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
        # The engineering workstation has no Modbus role and stands on the
        # plant's link: a second way in, which the boundary rules do not close.
        self.assertTrue(trees.feasible(idx["direct_ot"], self.g))
        self.assertEqual(
            trees.prerequisites(self.tree, "meas_fdi"),
            ["ot_aitm", "ot_foothold"],
            "falsifying a reading would be planned without the position it needs",
        )

    def test_without_the_workstation_nothing_reaches_the_plant_directly(self):
        inv = cps_inv.inventory()
        inv["hosts"] = [h for h in inv["hosts"] if h["role"] != "engineering"]
        g2 = kg.build_kg(inv)
        idx = trees.index(trees.cps_attack_tree(g2))
        self.assertFalse(trees.feasible(idx["direct_ot"], g2))
        ids = {c.id for c in trees.cps_countermeasures(g2)}
        self.assertFalse({"isolate_ews", "repair_arp"} & ids, "a response with no host to act on")

    def test_without_allow_rule_the_pivot_is_infeasible(self):
        rules = [r for r in cps.firewall_rules() if "--dport" not in r]
        g2 = kg.build_kg(cps_inv.inventory(rules=rules))
        idx = trees.index(self.tree)
        self.assertFalse(trees.feasible(idx["via_hmi"], g2))
        # The workstation's way does not cross the boundary: it stays open.
        self.assertTrue(trees.feasible(self.tree, g2))

    def test_prerequisites(self):
        pre = trees.prerequisites(self.tree, "mode_hijack")
        self.assertEqual(pre[:3], ["it_access", "it_exec", "pivot"])
        self.assertEqual(trees.prerequisites(self.tree, "it_access"), [])
        self.assertIn("via_hmi", trees.ancestors(self.tree, "breaker_open"))

    def test_countermeasures(self):
        ids = {c.id for c in self.cms}
        self.assertEqual(
            ids,
            {
                "notify",
                "block_flow",
                "isolate_hmi",
                "isolate_ews",
                "repair_arp",
                "force_auto",
                "restore_breaker",
            },
        )
        nodes = trees.index(self.tree)
        for c in self.cms:
            for nid in c.prevents + c.restores:
                self.assertIn(nid, nodes, f"{c.id} -> {nid}")
            if c.id in ("block_flow", "isolate_hmi", "isolate_ews"):
                self.assertTrue(c.revert, f"{c.id} changes network state: needs a revert")
        by = {c.id: c for c in self.cms}
        # Inserted before the ESTABLISHED accept, with the KG's addresses.
        self.assertIn("iptables -I FORWARD 1", by["block_flow"].apply[0])
        self.assertIn(f"-s {cps.HMI_IP} -d {cps.ENGINE_IP}", by["block_flow"].apply[0])
        # The plant is restored from the boundary device over the OT link: it
        # holds no agent, and loopback would mean a command run inside it.
        for cid in ("force_auto", "restore_breaker"):
            self.assertEqual(by[cid].machine, "firewall", cid)
            self.assertIn(f"ot_write.py {cps.ENGINE_IP} {cps.MODBUS_PORT}", by[cid].apply[0])
        self.assertEqual(trees.cps_context(self.g)["responder_ip"], cps.FW_OT_IP)
        self.assertTrue(by["isolate_hmi"].requires_approval)
        # Every impact leaf can be undone by some countermeasure.
        restorable = {n for c in self.cms for n in c.restores}
        leaves = {n.id for n in trees.index(self.tree)["ot_action"].children}
        self.assertEqual(leaves - restorable, set(), "an impact with no way back")

    def test_a_countermeasure_costs_what_it_cuts(self):
        by = {c.id: c for c in self.cms}
        cost = {c.id: round(trees.disruption(c.cuts) + c.op_cost, 4) for c in self.cms}
        self.assertEqual(
            {f.split(":")[1] for f in by["block_flow"].cuts}, {"hmi"}, "the PLC's control was cut"
        )
        self.assertLess(set(by["block_flow"].cuts), set(by["isolate_hmi"].cuts))
        self.assertEqual(by["isolate_ews"].cuts, ["on:ews:OT"])
        self.assertLess(cost["block_flow"], cost["isolate_hmi"])
        for cid in ("force_auto", "restore_breaker", "repair_arp"):
            self.assertEqual(by[cid].cuts, [], f"{cid} leaves the graph as it is")
            self.assertGreater(cost[cid], 0.0, f"{cid} would be free to run")
        # A function both cut is lost once.
        both = by["block_flow"].cuts + by["isolate_hmi"].cuts
        self.assertEqual(trees.disruption(both), trees.disruption(by["isolate_hmi"].cuts))

    def test_without_the_allow_rule_the_block_cuts_nothing(self):
        # The cost follows the graph: where the HMI holds no control of the
        # plant, blocking its flow takes nothing from anyone.
        rules = [r for r in cps.firewall_rules() if "--dport" not in r]
        g2 = kg.build_kg(cps_inv.inventory(rules=rules))
        by = {c.id: c for c in trees.cps_countermeasures(g2)}
        self.assertEqual(by["block_flow"].cuts, [])
        self.assertEqual(by["isolate_hmi"].cuts, ["on:hmi:IT"])

    def test_json(self):
        data = json.loads(json.dumps(trees.to_json(self.tree, self.cms)))
        cut = {c["id"]: c["cuts"] for c in data["countermeasures"]}
        self.assertTrue(cut["block_flow"], "tree.json does not say what the block costs")
        self.assertEqual(data["attack_tree"]["id"], "impact")
        self.assertIn("force_auto", data["defense"]["mode_hijack"]["restored_by"])
        self.assertIn("block_flow", data["defense"]["pivot"]["prevented_by"])


if __name__ == "__main__":
    unittest.main()
