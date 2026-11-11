"""Response policies (cyberrange.planes.defense.soar.policy): fixed rules vs the
enumeration solver, on synthetic campaign states.

Run: `.venv/bin/python -m unittest tests.test_soar_policy`.
"""

import sys
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.planes.defense.soar import kg, mapping, policy, trees  # noqa: E402
from cyberrange.scenarios.cps import kg as cps_kg
from tests.helpers.soar import HMI, finding, model  # noqa: E402

SCENARIOS = {
    "setpoint-overvoltage": [
        finding("out_of_range_command", 1.0, HMI, "dg_setpoint", value=200.0)],
    "breaker-open": [
        finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0)],
    "manual-hijack": [
        finding("unsafe_command", 2.0, HMI, "ctrl_mode", conf=0.85, value=1.0),
        finding("manual_mode_excursion", 3.0, None, "ctrl_mode")],
}
EXPECTED = {
    "setpoint-overvoltage": {"block_flow"},
    "breaker-open": {"block_flow", "restore_breaker"},
    "manual-hijack": {"block_flow", "force_auto"},
}


class Policies(unittest.TestCase):
    def setUp(self):
        self.g = cps_kg.build()
        self.tree = trees.cps_attack_tree(self.g)
        self.cms = trees.cps_countermeasures(self.g)

    def drive(self, kind, findings, approval="auto"):
        p = policy.make_policy(kind, self.cms, self.tree, approval=approval)
        st = mapping.CampaignState(self.tree, self.g)
        decisions = []
        for f in findings:
            st.update(f)
            d = p.decide(st.snapshot(f["t"]), f["t"])
            if d:
                p.mark_applied([a for a in d.actions if a != "notify"])
                decisions.append(d)
        return decisions

    def actions(self, decisions):
        return {a for d in decisions for a in d.actions if a != "notify"}

    def test_rules_playbook(self):
        for mode, fs in SCENARIOS.items():
            ds = self.drive("rules", fs)
            self.assertEqual(self.actions(ds), EXPECTED[mode], mode)
            self.assertTrue(all(d.explained for d in ds), mode)

    def test_solver_covers_the_expected_actions(self):
        for mode, fs in SCENARIOS.items():
            ds = self.drive("solver", fs)
            self.assertTrue(EXPECTED[mode] <= self.actions(ds), (mode, self.actions(ds)))
            self.assertNotIn("isolate_hmi", self.actions(ds), "block_flow is cheaper")
            for d in ds:
                self.assertTrue(d.explained, d.rationale)
                self.assertIn("total", d.cost_terms)

    def test_no_findings_no_action(self):
        for kind in ("rules", "solver"):
            p = policy.make_policy(kind, self.cms, self.tree)
            st = mapping.CampaignState(self.tree, self.g)
            self.assertIsNone(p.decide(st.snapshot(0.0), 0.0), kind)

    def test_rules_only_notify_on_suspicion(self):
        ds = self.drive("rules", [model(1.0, "max_dsetpoint")])
        self.assertEqual([d.actions for d in ds], [["notify"]])

    def test_each_action_fires_once(self):
        fs = SCENARIOS["breaker-open"] * 3
        for kind in ("rules", "solver"):
            ds = self.drive(kind, fs)
            flat = [a for d in ds for a in d.actions]
            self.assertEqual(len(flat), len(set(flat)), (kind, flat))

    def test_execution_order_preventive_first(self):
        ds = self.drive("rules", SCENARIOS["manual-hijack"])
        self.assertEqual(ds[-1].actions, ["block_flow", "force_auto"])

    def test_solver_falls_back_to_isolation_when_block_unavailable(self):
        p = policy.SolverPolicy([c for c in self.cms if c.id != "block_flow"], self.tree)
        st = mapping.CampaignState(self.tree, self.g)
        for f in SCENARIOS["breaker-open"]:
            st.update(f)
        d = p.decide(st.snapshot(1.0), 1.0)
        self.assertIn("isolate_hmi", d.actions)
        self.assertEqual(d.needs_approval, ["isolate_hmi"])
        # ... and never proposes it when approvals are denied.
        p2 = policy.make_policy("solver", [c for c in self.cms if c.id != "block_flow"],
                                self.tree, approval="deny")
        d2 = p2.decide(st.snapshot(1.0), 1.0)
        self.assertNotIn("isolate_hmi", d2.actions)

    def test_solver_pairs_restore_with_path_cut(self):
        # Seen live (manual-hijack, seed 1): only the model fires before the
        # restore, and the early restore suppresses the voltage findings that
        # would later confirm the path. Restoring alone was cheapest, which
        # left the HMI -> plant path open. The causal pairing forbids that.
        ds = self.drive("solver", [model(1.0, "max_dsetpoint", "mode_writes", conf=0.926)])
        acts = self.actions(ds)
        self.assertIn("force_auto", acts)
        self.assertIn("block_flow", acts)
        self.assertIn("causal pairing", ds[0].rationale)

    def test_pairing_waived_when_nothing_can_cut_the_path(self):
        cms = [c for c in self.cms if c.id not in ("block_flow", "isolate_hmi")]
        p = policy.SolverPolicy(cms, self.tree)
        st = mapping.CampaignState(self.tree, self.g)
        for f in SCENARIOS["manual-hijack"]:
            st.update(f)
        d = p.decide(st.snapshot(3.0), 3.0)
        self.assertIn("force_auto", d.actions)      # restoring is still worth it
        self.assertNotIn("causal pairing", d.rationale)

    def it_finding(self, klass, node, t, conf=0.9):
        return {"i": 0, "t": t, "kind": "ot_finding", "detector": "it", "klass": klass,
                "reasons": [klass], "confidence": conf, "maps_to": node,
                "entities": {"src": HMI, "dst": None, "unit": None, "register": None,
                             "name": None}, "evidence": {}}

    def test_rules_early_response_on_it_exec(self):
        # With the IT sensor, a confirmed it_exec triggers an early response
        # (kill the foothold + pre-block the pivot) before the plant is touched.
        cms = trees.cps_countermeasures(self.g, it=True)
        p = policy.make_policy("rules", cms, self.tree)
        st = mapping.CampaignState(self.tree, self.g)
        st.update(self.it_finding("web_child_process", "it_exec", 1.0))
        d = p.decide(st.snapshot(1.0), 1.0)
        self.assertEqual(set(d.actions), {"kill_proc_tree", "block_flow"})
        self.assertEqual(d.actions[0], "kill_proc_tree")   # order: earliest first
        self.assertTrue(d.explained)

    def test_it_countermeasures_absent_without_it_sensor(self):
        cms = trees.cps_countermeasures(self.g, it=False)
        self.assertNotIn("kill_proc_tree", {c.id for c in cms})

    def test_solver_prefers_cheap_early_cut_with_it(self):
        cms = trees.cps_countermeasures(self.g, it=True)
        p = policy.make_policy("solver", cms, self.tree)
        st = mapping.CampaignState(self.tree, self.g)
        st.update(self.it_finding("web_child_process", "it_exec", 1.0))
        d = p.decide(st.snapshot(1.0), 1.0)
        # an IT cut (kill_proc_tree / block_web_src) is cheaper than block_flow
        self.assertTrue({"kill_proc_tree", "block_web_src"} & set(d.actions))
        self.assertTrue(d.explained)

    def test_pareto_front_non_dominated(self):
        d = self.drive("solver", SCENARIOS["manual-hijack"])[0]
        front = d.pareto
        self.assertTrue(front)
        for a in front:
            for b in front:
                if a is b:
                    continue
                self.assertFalse(b["risk"] <= a["risk"] and b["op"] <= a["op"]
                                 and b["energy"] <= a["energy"]
                                 and (b["risk"], b["op"], b["energy"]) != (a["risk"], a["op"], a["energy"]))


if __name__ == "__main__":
    unittest.main()
