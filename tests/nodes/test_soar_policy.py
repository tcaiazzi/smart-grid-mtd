"""Response policies (nodes/soc/soar_policy.py): fixed rules vs the enumeration
solver, on synthetic campaign states.

Run: `.venv/bin/python -m pytest tests/nodes/test_soar_policy.py`.
"""

import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)

import soar_kg as kg  # noqa: E402  (flat guest imports, need the path set above)
import soar_mapping as mapping  # noqa: E402
import soar_policy as policy  # noqa: E402
import attack_graph  # noqa: E402

from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402
from tests.helpers.soar import HMI, finding, model  # noqa: E402

SCENARIOS = {
    "setpoint-overvoltage": [finding("out_of_range_command", 1.0, HMI, "dg_setpoint", value=200.0)],
    "breaker-open": [finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0)],
    "manual-hijack": [
        finding("unsafe_command", 2.0, HMI, "ctrl_mode", conf=0.85, value=1.0),
        finding("manual_mode_excursion", 3.0, None, "ctrl_mode"),
    ],
    # Each step is too small to be a jump; the excursion comes with the last ones.
    "slow-ramp": [
        finding("unsafe_command", 30.0, HMI, "dg_setpoint", conf=0.85, value=47.0, prev=46.0),
        finding("unsafe_command", 30.0, HMI, "dg_setpoint", conf=0.85, value=48.0, prev=47.0),
    ],
    "setpoint-oscillation": [
        finding("unsafe_command", 2.0, HMI, "dg_setpoint", conf=0.85, value=55.0, prev=20.0),
        finding("unsafe_command", 5.0, HMI, "dg_setpoint", conf=0.85, value=5.0, prev=55.0),
    ],
    "breaker-chatter": [
        finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0),
        finding("policy_violation", 3.0, HMI, "switch_cmd", value=0.0),
    ],
    # No write of the attacker's: only the position and the two readings show.
    "meas-fdi": [
        finding("address_spoofing", 1.0, "10.20.0.30", None, conf=0.95, address=HMI),
        finding("conflicting_reading", 3.0, None, None, conf=0.95),
    ],
}
EXPECTED = {
    "setpoint-overvoltage": {"block_flow"},
    "breaker-open": {"block_flow", "restore_breaker"},
    "manual-hijack": {"block_flow", "force_auto"},
    "slow-ramp": {"block_flow", "force_auto"},
    "setpoint-oscillation": {"block_flow", "force_auto"},
    "breaker-chatter": {"block_flow", "restore_breaker"},
    "meas-fdi": {"isolate_ews", "repair_arp"},
}


class Policies(unittest.TestCase):
    def setUp(self):
        self.g = kg.build_kg(cps_inv.inventory())
        self.tree = attack_graph.attack_tree(self.g)
        self.cms = attack_graph.countermeasures(self.g)

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
        p2 = policy.make_policy(
            "solver", [c for c in self.cms if c.id != "block_flow"], self.tree, approval="deny"
        )
        d2 = p2.decide(st.snapshot(1.0), 1.0)
        self.assertNotIn("isolate_hmi", d2.actions)

    def test_a_declined_action_gives_way_to_the_alternative(self):
        p = policy.SolverPolicy(self.cms, self.tree)
        st = mapping.CampaignState(self.tree, self.g)
        for f in SCENARIOS["breaker-open"]:
            st.update(f)
        snap = st.snapshot(1.0)
        d = p.decide(snap, 1.0)
        self.assertIn("block_flow", d.actions)
        p.mark_applied(d.actions)
        p.mark_withdrawn(["block_flow"], declined=True)
        d2 = p.decide(snap, 2.0)
        self.assertIsNotNone(d2, "with its path cut turned down the solver offered nothing else")
        self.assertNotIn("block_flow", d2.actions, "a declined action was proposed again")
        self.assertIn("isolate_hmi", d2.actions)

    def test_a_lapsed_action_may_be_proposed_again(self):
        for kind in ("rules", "solver"):
            p = policy.make_policy(kind, self.cms, self.tree)
            st = mapping.CampaignState(self.tree, self.g)
            for f in SCENARIOS["breaker-open"]:
                st.update(f)
            snap = st.snapshot(1.0)
            d = p.decide(snap, 1.0)
            p.mark_applied(d.actions)
            self.assertIsNone(p.decide(snap, 2.0), kind)
            p.mark_withdrawn(["block_flow"])
            self.assertEqual(p.decide(snap, 3.0).actions, ["block_flow"], kind)

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
        self.assertIn("force_auto", d.actions)  # restoring is still worth it
        self.assertNotIn("causal pairing", d.rationale)

    def believed(self, mode):
        st = mapping.CampaignState(self.tree, self.g)
        for f in SCENARIOS[mode]:
            st.update(f)
        return {n: v["score"] for n, v in st.snapshot(9.0)["nodes"].items()}

    def test_a_function_already_cut_is_not_charged_again(self):
        p = policy.SolverPolicy(self.cms, self.tree)
        scores = self.believed("breaker-open")
        alone = p.cost(("isolate_hmi",), scores)["op"]
        block = p.cost(("block_flow",), scores)["op"]
        self.assertEqual(
            p.cost(("block_flow", "isolate_hmi"), scores)["op"],
            alone,
            "the HMI's control of the plant was charged to both actions that cut it",
        )
        p.mark_applied(["block_flow"])
        self.assertAlmostEqual(p.cost(("isolate_hmi",), scores)["op"], alone - block)

    def test_an_action_that_bites_late_is_worth_less(self):
        scores = self.believed("breaker-open")
        now = policy.SolverPolicy(self.cms, self.tree)
        waits = policy.SolverPolicy(self.cms, self.tree, approval_delay_s=10.0)
        never = policy.SolverPolicy(self.cms, self.tree, approval_delay_s=3600.0)
        # isolate_hmi needs approval, block_flow does not: only the first waits.
        self.assertEqual(now.cost(("block_flow",), scores), waits.cost(("block_flow",), scores))
        late = [p.cost(("isolate_hmi",), scores) for p in (now, waits, never)]
        self.assertLess(late[0]["time"], late[1]["time"])
        self.assertLess(late[1]["time"], late[2]["time"])
        # However late, acting loses no more than the path it would have cut.
        idle = never.cost((), scores)
        self.assertAlmostEqual(late[2]["future"] + late[2]["time"], idle["future"], places=3)

    def test_an_approval_too_slow_to_matter_is_not_asked_for(self):
        cms = [c for c in self.cms if c.id != "block_flow"]
        st = mapping.CampaignState(self.tree, self.g)
        for f in SCENARIOS["breaker-open"]:
            st.update(f)
        fast = policy.make_policy("solver", cms, self.tree, approval_delay_s=2.0)
        slow = policy.make_policy("solver", cms, self.tree, approval_delay_s=3600.0)
        self.assertIn("isolate_hmi", fast.decide(st.snapshot(1.0), 1.0).actions)
        self.assertNotIn(
            "isolate_hmi",
            slow.decide(st.snapshot(1.0), 1.0).actions,
            "the operator's work was cut for a path the attacker keeps for an hour",
        )

    def it_finding(self, klass, node, t, conf=0.9):
        return {
            "i": 0,
            "t": t,
            "kind": "ot_finding",
            "detector": "it",
            "klass": klass,
            "reasons": [klass],
            "confidence": conf,
            "maps_to": node,
            "entities": {"src": HMI, "dst": None, "unit": None, "register": None, "name": None},
            "evidence": {},
        }

    def test_rules_early_response_on_it_exec(self):
        # With the IT sensor, a confirmed it_exec triggers an early response
        # (kill the foothold + pre-block the pivot) before the plant is touched.
        cms = attack_graph.countermeasures(self.g, it=True)
        p = policy.make_policy("rules", cms, self.tree)
        st = mapping.CampaignState(self.tree, self.g)
        st.update(self.it_finding("web_child_process", "it_exec", 1.0))
        d = p.decide(st.snapshot(1.0), 1.0)
        self.assertEqual(set(d.actions), {"kill_proc_tree", "block_flow"})
        self.assertEqual(d.actions[0], "kill_proc_tree")  # order: earliest first
        self.assertTrue(d.explained)

    def test_it_countermeasures_absent_without_it_sensor(self):
        cms = attack_graph.countermeasures(self.g, it=False)
        self.assertNotIn("kill_proc_tree", {c.id for c in cms})

    def test_solver_prefers_cheap_early_cut_with_it(self):
        cms = attack_graph.countermeasures(self.g, it=True)
        p = policy.make_policy("solver", cms, self.tree)
        st = mapping.CampaignState(self.tree, self.g)
        st.update(self.it_finding("web_child_process", "it_exec", 1.0))
        d = p.decide(st.snapshot(1.0), 1.0)
        # An IT cut (kill_proc_tree / block_web_src) is cheaper than block_flow.
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
                self.assertFalse(
                    b["risk"] <= a["risk"]
                    and b["op"] <= a["op"]
                    and b["energy"] <= a["energy"]
                    and (b["risk"], b["op"], b["energy"]) != (a["risk"], a["op"], a["energy"])
                )


if __name__ == "__main__":
    unittest.main()
