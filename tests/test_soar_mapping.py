"""Findings -> attack-tree nodes -> campaign state (defense_plane.soar.mapping),
on synthetic findings shaped like the sensor's (see ot_sensor._finding).

Run: `.venv/bin/python -m unittest tests.test_soar_mapping`.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from defense_plane.soar import kg, mapping, trees  # noqa: E402
from network_scenario.scenarios.cps import topology as cps  # noqa: E402

HMI, PLC, ROGUE = cps.HMI_IP, cps.PLC_IP, "10.20.0.99"


def finding(klass, t, src=None, name=None, conf=0.9, detector="rules", **evidence):
    return {"i": 0, "t": t, "kind": "ot_finding", "detector": detector, "klass": klass,
            "reasons": [klass], "confidence": conf,
            "entities": {"src": src, "dst": cps.ENGINE_IP, "unit": 1, "register": None,
                         "name": name},
            "evidence": evidence}


def model(t, *features, conf=0.9):
    return finding("behavioral_anomaly", t, detector="model", conf=conf,
                   top=[{"feature": f, "z": 10.0} for f in features])


class Mapping(unittest.TestCase):
    def setUp(self):
        self.g = kg.build_cps_kg()
        self.tree = trees.cps_attack_tree(self.g)

    def run_findings(self, findings):
        st = mapping.CampaignState(self.tree, self.g)
        for f in findings:
            st.update(f)
        return st.snapshot(findings[-1]["t"] if findings else None)

    def confirmed_leaves(self, snap):
        return sorted(n for n in mapping.IMPACT_LEAVES
                      if snap["nodes"].get(n, {}).get("state") == mapping.CONFIRMED)

    def test_setpoint_out_of_range(self):
        snap = self.run_findings([
            model(1.0, "max_dsetpoint", "new_sessions"),
            finding("out_of_range_command", 1.0, HMI, "dg_setpoint", value=200.0),
            finding("unsafe_command", 2.2, HMI, "dg_setpoint", conf=0.85, value=200.0),
            finding("unsafe_command", 2.2, PLC, "dg_setpoint", conf=0.85, value=14.0),
        ])
        self.assertEqual(self.confirmed_leaves(snap), ["setpoint_oor"])
        self.assertEqual(snap["hosts_implicated"], ["hmi"])

    def test_breaker_explains_away_operator_dispatch(self):
        # Breaker opened; the operator's routine MANUAL dispatch during the
        # outage is "unsafe" too, but it is a consequence, not a hijack.
        snap = self.run_findings([
            finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0),
            finding("unsafe_command", 2.0, HMI, "switch_cmd", conf=0.85, value=1.0),
            finding("unsafe_command", 9.0, HMI, "ctrl_mode", conf=0.85, value=1.0),
            finding("manual_mode_excursion", 10.0, None, "ctrl_mode"),
            model(10.0, "v_min"),
        ])
        self.assertEqual(self.confirmed_leaves(snap), ["breaker_open"])
        self.assertLess(snap["nodes"]["mode_hijack"]["score"], mapping.CONFIRM_AT)

    def test_manual_hijack_without_command_level_evidence(self):
        snap = self.run_findings([
            model(1.0, "max_dsetpoint", "mode_writes"),
            finding("unsafe_command", 2.0, HMI, "ctrl_mode", conf=0.85, value=1.0),
            finding("unsafe_command", 2.0, HMI, "dg_setpoint", conf=0.85, value=60.0),
            finding("manual_mode_excursion", 3.0, None, "ctrl_mode"),
        ])
        # In-range setpoint: the hijack, not the out-of-range leaf.
        self.assertEqual(self.confirmed_leaves(snap), ["mode_hijack"])

    def test_prerequisites_inferred(self):
        snap = self.run_findings([finding("out_of_range_command", 1.0, HMI, "dg_setpoint",
                                          value=200.0)])
        for step in ("it_access", "it_exec", "pivot"):
            self.assertEqual(snap["nodes"][step]["state"], mapping.INFERRED, step)
        self.assertEqual(snap["nodes"]["setpoint_oor"]["state"], mapping.CONFIRMED)
        self.assertIn("breaker_open", snap["next"])

    def test_model_alone_never_confirms(self):
        snap = self.run_findings([model(1.0, "max_dsetpoint", conf=0.99)])
        self.assertEqual(self.confirmed_leaves(snap), [])
        self.assertEqual(snap["nodes"]["setpoint_oor"]["state"], mapping.SUSPECTED)

    def test_plc_reaction_is_not_evidence(self):
        snap = self.run_findings([finding("unsafe_command", 1.0, PLC, "dg_setpoint",
                                          conf=0.85, value=14.0)])
        self.assertEqual(snap["nodes"], {})

    def test_unknown_writer_branch(self):
        snap = self.run_findings([finding("unauthorized_write_to_actuator", 1.0, ROGUE,
                                          "dg_setpoint", conf=0.95)])
        self.assertEqual(snap["nodes"]["ot_write_unknown"]["state"], mapping.CONFIRMED)
        self.assertEqual(snap["nodes"]["ot_foothold"]["state"], mapping.INFERRED)
        self.assertNotIn("pivot", snap["nodes"])

    def it_finding(self, klass, node, t, src=None, conf=0.9):
        return {"i": 0, "t": t, "kind": "ot_finding", "detector": "it", "klass": klass,
                "reasons": [klass], "confidence": conf, "maps_to": node,
                "entities": {"src": src, "dst": None, "unit": None, "register": None,
                             "name": None}, "evidence": {}}

    def test_it_findings_confirm_early_steps(self):
        # The IT sensor observes the early steps directly: they become confirmed,
        # not merely inferred, before any plant manipulation.
        snap = self.run_findings([
            self.it_finding("web_injection_pattern", "it_access", 1.0, src="10.10.0.10"),
            self.it_finding("web_child_process", "it_exec", 2.0),
        ])
        self.assertEqual(snap["nodes"]["it_access"]["state"], mapping.CONFIRMED)
        self.assertEqual(snap["nodes"]["it_exec"]["state"], mapping.CONFIRMED)
        # no impact is fabricated from IT evidence alone
        for leaf in mapping.IMPACT_LEAVES:
            self.assertNotEqual(snap["nodes"].get(leaf, {}).get("state"), mapping.CONFIRMED)
        self.assertIn("attacker", snap["hosts_implicated"])

    def test_it_pivot_confirmed_lifts_access(self):
        snap = self.run_findings([self.it_finding("unexpected_modbus_client", "pivot", 1.0)])
        self.assertEqual(snap["nodes"]["pivot"]["state"], mapping.CONFIRMED)
        self.assertEqual(snap["nodes"]["it_access"]["state"], mapping.INFERRED)

    def test_non_findings_ignored(self):
        st = mapping.CampaignState(self.tree, self.g)
        self.assertEqual(st.update({"kind": "ot_alert", "state": "raised"}), [])
        self.assertEqual(st.update({"kind": "sensor_up"}), [])
        self.assertEqual(st.snapshot()["nodes"], {})


if __name__ == "__main__":
    unittest.main()
