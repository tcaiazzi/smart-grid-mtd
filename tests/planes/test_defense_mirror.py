"""What the defender's telemetry becomes on the progress ledger.

The dashboard draws the defender only from the ledger, so a field the mirror
drops is a line the referee never sees: which attack step an IT finding
confirms, which register a write touched by name, what triggered a decision and
what it weighed. These check the mirror keeps them.

Run: `.venv/bin/python -m pytest tests/planes/test_defense_mirror.py`
"""

import unittest

from cyberrange.planes.defense.components import ItSensor, OtSensor, SocAnalytics


class Findings(unittest.TestCase):
    def test_an_it_finding_names_the_attack_step_it_confirms(self):
        sensor = ItSensor("hmi", "10.1.0.2", 5020, "/access.jsonl", 10)
        row = {"t": 3.0, "kind": "ot_finding", "detector": "it", "klass": "web_injection_pattern"}
        row |= {"maps_to": "it_access", "entities": {"src": "10.0.0.9"}}
        kind, fields = sensor.mirror(row)
        self.assertEqual(kind, "finding")
        self.assertEqual((fields["maps_to"], fields["src"]), ("it_access", "10.0.0.9"))

    def test_an_ot_finding_names_its_register(self):
        sensor = OtSensor("sensor", "eth0", "10.1.0.2", 5020, "10.1.0.3", "10.0.0.2", "rules", 10)
        row = {"t": 4.0, "kind": "ot_finding", "detector": "rules", "klass": "unsafe_command"}
        row |= {"entities": {"src": "10.0.0.2", "register": 0, "name": "dg_setpoint"}}
        _kind, fields = sensor.mirror(row)
        self.assertEqual((fields["register"], fields["name"]), (0, "dg_setpoint"))
        self.assertIsNone(fields["maps_to"], "an OT finding confirms no IT step")


class Decisions(unittest.TestCase):
    def test_a_decision_keeps_its_trigger_and_its_costs(self):
        soc = SocAnalytics("soc", {}, policy="solver")
        row = {"kind": "decision", "decided_t": 9.0, "trigger_t": 8.5, "trigger_klass": "pivot"}
        row |= {"policy": "solver", "actions": ["block_flow"], "rationale": "cheapest cover"}
        row |= {"covers": {"block_flow": {"prevents": ["pivot"]}}, "needs_approval": []}
        row |= {"cost_terms": {"residual": 0.1, "op": 1.0, "total": 1.1}, "pareto": [{"risk": 0}]}
        kind, fields = soc.mirror(row)
        self.assertEqual(kind, "decision")
        self.assertEqual((fields["trigger_t"], fields["trigger_klass"]), (8.5, "pivot"))
        self.assertEqual(fields["cost_terms"]["total"], 1.1)
        self.assertEqual(fields["guest_t"], 9.0)
        self.assertNotIn("pareto", fields, "the Pareto front stays in response.jsonl: too big")


if __name__ == "__main__":
    unittest.main()
