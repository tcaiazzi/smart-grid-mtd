"""The Wazuh manager's integration with DFIR-IRIS (nodes/wazuh/manager/
iris_forward.py): which alerts reach the analyst, and what they carry.

The integration forwards what a tuned SOC puts in front of a person — an OT
sensor alert as it opens, every IT intrusion finding — and nothing else: the
findings behind an alert stay in Wazuh's dashboard. Wazuh's integrator and IRIS
are not here; the decision and the translation are.

Run: `.venv/bin/python -m pytest tests/nodes/test_iris_forward.py`
"""

import json
import tempfile
import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.WAZUH_MANAGER)

import iris_forward as F  # noqa: E402  (flat guest import, needs the path set above)

IDS = {
    "severity": {"Medium": 4, "High": 5},
    "status": {"New": 2},
    "ioc_type": {"ip-src": 79},
    "asset_type": {"Linux - Server": 3},
    "tlp": {"amber": 2},
}


def wazuh(rule, level, agent, **data):
    """An alert as the manager writes it, with the shipped JSON decoded in data."""
    return {
        "id": "1763064620.1234",
        "timestamp": "2026-11-13T20:10:20.268+0000",
        "rule": {"id": rule, "level": level, "description": f"CPS {data.get('klass')}"},
        "agent": {"id": "001", "name": agent, "ip": "10.30.0.10"},
        "data": data,
    }


OT_ALERT = wazuh("100101", 7, "sensor", kind="ot_alert", state="raised", detector="rules",
                 klass="unsafe_command", confidence="0.8",
                 entities={"src": "10.10.0.20", "name": "dg_setpoint"})  # fmt: skip
IT_FINDING = wazuh("100100", 10, "hmi", kind="ot_finding", detector="it",
                   klass="web_injection_pattern", maps_to="it_access",
                   entities={"src": "10.10.0.10"})  # fmt: skip


class WhatIsForwarded(unittest.TestCase):
    def test_an_ot_alert_as_it_opens(self):
        self.assertTrue(F.should_forward(OT_ALERT))

    def test_not_when_it_clears(self):
        cleared = json.loads(json.dumps(OT_ALERT))
        cleared["data"]["state"] = "cleared"
        self.assertFalse(F.should_forward(cleared), "one episode would reach IRIS twice")

    def test_every_it_finding(self):
        self.assertTrue(F.should_forward(IT_FINDING))

    def test_not_the_ot_findings_behind_an_alert(self):
        finding = wazuh("100100", 10, "sensor", kind="ot_finding", detector="rules",
                        klass="unsafe_command")  # fmt: skip
        self.assertFalse(F.should_forward(finding), "every packet would become an IRIS alert")

    def test_nor_any_other_rule(self):
        self.assertFalse(F.should_forward(wazuh("100120", 5, "firewall", kind="cps_response")))
        self.assertFalse(F.should_forward(wazuh("5715", 3, "hmi")))


class WhatTheAnalystGets(unittest.TestCase):
    def test_an_ot_alert_becomes_an_iris_alert_with_host_and_source(self):
        out = F.to_iris(OT_ALERT, IDS)
        self.assertEqual(out["alert_title"], "[sensor] CPS unsafe_command")
        self.assertEqual((out["alert_status_id"], out["alert_severity_id"]), (2, 4))
        self.assertEqual(out["alert_source"], "Wazuh")
        self.assertEqual(out["alert_source_ref"], "1763064620.1234")
        self.assertEqual(out["alert_source_event_time"], "2026-11-13T20:10:20.268")
        self.assertIn("Register: dg_setpoint", out["alert_description"])
        (asset,) = out["alert_assets"]
        self.assertEqual((asset["asset_name"], asset["asset_ip"]), ("sensor", "10.30.0.10"))
        (ioc,) = out["alert_iocs"]
        self.assertEqual((ioc["ioc_value"], ioc["ioc_type_id"]), ("10.10.0.20", 79))
        self.assertEqual(out["alert_source_content"], OT_ALERT, "the raw event lost for triage")

    def test_an_it_finding_is_high_and_names_its_attack_step(self):
        out = F.to_iris(IT_FINDING, IDS)
        self.assertEqual(out["alert_severity_id"], 5)
        self.assertIn("Attack step it points to: it_access", out["alert_description"])
        self.assertIn("web_injection_pattern", out["alert_tags"].split(","))

    def test_a_reference_iris_lacks_drops_the_detail_not_the_alert(self):
        ids = dict(IDS, ioc_type={}, asset_type={})
        out = F.to_iris(OT_ALERT, ids)
        self.assertEqual((out["alert_iocs"], out["alert_assets"]), ([], []))


class Aggregation(unittest.TestCase):
    def test_a_repeat_within_the_window_updates_the_open_alert(self):
        state = {}
        k = F.key_of(IT_FINDING)
        self.assertIsNone(F.aggregate(state, k, 100.0))
        state[k] = {"alert_id": 7, "n": 1, "t": 100.0}
        self.assertEqual(F.aggregate(state, k, 150.0), (7, 2))
        self.assertEqual(F.aggregate(state, k, 260.0), (7, 3), "the window runs from the last one")

    def test_after_the_window_it_is_a_new_alert(self):
        k = F.key_of(IT_FINDING)
        state = {k: {"alert_id": 7, "n": 4, "t": 100.0}}
        self.assertIsNone(F.aggregate(state, k, 100.0 + F.AGGREGATE_S + 1))
        self.assertNotIn(k, state)

    def test_another_source_or_class_is_another_alert(self):
        other = json.loads(json.dumps(IT_FINDING))
        other["data"]["entities"]["src"] = "10.10.0.99"
        self.assertNotEqual(F.key_of(IT_FINDING), F.key_of(other))
        self.assertNotEqual(F.key_of(IT_FINDING), F.key_of(OT_ALERT))


class FakeIris:
    calls = []

    def __init__(self, url, key):
        pass

    def ids(self):
        return IDS

    def call(self, method, path, body=None):
        FakeIris.calls.append((method, path, body))
        return {"alert_id": 40 + len(FakeIris.calls)}


class TheIntegration(unittest.TestCase):
    def setUp(self):
        self.real, F.Iris = F.Iris, FakeIris
        FakeIris.calls = []
        self.addCleanup(setattr, F, "Iris", self.real)
        self.dir = tempfile.mkdtemp(prefix="custom-iris-")
        self.state = f"{self.dir}/state"
        self.now = [1000.0]

    def run_with(self, alert):
        path = f"{self.dir}/alert.json"
        with open(path, "w") as f:
            json.dump(alert, f)
        argv = ["custom-iris", path, "key", "https://iris.lab"]
        return F.main(argv, state_path=self.state, clock=lambda: self.now[0])

    def test_eight_connections_are_one_alert_seen_eight_times(self):
        for _ in range(8):
            self.assertEqual(self.run_with(IT_FINDING), 0)
            self.now[0] += 5
        paths = [p for _m, p, _b in FakeIris.calls]
        self.assertEqual(paths.count("/alerts/add"), 1, "each connection became an alert")
        self.assertEqual(paths[-1], "/alerts/update/41")
        self.assertEqual(FakeIris.calls[-1][2], {"alert_note": "Seen 8 times; last at "
                                                 "2026-11-13T20:10:20.268+0000."})  # fmt: skip

    """main() as Wazuh's integrator calls it: an alert not to forward costs no
    call to IRIS, and bad arguments are refused."""

    def test_an_alert_not_to_forward_never_reaches_iris(self):
        with tempfile.NamedTemporaryFile("w", suffix=".alert") as f:
            json.dump(wazuh("100120", 5, "firewall", kind="cps_response"), f)
            f.flush()
            # An unreachable IRIS: reaching it at all would fail the call.
            self.assertEqual(F.main(["custom-iris", f.name, "key", "https://192.0.2.1"]), 0)

    def test_bad_arguments(self):
        self.assertEqual(F.main(["custom-iris"]), 2)


if __name__ == "__main__":
    unittest.main()
