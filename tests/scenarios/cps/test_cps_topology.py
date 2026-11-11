"""Topology test for the cyber-physical Kathará lab builder
(cyberrange/scenarios/cps/topology.py on core.topology). Builds the Lab model in-process
(no Docker) and asserts the three zones, the IT/OT boundary firewall, and the
passive-sensor wiring are correct.

Run: `.venv/bin/python -m unittest tests.test_cps_topology`.
"""

import sys
import types
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.scenarios.cps import topology as cps  # noqa: E402
from cyberrange.scenarios.cps.scenario import CpsScenario  # noqa: E402


def _links(machine):
    return {idx: iface.link.name for idx, iface in machine.interfaces.items()}


class Topology(unittest.TestCase):
    def setUp(self):
        self.lab, self.m, self.startups = cps.build_lab(types.SimpleNamespace(dashboard_port=0))

    def test_six_machines_on_cps_image(self):
        self.assertEqual(sorted(self.lab.machines),
                         ["attacker", "engine", "firewall", "hmi", "plc", "sensor"])
        for name, mach in self.lab.machines.items():
            self.assertEqual(mach.get_image(), cps.IMAGE, name)

    def test_zones(self):
        self.assertEqual(_links(self.m["attacker"]), {0: cps.IT})
        self.assertEqual(_links(self.m["hmi"]), {0: cps.IT})
        self.assertEqual(_links(self.m["firewall"]), {0: cps.IT, 1: cps.OT})
        self.assertEqual(_links(self.m["plc"]), {0: cps.OT})
        self.assertEqual(_links(self.m["engine"]), {0: cps.OT})
        self.assertEqual(_links(self.m["sensor"]), {0: cps.OT, 1: cps.DEF})

    def test_firewall_default_drop_single_allow(self):
        rules = cps.firewall_rules()
        self.assertIn("iptables -P FORWARD DROP", rules)
        allow = [r for r in rules if "-j ACCEPT" in r and "ESTABLISHED" not in r]
        self.assertEqual(len(allow), 1, f"exactly one sanctioned flow expected: {allow}")
        self.assertIn(f"--dport {cps.MODBUS_PORT}", allow[0])
        self.assertIn(cps.ENGINE_IP, allow[0])
        # Only the HMI may cross the boundary: the attacker host (same IT
        # subnet) has to compromise the HMI and pivot from it.
        self.assertIn(f"-s {cps.HMI_IP} ", allow[0])
        self.assertNotIn(cps.IT_NET, allow[0])
        self.assertTrue(any("ip_forward=1" in r for r in rules))

    def test_sensor_startup_passive_ot_mgmt_def(self):
        cmds = self.startups["sensor"]
        self.assertTrue(any("promisc on" in c for c in cmds))
        self.assertTrue(any(f"{cps.SENSOR_DEF_IP}/24 dev eth1" in c for c in cmds))
        # No IP on the OT subnet -> unreachable from OT while still sniffing it.
        self.assertFalse(any("10.20." in c for c in cmds))

    def test_addresses_meta_matches_startups(self):
        for name, mach in self.m.items():
            meta = mach.meta.get("addresses")
            self.assertEqual(meta, cps.ADDRESSES[name], name)
            for iface, cidr in meta.items():
                self.assertIn(f"ip address add {cidr} dev {iface}", self.startups[name])
                # Every addressed interface exists on the Lab model.
                self.assertIn(int(iface[3:]), mach.interfaces, f"{name} {iface}")
        # The sensor's passive OT NIC carries no address.
        self.assertNotIn("eth0", self.m["sensor"].meta["addresses"])

    def test_authorized_writer_is_plc(self):
        # The sensor must treat the PLC as the only legitimate writer.
        self.assertEqual(cps.PLC_IP, "10.20.0.10")

    def test_hmi_startup_routes_via_firewall(self):
        cmds = self.startups["hmi"]
        self.assertIn(f"ip address add {cps.HMI_IP}/24 dev eth0", cmds)
        self.assertIn(f"ip route add default via {cps.FW_IT_IP} dev eth0", cmds)

    def test_attack_must_not_overlap_model_calibration(self):
        validate = CpsScenario().validate
        ok = types.SimpleNamespace(attack=True, normal_duration=60, learn_seconds=45)
        validate(ok)  # no raise
        bad = types.SimpleNamespace(attack=True, normal_duration=30, learn_seconds=45)
        with self.assertRaises(SystemExit):
            validate(bad)
        # A normal-only run has no attack to overlap with.
        validate(types.SimpleNamespace(attack=False, normal_duration=30, learn_seconds=45))

    def test_dashboard_meta_only_when_enabled(self):
        self.assertIsNone(self.m["sensor"].meta.get("bridged"))
        _lab, m, _s = cps.build_lab(types.SimpleNamespace(dashboard_port=8090))
        self.assertTrue(m["sensor"].meta.get("bridged"))
        self.assertEqual(m["sensor"].meta["ports"], {(8090, "tcp"): cps.DASHBOARD_GUEST_PORT})


if __name__ == "__main__":
    unittest.main()
