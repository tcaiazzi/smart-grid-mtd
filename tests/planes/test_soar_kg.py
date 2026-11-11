"""Knowledge graph v0 of the CPS lab (cyberrange.planes.defense.soar.kg), built in-process
from the Lab model — no Docker.

Run: `.venv/bin/python -m unittest tests.test_soar_kg`.
"""

import sys
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.planes.defense import ot_registers as reg  # noqa: E402
from cyberrange.planes.defense.soar import kg  # noqa: E402
from cyberrange.scenarios.cps import kg as cps_kg
from cyberrange.scenarios.cps import topology as cps  # noqa: E402


class CPSKnowledgeGraph(unittest.TestCase):
    def setUp(self):
        self.g = cps_kg.build()

    def test_hosts_zones_roles(self):
        self.assertEqual(kg.hosts(self.g), [f"host:{h}" for h in
                         ["attacker", "engine", "firewall", "hmi", "plc", "sensor"]])
        zones = sorted(n for n, d in self.g.nodes(data=True) if d["type"] == "zone")
        self.assertEqual(zones, ["zone:DEF", "zone:IT", "zone:OT"])
        self.assertEqual(self.g.nodes["host:firewall"]["role"], kg.BOUNDARY_ROLE)
        self.assertEqual(self.g.nodes["host:plc"]["role"], "plc")

    def test_addresses_from_meta(self):
        self.assertEqual(kg.addresses(self.g, "hmi"), [(cps.HMI_IP, "IT")])
        self.assertEqual(kg.addresses(self.g, "firewall"),
                         sorted([(cps.FW_IT_IP, "IT"), (cps.FW_OT_IP, "OT")]))
        # Passive OT NIC: the sensor is in OT but has no address there.
        self.assertEqual(kg.addresses(self.g, "sensor"), [(cps.SENSOR_DEF_IP, "DEF")])
        self.assertEqual(kg.host_of_ip(self.g, cps.ENGINE_IP), "engine")
        self.assertEqual(kg.host_of_ip(self.g, "10.99.0.1"), None)

    def test_registers_and_permissions(self):
        exposed = [v for _, v, k in self.g.out_edges("svc:engine/modbus", keys=True)
                   if k == "exposes"]
        self.assertEqual(len(exposed), reg.ACTUATOR_COUNT + reg.SENSOR_COUNT)
        self.assertTrue(self.g.nodes[f"reg:hr:{reg.HR_CTRL_MODE}"]["sensitive"])
        writes = {h: sorted(v for _, v, k in self.g.out_edges(f"host:{h}", keys=True)
                            if k == "may_write") for h in ("plc", "hmi", "attacker")}
        self.assertEqual(writes["plc"], [f"reg:hr:{reg.HR_DG_SETPOINT}"])
        self.assertEqual(writes["hmi"], sorted([f"reg:hr:{reg.HR_DG_SETPOINT}",
                                                f"reg:hr:{reg.HR_CTRL_MODE}"]))
        self.assertEqual(writes["attacker"], [])

    def test_boundary_rule_parsed(self):
        rules = kg.flow_rules(self.g)
        self.assertEqual(self.g.nodes["host:firewall"]["forward_default"], "DROP")
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual((r["src"], r["dst"], r["proto"], r["dport"], r["action"]),
                         (cps.HMI_IP, cps.ENGINE_IP, "tcp", cps.MODBUS_PORT, "ACCEPT"))
        dst = [v for _, v, k in self.g.out_edges(r["id"], keys=True) if k == "dst"]
        self.assertEqual(dst, ["svc:engine/modbus"])

    def test_reachability(self):
        P, A = cps.MODBUS_PORT, cps.APP_PORT
        self.assertTrue(kg.reachable(self.g, "hmi", "engine", P))        # sanctioned flow
        self.assertFalse(kg.reachable(self.g, "attacker", "engine", P))  # default DROP
        self.assertTrue(kg.reachable(self.g, "attacker", "hmi", A))      # same zone
        self.assertTrue(kg.reachable(self.g, "plc", "engine", P))        # same zone
        self.assertFalse(kg.reachable(self.g, "sensor", "engine", P))    # no OT address
        self.assertFalse(kg.reachable(self.g, "hmi", "engine", 502))     # no such service

    def test_rule_removal_cuts_the_path(self):
        rules = [r for r in cps.firewall_rules() if "--dport" not in r]
        services, roles = cps_kg.catalog()
        lab, _m, _s = cps.build_lab(__import__("types").SimpleNamespace(dashboard_port=0))
        g = kg.build_kg(lab, rules, services=services, roles=roles,
                        plant_service=("engine", "modbus"))
        self.assertFalse(kg.reachable(g, "hmi", "engine", cps.MODBUS_PORT))

    def test_json_roundtrip(self):
        g2 = kg.from_json(kg.to_json(self.g))
        self.assertEqual(sorted(g2.nodes), sorted(self.g.nodes))
        self.assertEqual(g2.number_of_edges(), self.g.number_of_edges())
        self.assertTrue(kg.reachable(g2, "hmi", "engine", cps.MODBUS_PORT))


if __name__ == "__main__":
    unittest.main()
