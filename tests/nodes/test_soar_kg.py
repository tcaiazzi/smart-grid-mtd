"""Knowledge graph of the CPS lab (nodes/soc/soar_kg.py), built from the SOC's
inventory (cyberrange.scenarios.cps.inventory) — the node's code, run on the host.

Run: `.venv/bin/python -m pytest tests/nodes/test_soar_kg.py`.
"""

import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)

import ot_registers as reg  # noqa: E402  (flat guest imports, need the path set above)
import soar_kg as kg  # noqa: E402

from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402
from cyberrange.scenarios.cps import topology as cps  # noqa: E402


def hr(addr, unit=reg.UNIT_ID):
    return kg.reg_id(unit, "hr", addr)


class CPSKnowledgeGraph(unittest.TestCase):
    def setUp(self):
        self.g = kg.build_kg(cps_inv.inventory())

    def test_hosts_zones_roles(self):
        self.assertEqual(
            kg.hosts(self.g),
            [
                f"host:{h}"
                for h in ["attacker", "engine", "ews", "firewall", "hmi", "plc", "sensor", "soc"]
            ],
        )
        zones = sorted(n for n, d in self.g.nodes(data=True) if d["type"] == "zone")
        self.assertEqual(zones, ["zone:IT", "zone:MGMT", "zone:OT"])
        self.assertEqual(self.g.nodes["host:firewall"]["role"], kg.BOUNDARY_ROLE)
        self.assertEqual(self.g.nodes["host:plc"]["role"], "plc")

    def test_addresses_from_meta(self):
        # IT first: the tree and the countermeasures take a host's first address
        # as its primary one.
        self.assertEqual(
            kg.addresses(self.g, "hmi"), [(cps.HMI_IP, "IT"), (cps.HMI_MGMT_IP, "MGMT")]
        )
        self.assertEqual(
            kg.addresses(self.g, "firewall"),
            [(cps.FW_IT_IP, "IT"), (cps.FW_OT_IP, "OT"), (cps.FW_MGMT_IP, "MGMT")],
        )
        self.assertEqual(kg.addresses(self.g, "soc"), [(cps.SOC_IP, "MGMT")])
        # Passive OT NIC: the sensor is in OT but has no address there.
        self.assertEqual(kg.addresses(self.g, "sensor"), [(cps.SENSOR_MGMT_IP, "MGMT")])
        self.assertEqual(kg.host_of_ip(self.g, cps.ENGINE_IP), "engine")
        self.assertEqual(kg.host_of_ip(self.g, "10.99.0.1"), None)

    def test_registers_and_permissions(self):
        exposed = [
            v for _, v, k in self.g.out_edges("svc:engine/modbus", keys=True) if k == "exposes"
        ]
        self.assertEqual(len(exposed), reg.ACTUATOR_COUNT + reg.SENSOR_COUNT)
        self.assertTrue(self.g.nodes[hr(reg.HR_CTRL_MODE)]["sensitive"])
        writes = {
            h: sorted(v for _, v, k in self.g.out_edges(f"host:{h}", keys=True) if k == "may_write")
            for h in ("plc", "hmi", "attacker")
        }
        self.assertEqual(writes["plc"], [hr(reg.HR_DG_SETPOINT)])
        self.assertEqual(writes["hmi"], sorted([hr(reg.HR_DG_SETPOINT), hr(reg.HR_CTRL_MODE)]))
        self.assertEqual(writes["attacker"], [])

    def test_boundary_rule_parsed(self):
        rules = kg.flow_rules(self.g)
        self.assertEqual(self.g.nodes["host:firewall"]["forward_default"], "DROP")
        self.assertEqual(len(rules), 1)
        r = rules[0]
        self.assertEqual(
            (r["src"], r["dst"], r["proto"], r["dport"], r["action"]),
            (cps.HMI_IP, cps.ENGINE_IP, "tcp", cps.MODBUS_PORT, "ACCEPT"),
        )
        dst = [v for _, v, k in self.g.out_edges(r["id"], keys=True) if k == "dst"]
        self.assertEqual(dst, ["svc:engine/modbus"])

    def test_functions_are_what_the_lab_does(self):
        fs = kg.functions(self.g)
        mode, setpoint = hr(reg.HR_CTRL_MODE), hr(reg.HR_DG_SETPOINT)
        self.assertEqual(
            {f for f in fs if f.startswith("write:")},
            {f"write:hmi:{mode}", f"write:hmi:{setpoint}", f"write:plc:{setpoint}"},
        )
        self.assertIn("on:hmi:IT", fs)
        self.assertNotIn("on:sensor:OT", fs, "a passive NIC is no presence to lose")
        self.assertEqual(
            kg.function_label(self.g, f"write:hmi:{mode}"), "hmi's control of ctrl_mode"
        )

    def test_a_drop_at_the_boundary_takes_the_hmi_control_only(self):
        g2 = kg.with_effects(
            self.g, [[kg.DROP, "firewall", cps.HMI_IP, cps.ENGINE_IP, cps.MODBUS_PORT]]
        )
        self.assertFalse(kg.reachable(g2, "hmi", "engine", cps.MODBUS_PORT))
        lost = kg.functions(self.g) - kg.functions(g2)
        self.assertEqual({f.split(":")[1] for f in lost}, {"hmi"}, lost)
        self.assertTrue(all(f.startswith("write:") for f in lost), lost)
        # The graph the SOC reasons on is the lab as it stands, not as a
        # response it only weighed would leave it.
        self.assertTrue(kg.reachable(self.g, "hmi", "engine", cps.MODBUS_PORT))

    def test_an_interface_down_takes_the_presence_and_what_went_through_it(self):
        g2 = kg.with_effects(self.g, [[kg.DETACH, "hmi", "eth0"]])
        self.assertEqual(kg.addresses(g2, "hmi"), [(cps.HMI_MGMT_IP, "MGMT")])
        lost = kg.functions(self.g) - kg.functions(g2)
        self.assertIn("on:hmi:IT", lost)
        self.assertEqual(len([f for f in lost if f.startswith("write:hmi:")]), 2, lost)
        with self.assertRaises(ValueError):
            kg.with_effects(self.g, [["reboot", "hmi"]])

    def test_reachability(self):
        P, A = cps.MODBUS_PORT, cps.APP_PORT
        self.assertTrue(kg.reachable(self.g, "hmi", "engine", P))  # sanctioned flow
        self.assertFalse(kg.reachable(self.g, "attacker", "engine", P))  # default DROP
        self.assertTrue(kg.reachable(self.g, "attacker", "hmi", A))  # same zone
        self.assertTrue(kg.reachable(self.g, "plc", "engine", P))  # same zone
        self.assertFalse(kg.reachable(self.g, "sensor", "engine", P))  # no OT address
        self.assertFalse(kg.reachable(self.g, "hmi", "engine", 502))  # no such service
        self.assertFalse(kg.reachable(self.g, "soc", "engine", P))  # MGMT is not forwarded

    def test_management_network_membership(self):
        on_mgmt = sorted(
            self.g.nodes[h]["name"]
            for h in kg.hosts(self.g)
            if "MGMT" in {z for _, z in kg.addresses(self.g, self.g.nodes[h]["name"])}
        )
        self.assertEqual(on_mgmt, ["ews", "firewall", "hmi", "sensor", "soc"])
        # Besides the boundary device, which forwards nothing between them, the
        # hosts with one foot in IT and one in MGMT are those an attacker can
        # take that also report to the SOC: the HMI and the workstation.
        it_and_mgmt = [
            h
            for h in on_mgmt
            if "IT" in {z for _, z in kg.addresses(self.g, h)}
            and self.g.nodes[f"host:{h}"]["role"] != kg.BOUNDARY_ROLE
        ]
        self.assertEqual(it_and_mgmt, ["ews", "hmi"])

    def test_rule_removal_cuts_the_path(self):
        rules = [r for r in cps.firewall_rules() if "--dport" not in r]
        g = kg.build_kg(cps_inv.inventory(rules=rules))
        self.assertFalse(kg.reachable(g, "hmi", "engine", cps.MODBUS_PORT))

    def test_json_roundtrip(self):
        g2 = kg.from_json(kg.to_json(self.g))
        self.assertEqual(sorted(g2.nodes), sorted(self.g.nodes))
        self.assertEqual(g2.number_of_edges(), self.g.number_of_edges())
        self.assertTrue(kg.reachable(g2, "hmi", "engine", cps.MODBUS_PORT))


class PlantOfSeveralFeeders(unittest.TestCase):
    """The plant the inventory carries: a feeder per Modbus unit, each with its
    own registers, and each controller bound to its own."""

    def setUp(self):
        plant = reg.plant()
        second = dict(plant["feeders"][0], unit=2, dg_rating_kw=80.0)
        plant["feeders"].append(second)
        inv = cps_inv.inventory(plant=plant)
        for h in inv["hosts"]:
            if h["name"] == "plc":
                h["unit"] = 2
        self.g = kg.build_kg(inv)

    def test_every_feeder_has_its_registers_with_its_own_envelope(self):
        self.assertEqual(kg.feeders(self.g), [1, 2])
        self.assertEqual(self.g.nodes[hr(reg.HR_DG_SETPOINT, 2)]["hi"], 80.0)
        self.assertEqual(self.g.nodes[hr(reg.HR_DG_SETPOINT, 1)]["hi"], 60.0)
        exposed = [
            v for _u, v, k in self.g.out_edges("svc:engine/modbus", keys=True) if k == "exposes"
        ]
        self.assertEqual(len(exposed), 2 * (reg.ACTUATOR_COUNT + reg.SENSOR_COUNT))

    def test_a_controller_writes_its_own_feeder_only(self):
        writes = sorted(
            v for _u, v, k in self.g.out_edges("host:plc", keys=True) if k == "may_write"
        )
        self.assertEqual(writes, [hr(reg.HR_DG_SETPOINT, 2)])

    def test_the_limits_travel_with_the_graph(self):
        self.assertEqual(self.g.graph["limits"]["v_band"], [0.95, 1.05])


if __name__ == "__main__":
    unittest.main()
