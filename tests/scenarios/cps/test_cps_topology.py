"""Topology test for the cyber-physical Kathará lab builder
(cyberrange/scenarios/cps/topology.py on core.topology). Builds the Lab model in-process
(no Docker) and asserts the zones, the IT/OT boundary firewall, the management
network and the passive-sensor wiring are correct.

Run: `.venv/bin/python -m unittest tests.test_cps_topology`.
"""

import types
import unittest


from cyberrange.scenarios.cps import topology as cps  # noqa: E402
from cyberrange.scenarios.cps.scenario import CpsScenario  # noqa: E402


def _links(machine):
    return {idx: iface.link.name for idx, iface in machine.interfaces.items()}


class Topology(unittest.TestCase):
    def setUp(self):
        self.lab, self.m, self.startups = cps.build_lab(types.SimpleNamespace(dashboard_port=0))

    def test_machines_on_cps_image(self):
        self.assertEqual(
            sorted(self.lab.machines),
            ["attacker", "engine", "firewall", "hmi", "plc", "sensor", "soc"],
        )
        for name, mach in self.lab.machines.items():
            # The manager is too heavy for every node: only the SOC carries it.
            self.assertEqual(mach.get_image(), cps.SOC_IMAGE if name == "soc" else cps.IMAGE, name)

    def test_agents_only_on_management_hosts(self):
        for name in cps.WAZUH_AGENTS:
            self.assertIn(
                cps.MGMT,
                _links(self.m[name]).values(),
                f"{name} runs an agent but cannot reach the manager",
            )
        # Nothing on the plant: it is watched from the wire, acted on from the boundary.
        self.assertFalse({"engine", "plc"} & set(cps.WAZUH_AGENTS))

    def test_zones(self):
        self.assertEqual(_links(self.m["attacker"]), {0: cps.IT})
        self.assertEqual(_links(self.m["hmi"]), {0: cps.IT, 1: cps.MGMT})
        self.assertEqual(_links(self.m["firewall"]), {0: cps.IT, 1: cps.OT, 2: cps.MGMT})
        self.assertEqual(_links(self.m["plc"]), {0: cps.OT})
        self.assertEqual(_links(self.m["engine"]), {0: cps.OT})
        self.assertEqual(_links(self.m["sensor"]), {0: cps.OT, 1: cps.MGMT})
        self.assertEqual(_links(self.m["soc"]), {0: cps.MGMT})

    def test_plant_is_not_on_the_management_network(self):
        for name in ("engine", "plc", "attacker"):
            self.assertNotIn(
                cps.MGMT,
                _links(self.m[name]).values(),
                f"{name} on MGMT: a host there could reach it without crossing the firewall",
            )

    def test_hmi_keeps_it_on_eth0(self):
        # isolate_hmi takes eth0 down; if MGMT were eth0 the response would cut
        # the HMI off from the SOC and leave the attacker's IT link up.
        self.assertEqual(_links(self.m["hmi"])[0], cps.IT)

    def test_nothing_is_forwarded_to_or_from_mgmt(self):
        accepts = [r for r in cps.firewall_rules() if "-j ACCEPT" in r and "ESTABLISHED" not in r]
        for r in accepts:
            self.assertNotIn("10.30.", r, "a forward rule opens the management network")

    def test_sensor_page_is_closed_on_mgmt(self):
        self.assertIn(
            f"iptables -A INPUT -i eth1 -p tcp --dport {cps.DASHBOARD_GUEST_PORT} -j DROP",
            self.startups["sensor"],
            "the sensor's live page would answer on MGMT, readable from the HMI",
        )

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

    def test_sensor_startup_passive_ot_addressed_mgmt(self):
        cmds = self.startups["sensor"]
        self.assertTrue(any("promisc on" in c for c in cmds))
        self.assertTrue(any(f"{cps.SENSOR_MGMT_IP}/24 dev eth1" in c for c in cmds))
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

    def test_a_scenario_built_on_the_lab_adds_to_its_nodes_without_changing_it(self):
        self.assertIsNone(self.m["soc"].meta.get("bridged"))
        self.assertEqual([c for c in self.startups["soc"] if "iptables" in c], [])
        extras = {
            "soc": cps.Extra(
                files=[("nodes/soc/soc_console.html", "/soc_console.html")],
                ports=["8766:8090/tcp", "8767:8091/tcp"],
                startup=cps.closed_on("eth0", 8090, 8091),
            )
        }
        topo = cps.topology(cps.default_args(), name="other", extras=extras)
        self.assertEqual(topo.name, "other")
        _lab, m, startups = cps._build(topo)
        self.assertEqual(m["soc"].meta["ports"], {(8766, "tcp"): 8090, (8767, "tcp"): 8091})
        self.assertIn(
            "iptables -A INPUT -i eth0 -p tcp --dport 8090 -j DROP",
            startups["soc"],
            "the SOC's console would answer on MGMT: the HMI, the attacker's foothold, "
            "could approve or reject in the operator's place",
        )
        soc = next(n for n in topo.nodes if n.name == "soc")
        self.assertIn(("nodes/soc/soc_console.html", "/soc_console.html"), soc.files)
        # The lab itself is untouched by having been extended once.
        again = next(n for n in cps.topology(cps.default_args()).nodes if n.name == "soc")
        self.assertNotIn(("nodes/soc/soc_console.html", "/soc_console.html"), again.files)

    def test_a_published_attacker_keeps_its_route_into_the_lab(self):
        extras = {"attacker": cps.Extra(ports=["8768:8090/tcp"])}
        _lab, _m, startups = cps._build(cps.topology(cps.default_args(), extras=extras))
        self.assertIn(
            f"ip route replace default via {cps.FW_IT_IP} dev eth0",
            startups["attacker"],
            "next to the bridged NIC's default route an `ip route add` fails, and the "
            "attacker loses its way to the lab",
        )
        self.assertIn(
            f"ip route add default via {cps.FW_IT_IP} dev eth0", self.startups["attacker"]
        )

    def test_a_person_cannot_be_asked_in_this_scenario(self):
        with self.assertRaises(SystemExit):
            CpsScenario().check_approval("operator:60")


if __name__ == "__main__":
    unittest.main()
