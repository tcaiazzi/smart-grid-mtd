"""The CPS lab as data (cyberrange/scenarios/cps/lab.py) and the features a
scenario composes on it (feature.py). The default lab is covered by the frozen
deploy snapshots; this is about another lab — two substations — and about the
constraints a spec refuses to break, so that the next, larger scenario is a new
LabSpec and not new code.

Run: `.venv/bin/python -m pytest tests/scenarios/cps/test_cps_lab.py`.
"""

import ipaddress
import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)

import soar_kg as kg  # noqa: E402  (flat guest import, needs the path set above)

from cyberrange.core.cli import default_args  # noqa: E402
from cyberrange.core.topology import build_lab  # noqa: E402
from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402
from cyberrange.scenarios.cps import topology as T  # noqa: E402
from cyberrange.scenarios.cps.lab import Flow, Host, LabSpec, Nic, Service, Zone  # noqa: E402
from cyberrange.scenarios.cps.scenario import CpsScenario  # noqa: E402
from cyberrange.scenarios.cps_advisor.feature import People  # noqa: E402
from cyberrange.scenarios.cps_recon.feature import Recon  # noqa: E402
from cyberrange.scenarios.cps_soc.feature import SocTools  # noqa: E402

MODBUS = Service("modbus", "tcp", 5020, "modbus")


def two_substations():
    """The default lab's control centre with two substations, each on its own
    OT network behind the same boundary: an HMI per substation, each allowed to
    its own engine only."""
    return LabSpec(
        name="cps2",
        zones=(
            Zone("IT", "10.10.0.0/24"),
            Zone("OTA", "10.20.0.0/24"),
            Zone("OTB", "10.21.0.0/24"),
            Zone("MGMT", "10.30.0.0/24", routed=False),
        ),
        hosts=(
            Host("attacker", "it-host", [Nic("IT", 10)]),
            Host("hmia", "hmi", [Nic("IT", 20), Nic("MGMT", 30)], profile="hmi"),
            Host("hmib", "hmi", [Nic("IT", 21), Nic("MGMT", 31)], profile="hmi"),
            Host(
                "firewall", "boundary", [Nic("IT", 1), Nic("OTA", 1), Nic("OTB", 1), Nic("MGMT", 1)]
            ),
            Host("plca", "plc", [Nic("OTA", 10)], profile="plc"),
            Host("enginea", "plant", [Nic("OTA", 20)], [MODBUS], profile="engine"),
            Host("plcb", "plc", [Nic("OTB", 10)], profile="plc"),
            Host("engineb", "plant", [Nic("OTB", 20)], [MODBUS], profile="engine"),
            Host("sensor", "sensor", [Nic("OTA"), Nic("OTB"), Nic("MGMT", 10)]),
            Host("soc", "soc", [Nic("MGMT", 20)], image=T.SOC_IMAGE),
        ),
        boundary="firewall",
        flows=(Flow("hmia", "enginea", "modbus"), Flow("hmib", "engineb", "modbus")),
    )


class AnotherLab(unittest.TestCase):
    def setUp(self):
        self.spec = two_substations()
        self.topo = T.topology(T.default_args(), name="cps2", spec=self.spec)
        _lab, self.machines, self.startups = build_lab(self.topo)

    def test_every_host_becomes_a_node_with_its_profiles_files(self):
        self.assertEqual(sorted(self.machines), sorted(h.name for h in self.spec.hosts))
        files = {n.name: [g for _h, g in n.files] for n in self.topo.nodes}
        self.assertIn("/modbus_engine.py", files["engineb"], "a second engine runs nothing")
        self.assertIn("/plc_controller.py", files["plcb"])

    def test_each_substation_routes_through_the_boundary(self):
        self.assertIn("ip route add default via 10.21.0.1 dev eth0", self.startups["engineb"])
        self.assertIn("ip route add default via 10.10.0.1 dev eth0", self.startups["hmib"])
        self.assertFalse(
            any("ip route" in c for c in self.startups["soc"]),
            "the SOC stands only where nothing is forwarded: a route would lead nowhere",
        )

    def test_the_boundary_lets_each_hmi_to_its_own_engine_only(self):
        allow = [r for r in self.spec.boundary_rules() if "-j ACCEPT" in r and "-s " in r]
        self.assertEqual(
            allow,
            [
                "iptables -A FORWARD -s 10.10.0.20 -d 10.20.0.20 -p tcp --dport 5020 -j ACCEPT",
                "iptables -A FORWARD -s 10.10.0.21 -d 10.21.0.20 -p tcp --dport 5020 -j ACCEPT",
            ],
        )
        self.assertIn("iptables -P FORWARD DROP", self.startups["firewall"])

    def test_addresses_are_unique_and_inside_their_zone(self):
        seen = set()
        for h in self.spec.hosts:
            for nic in h.nics:
                if nic.passive:
                    continue
                addr = self.spec.address(nic)
                self.assertNotIn(addr, seen)
                seen.add(addr)
                self.assertIn(
                    ipaddress.ip_address(addr), ipaddress.ip_network(self.spec.zone(nic.zone).cidr)
                )

    def test_the_sensor_is_passive_on_both_substations(self):
        self.assertEqual(self.spec.addresses("sensor"), {"eth2": "10.30.0.10/24"})
        self.assertEqual(sum("promisc on" in c for c in self.startups["sensor"]), 2)

    def test_the_soc_reasons_about_it(self):
        g = kg.build_kg(cps_inv.inventory(self.spec))
        self.assertEqual(len(kg.hosts(g)), len(self.spec.hosts))
        self.assertTrue(kg.reachable(g, "hmia", "enginea", 5020))
        self.assertFalse(
            kg.reachable(g, "hmia", "engineb", 5020), "an HMI reaches the other substation"
        )
        self.assertFalse(kg.reachable(g, "attacker", "enginea", 5020))

    def test_the_agents_are_the_hosts_on_the_socs_network(self):
        self.assertEqual(sorted(T.wazuh_agents(self.spec)), ["firewall", "hmia", "hmib", "sensor"])


class SpecRefuses(unittest.TestCase):
    """What the rest of the system relies on, checked where a lab is declared."""

    def spec(self, **over):
        base = dict(
            name="x",
            zones=(Zone("IT", "10.10.0.0/24"), Zone("MGMT", "10.30.0.0/24", routed=False)),
            hosts=(
                Host("fw", "boundary", [Nic("IT", 1), Nic("MGMT", 1)]),
                Host("a", "it-host", [Nic("IT", 10)]),
            ),
            boundary="fw",
        )
        return LabSpec(**(base | over))

    def test_two_hosts_on_one_address(self):
        hosts = (Host("fw", "boundary", [Nic("IT", 1)]), Host("a", "it-host", [Nic("IT", 1)]))
        with self.assertRaisesRegex(ValueError, "share 10.10.0.1"):
            self.spec(hosts=hosts)

    def test_a_primary_address_that_does_not_sort_first(self):
        # The knowledge graph would take the MGMT address for the host's own.
        hosts = (
            Host("fw", "boundary", [Nic("IT", 1)]),
            Host("a", "hmi", [Nic("MGMT", 5), Nic("IT", 5)]),
        )
        with self.assertRaisesRegex(ValueError, "does not sort first"):
            self.spec(hosts=hosts)

    def test_a_name_kathara_refuses(self):
        hosts = (Host("fw", "boundary", [Nic("IT", 1)]), Host("iris-db", "x", [Nic("IT", 9)]))
        with self.assertRaisesRegex(ValueError, "'-'"):
            self.spec(hosts=hosts)

    def test_an_address_outside_the_zone(self):
        hosts = (Host("fw", "boundary", [Nic("IT", 1)]), Host("a", "x", [Nic("IT", 300)]))
        with self.assertRaisesRegex(ValueError, "outside"):
            self.spec(hosts=hosts)

    def test_a_flow_to_a_service_nobody_serves(self):
        with self.assertRaises(KeyError):
            self.spec(flows=(Flow("a", "fw", "modbus"),))


class Features(unittest.TestCase):
    """A combination no scenario declares today: the SOC's tools and a recon
    attacker on one lab. It is a tuple, not a class."""

    class Both(CpsScenario):
        name = lab_name = "cpsboth"
        features = (SocTools(), People(console=False), Recon())
        DEFAULT_RESPOND = "solver"
        DEFAULT_APPROVAL = "operator:60"

    def test_they_compose_on_one_lab(self):
        s = self.Both()
        args = default_args(s)
        s.prepare(args)
        s.validate(args)
        topo = s.topology(args)
        nodes = {n.name: n for n in topo.nodes}
        self.assertIn("indexer", nodes)
        self.assertEqual(topo.image_of(nodes["attacker"]), "kathara/redteam")
        self.assertEqual(topo.image_of(nodes["soc"]), "kathara/soc-siem")
        soc_files = [g for _h, g in nodes["soc"].files]
        self.assertLess(
            soc_files.index("/belief_feed.py"),
            soc_files.index("/team-access.sh"),
            "the features' files are not in the order the scenario lists them",
        )
        self.assertEqual(type(s.attacker(args)).__name__, "ReconAttacker")
        api = s.operator_api(args)
        self.assertEqual(api["iris"]["url"], "https://iris.lab")
        self.assertNotIn("operator_port", api)

    def test_two_features_cannot_publish_one_port(self):
        s = self.Both()
        args = default_args(s, cases_port=8767)  # the blue team's shell
        with self.assertRaises(SystemExit):
            s.validate(args)

    def test_two_images_for_one_node_are_refused(self):
        a, b = T.Extra(image="x"), T.Extra(image="y")
        with self.assertRaises(ValueError):
            a.merged(b)


if __name__ == "__main__":
    unittest.main()
