"""The cps-soc scenario: the cps-advisor lab, with the blue team on the tools of
a real SOC — Wazuh's indexer and dashboard, and DFIR-IRIS — each service on its
own node. Everything here runs without Docker: the lab is declared, the episode
driven against the in-process fake manager.

Run: `.venv/bin/python -m pytest tests/scenarios/cps_soc`
"""

import json
import os
import tempfile
import unittest

from cyberrange.core import registry
from cyberrange.core.cli import default_args
from cyberrange.core.topology import build_lab
from cyberrange.scenarios.cps import guest_files as cps_files
from cyberrange.scenarios.cps import inventory as cps_inv
from cyberrange.scenarios.cps import scenario as cps_scenario
from cyberrange.scenarios.cps_soc import cli as soc_cli
from cyberrange.scenarios.cps_soc.scenario import IDLE, IMAGES, CpsSocScenario
from tests.helpers.kathara import FakeManager, fake_downloads

TOOLS = ("indexer", "wazuhui", "irisweb", "irisapp", "irisworker", "irisdb", "irismq")


class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, kind, **fields):
        self.events.append({"kind": kind, **fields})


def args_of(scenario, **over):
    args = default_args(scenario, **over)
    scenario.prepare(args)
    return args


class Options(unittest.TestCase):
    def setUp(self):
        self.s = CpsSocScenario()

    def test_it_is_an_advisor_under_its_own_name(self):
        self.assertEqual(registry.get("cps-soc").lab_name, "cps-soc")
        args = default_args(self.s)
        self.assertEqual((args.respond, args.approval), ("solver", "operator:120"))
        self.assertEqual((args.siem_port, args.cases_port), (8770, 8771))
        self.s.validate(args)

    def test_the_tools_ports_cannot_take_the_teams(self):
        args = default_args(self.s, cases_port=8767)  # the blue team's shell
        with self.assertRaises(SystemExit):
            self.s.validate(args)

    def test_every_secret_is_fresh_and_none_reaches_the_ledger(self):
        args, other = args_of(self.s), args_of(self.s)
        secrets = args.soc_secrets
        self.assertEqual(len(set(secrets.values())), len(secrets), "two services share a secret")
        self.assertNotEqual(secrets["iris_key"], other.soc_secrets["iris_key"])
        told = json.dumps(self.s.run_info(args))
        for name, value in secrets.items():
            self.assertNotIn(value, told, f"{name} is on the ledger, which the red team may read")
        for name in ("blue", "iris_admin", "indexer_admin"):
            p = secrets[name]
            self.assertTrue(
                len(p) >= 12 and any(c.isupper() for c in p) and any(c.isdigit() for c in p),
                f"IRIS would refuse {name}'s password",
            )

    def test_no_password_reads_as_an_option(self):
        # token_urlsafe draws '-' as often as any other character: one run in 64
        # would hand the SOC an --iris-analyst-password it cannot parse.
        from cyberrange.scenarios.cps_soc.feature import password

        self.assertFalse(any(password().startswith("-") for _ in range(2000)))

    def test_the_blue_team_gets_the_siem_and_the_cases_not_the_console(self):
        args = args_of(self.s)
        blue = self.s.links(args)["blue"]
        self.assertNotIn("console", blue, "a console link to a console nobody serves")
        self.assertIn("https://127.0.0.1:8770/", blue["siem"])
        self.assertTrue(
            blue["attack tree"].startswith("https://127.0.0.1:8770/app/dashboards#/view/"),
            "the attack tree's link is not on the SIEM's published port",
        )
        self.assertNotIn(args.soc_secrets["blue"], blue["attack tree"])
        self.assertIn(f"blue / {args.soc_secrets['blue']}", blue["cases"])


class Lab(unittest.TestCase):
    def setUp(self):
        self.s = CpsSocScenario()
        self.topo = self.s.topology(args_of(self.s))
        _lab, self.machines, self.startups = build_lab(self.topo)
        self.nodes = {n.name: n for n in self.topo.nodes}

    def test_each_service_is_a_node_of_its_own_on_its_projects_image(self):
        for name in TOOLS:
            with self.subTest(node=name):
                self.assertEqual(self.nodes[name].image, IMAGES[name])
                self.assertEqual(
                    self.machines[name].meta.get("entrypoint"),
                    IDLE,
                    "the image's entrypoint would start the service before the lab set it up",
                )
        self.assertEqual(self.nodes["soc"].image, "kathara/soc-siem")
        self.assertIsNone(self.nodes["hmi"].entrypoint, "a cps node lost its own entrypoint")

    def test_irises_services_talk_on_their_own_network(self):
        for name in ("irisapp", "irisworker", "irisdb", "irismq"):
            self.assertEqual([f.link for f in self.nodes[name].ifaces], ["SOAR"], name)
        self.assertEqual([f.link for f in self.nodes["irisweb"].ifaces], ["SOAR", "MGMT"])

    def test_the_hmi_cannot_reach_the_tools_from_mgmt(self):
        self.assertIn("iptables -A INPUT -i eth0 -j DROP", self.startups["wazuhui"])
        self.assertIn("iptables -A INPUT -i eth0 -s 10.30.0.20 -j ACCEPT", self.startups["indexer"])
        self.assertIn("iptables -A INPUT -i eth1 -j DROP", self.startups["irisweb"])
        self.assertNotIn(
            "iptables -A INPUT -i eth1 -s 10.30.0.30 -j ACCEPT",
            self.startups["irisweb"],
            "the HMI, the attacker's foothold, may file tasks in IRIS",
        )

    def test_irises_app_and_worker_load_the_socs_module(self):
        for name in ("irisapp", "irisworker"):
            files = [g for _h, g in self.nodes[name].files]
            self.assertIn("/iris_modules/iris_soc_response/IrisSocResponse.py", files, name)
        soc = [g for _h, g in self.nodes["soc"].files]
        self.assertIn("/iris_orders.py", soc, "the desk could not read the module's orders")

    def test_the_siem_is_given_the_attack_tree(self):
        soc = [g for _h, g in self.nodes["soc"].files]
        for path in ("/belief_feed.py", "/soc_belief_rules.xml"):
            self.assertIn(path, soc, "the SOC's belief never becomes an alert")
        ui = [g for _h, g in self.nodes["wazuhui"].files]
        for path in (
            "/attack-tree.vega.json",
            "/knowledge-graph.vega.json",
            "/dashboard_objects.py",
        ):
            self.assertIn(path, ui, "the dashboard has no view to draw the tree or the graph with")
        # The cps and cps-advisor SOCs have no SIEM to feed.
        self.assertNotIn("/belief_feed.py", [g for _h, g in cps_files.SOC_FILES])

    def test_the_teams_reach_the_tools_on_published_ports(self):
        self.assertEqual(self.nodes["wazuhui"].mgmt_port, "8770:5601/tcp")
        self.assertEqual(self.nodes["irisweb"].mgmt_port, "8771:443/tcp")

    def test_the_tools_are_not_part_of_what_the_soc_protects(self):
        hosts = {h["name"] for h in cps_inv.inventory()["hosts"]}
        self.assertFalse(
            hosts & set(TOOLS), "the SOC's own tools entered its attack tree and inventory"
        )


class Episode(unittest.TestCase):
    def setUp(self):
        self._settle = cps_scenario.SERVICE_SETTLE_S
        cps_scenario.SERVICE_SETTLE_S = 0.0
        self.addCleanup(setattr, cps_scenario, "SERVICE_SETTLE_S", self._settle)
        self.out = tempfile.mkdtemp(prefix="cps-soc-")

    def started(self, mgr, node, needle):
        return next((c for n, c, _w, _s in mgr.calls if n == node and needle in c), None)

    def test_the_soc_files_its_suggestions_in_iris_and_the_tools_start(self):
        mgr = FakeManager(responses={"team-access.sh jump": (b"ssh-ed25519 AAAAkey soc\n", b"", 0)})
        s = CpsSocScenario()
        args = default_args(
            s, out_dir=self.out, seed=1, normal_duration=0.2, learn_seconds=0.1, poll_interval=0.05
        )
        col = Collector()
        with fake_downloads():
            self.assertEqual(soc_cli.run(args, progress=col, manager=mgr), 0)
        self.assertEqual(mgr.deployed, ["cps-soc"])
        secrets = args.soc_secrets
        soc = self.started(mgr, "soc", "soc_analytics.py")
        self.assertIn("--desk iris --iris-url https://iris.lab", soc)
        self.assertIn(f"--iris-key {secrets['iris_key']}", soc)
        self.assertIn(f"--iris-case {os.path.basename(self.out)}", soc)
        self.assertNotIn("--operator-port", soc, "a console nobody can reach")
        self.assertIn("--belief-feed /soc_belief.jsonl", soc, "the SIEM is told no belief")
        shipper = self.started(mgr, "soc", "wazuh-shipper")
        self.assertIn(f"INDEXER_PASSWORD={secrets['indexer_shipper']}", shipper)
        self.assertNotIn(secrets["indexer_admin"], shipper, "the shipper writes as the admin")
        self.assertIn(
            f"SHIPPER_PASSWORD={secrets['indexer_shipper']}",
            self.started(mgr, "indexer", "start.sh"),
        )
        self.assertIn("wazuh-indexer-start.sh", self.started(mgr, "indexer", "start.sh"))
        self.assertIn("wazuh-dashboard-start.sh", self.started(mgr, "wazuhui", "start.sh"))
        for node, role in (("irisdb", "db"), ("irismq", "mq"), ("irisapp", "app"),
                           ("irisworker", "worker"), ("irisweb", "web")):  # fmt: skip
            self.assertIn(f"/iris-start.sh {role}", self.started(mgr, node, "iris-start.sh"), node)
        app = self.started(mgr, "irisapp", "iris-start.sh")
        self.assertIn(f"IRIS_ADM_API_KEY={secrets['iris_key']}", app)
        self.assertIn("POSTGRES_SERVER=10.40.0.20", app)
        self.assertIn("PYTHONPATH=/iris_modules", app, "IRIS would not find the SOC's module")
        forwarder = self.started(mgr, "soc", "wazuh-iris-integration.sh")
        self.assertIn("IRIS_URL=https://iris.lab", forwarder)
        self.assertIn(f"IRIS_KEY={secrets['iris_key']}", forwarder)
        with open(os.path.join(self.out, "teams.json")) as f:
            self.assertIn(secrets["blue"], json.load(f)["blue"]["cases"])
        told = json.dumps(col.events)
        for name, value in secrets.items():
            self.assertNotIn(value, told, f"{name} reached the ledger")


if __name__ == "__main__":
    unittest.main()
