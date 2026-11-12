"""The cps-advisor scenario (cyberrange/scenarios/cps_advisor): the cps lab under
its own name, with the SOC's operator API published, and an episode whose SOC
advises — run with the fake Kathará manager, so no Docker.

Run: `.venv/bin/python -m pytest tests/scenarios/cps_advisor`.
"""

import tempfile
import unittest

from cyberrange.core import registry
from cyberrange.core.cli import default_args
from cyberrange.core.topology import build_lab
from cyberrange.planes.defense.components import SocAnalytics
from cyberrange.scenarios.cps import scenario as cps_scenario
from cyberrange.scenarios.cps import topology as cps_topology
from cyberrange.scenarios.cps_advisor import cli as advisor
from cyberrange.scenarios.cps_advisor.scenario import CpsAdvisorScenario
from tests.helpers.kathara import FakeManager, fake_downloads


class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, kind, **fields):
        self.events.append({"kind": kind, **fields})


class Options(unittest.TestCase):
    def setUp(self):
        self.s = CpsAdvisorScenario()
        self.args = default_args(self.s)

    def test_it_advises_by_default(self):
        self.assertEqual(registry.get("cps-advisor").name, "cps-advisor")
        self.assertEqual((self.args.respond, self.args.approval), ("solver", "operator:120"))
        self.assertEqual(self.args.out_dir, "output/cps-advisor/run-1")
        self.s.validate(self.args)

    def test_the_cps_defaults_are_untouched(self):
        cps = default_args(cps_scenario.CpsScenario())
        self.assertEqual((cps.respond, cps.approval), ("off", "auto"))
        self.assertEqual(cps.out_dir, "output/cps/run-1")

    def test_only_an_operator_may_decide_here(self):
        for approval in ("auto", "deny", "delay:5", "operator:0", "operator:x"):
            self.args.approval = approval
            with self.assertRaises(SystemExit, msg=approval):
                self.s.validate(self.args)

    def test_an_advisor_needs_a_policy_and_a_port(self):
        self.args.respond = "off"
        with self.assertRaises(SystemExit):
            self.s.validate(self.args)
        self.args.respond, self.args.operator_port = "rules", 0
        with self.assertRaises(SystemExit):
            self.s.validate(self.args)

    def test_each_run_gets_its_own_token_and_tells_the_console(self):
        self.s.prepare(self.args)
        first = self.args.operator_token
        self.assertGreaterEqual(len(first), 24)
        other = default_args(self.s)
        self.s.prepare(other)
        self.assertNotEqual(first, other.operator_token, "two runs share an operator token")
        info = self.s.run_info(self.args)
        self.assertEqual(info["operator_url"], "http://127.0.0.1:8766")
        self.assertEqual(info["operator_token"], first)
        self.args.operator_token = "chosen"
        self.s.prepare(self.args)
        self.assertEqual(self.args.operator_token, "chosen")


class Lab(unittest.TestCase):
    def test_same_lab_other_name_with_the_operator_api_published(self):
        s = CpsAdvisorScenario()
        topo = s.topology(default_args(s))
        self.assertEqual(topo.name, "cps-advisor", "it would undeploy a running cps lab")
        cps = cps_scenario.CpsScenario()
        self.assertEqual(
            [n.name for n in topo.nodes], [n.name for n in cps.topology(default_args(cps)).nodes]
        )
        _lab, machines, startups = build_lab(topo)
        self.assertEqual(
            machines["soc"].meta["ports"], {(8766, "tcp"): cps_topology.OPERATOR_GUEST_PORT}
        )
        self.assertTrue(any("--dport 8090 -j DROP" in c for c in startups["soc"]))


class Episode(unittest.TestCase):
    def setUp(self):
        self._settle = cps_scenario.SERVICE_SETTLE_S
        cps_scenario.SERVICE_SETTLE_S = 0.0
        self.addCleanup(setattr, cps_scenario, "SERVICE_SETTLE_S", self._settle)

    def test_the_soc_is_started_as_an_advisor(self):
        s = CpsAdvisorScenario()
        args = default_args(
            s,
            out_dir=tempfile.mkdtemp(prefix="cps-advisor-"),
            seed=1,
            normal_duration=0.2,
            learn_seconds=0.1,
            poll_interval=0.05,
        )
        col, mgr = Collector(), FakeManager()
        with fake_downloads():
            self.assertEqual(advisor.run(args, progress=col, manager=mgr), 0)
        self.assertEqual(mgr.deployed, ["cps-advisor"])
        start = col.events[0]
        self.assertEqual((start["scenario"], start["approval"]), ("cps-advisor", "operator:120"))
        soc = next(c for n, c, _w, _s in mgr.calls if n == "soc" and "soc_analytics.py" in c)
        self.assertIn("--policy solver --approval operator:120", soc)
        self.assertIn(f"--operator-port {cps_topology.OPERATOR_GUEST_PORT} ", soc)
        self.assertIn(f"--operator-token {args.operator_token}", soc)
        self.assertIn("--operator-origin http://127.0.0.1:8765", soc)


class Mirror(unittest.TestCase):
    def test_suggestions_and_answers_reach_the_ledger(self):
        soc = SocAnalytics("soc", {}, policy="rules", approval="operator:60")
        asked = {
            "t": 10.0,
            "kind": "approval",
            "request": "r1",
            "action": "block_flow",
            "state": "requested",
            "due_t": 70.0,
            "requested_t": 10.0,
            "explanation": {"rationale": "because"},
        }
        kind, fields = soc.mirror(asked)
        self.assertEqual(kind, "approval")
        self.assertEqual(fields["explanation"], {"rationale": "because"})
        self.assertEqual(
            (fields["request"], fields["due_t"], fields["guest_t"]), ("r1", 70.0, 10.0)
        )
        answered = {"t": 14.0, "kind": "approval", "request": "r1", "action": "block_flow"}
        answered |= {"state": "granted", "operator": "ada", "waited_s": 4.0}
        _kind, fields = soc.mirror(answered)
        self.assertEqual(
            (fields["state"], fields["operator"], fields["waited_s"]), ("granted", "ada", 4.0)
        )

    def test_a_soc_that_decides_alone_opens_no_api(self):
        self.assertNotIn("--operator", SocAnalytics("soc", {}, policy="rules").command)


if __name__ == "__main__":
    unittest.main()
