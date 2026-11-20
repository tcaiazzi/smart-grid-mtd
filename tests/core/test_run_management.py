"""How a run is kept (core/lifecycle.py, core/paths.py, core/runcard.py): the
directory it claims, the card and the score it leaves there, and what happens
when a service it cannot do without dies — the cps scenario on the fake lab, so
no Docker.

Run: `.venv/bin/python -m pytest tests/core/test_run_management.py`.
"""

import json
import os
import tempfile
import unittest

from cyberrange.core import lifecycle, paths, runcard
from cyberrange.core.cli import default_args
from cyberrange.scenarios.cps import cli as cps
from cyberrange.scenarios.cps import scenario as cps_scenario
from cyberrange.scenarios.cps_advisor.scenario import CpsAdvisorScenario
from tests.helpers.kathara import FakeManager, fake_downloads


def frame(i):
    return {"step": i, "timestamp": 1000.0 + i, "v_dg": 1.0, "v_load": 1.0, "abnormal": 0}


class ADirectoryOfItsOwn(unittest.TestCase):
    """Two runs in one directory share a ledger and overwrite each other's
    artifacts: what is left is neither run."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="runs-")

    def test_a_run_told_nowhere_gets_a_new_directory_and_latest_points_at_it(self):
        first = paths.new_run_dir(self.root, "cps", now=1_700_000_000)
        second = paths.new_run_dir(self.root, "cps", "probe", now=1_700_000_060)
        self.assertTrue(os.path.isdir(first) and os.path.isdir(second))
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith("-probe"))
        self.assertEqual(os.path.dirname(first), os.path.join(self.root, "cps", "runs"))
        latest = os.path.join(self.root, "cps", "latest")
        self.assertEqual(os.path.realpath(latest), os.path.realpath(second))

    def test_two_runs_started_in_the_same_second_do_not_share_one(self):
        a = paths.new_run_dir(self.root, "cps", now=1_700_000_000)
        b = paths.new_run_dir(self.root, "cps", now=1_700_000_000)
        self.assertNotEqual(a, b)

    def test_a_real_directory_called_latest_is_left_alone(self):
        mine = os.path.join(self.root, "cps", "latest")
        os.makedirs(mine)
        paths.new_run_dir(self.root, "cps")
        self.assertFalse(os.path.islink(mine), "someone's directory was replaced by a link")

    def claim(self, **over):
        s = cps_scenario.CpsScenario()
        args = default_args(s, out_root=self.root, **over)
        return lifecycle.claim_run_dir(s, args), args

    def test_a_directory_that_holds_a_run_is_refused(self):
        taken, _args = self.claim()
        with open(os.path.join(taken, "progress.jsonl"), "w") as f:
            f.write("{}\n")
        with open(os.path.join(taken, "ground_truth.jsonl"), "w") as f:
            f.write("the first run's\n")
        with self.assertRaises(lifecycle.RunDirTaken) as why:
            self.claim(out_dir=taken)
        self.assertIn("--overwrite", str(why.exception))
        self.assertTrue(
            os.path.exists(os.path.join(taken, "ground_truth.jsonl")),
            "a refused run still touched the run that was there",
        )
        again, _args = self.claim(out_dir=taken, overwrite=True)
        self.assertEqual(again, taken)
        self.assertFalse(os.path.exists(os.path.join(taken, "ground_truth.jsonl")))

    def test_an_empty_directory_named_by_hand_is_taken_as_it_is(self):
        mine = os.path.join(self.root, "mine")
        self.assertEqual(self.claim(out_dir=mine)[0], mine)

    def test_a_scenario_that_keeps_several_runs_in_one_directory_still_may(self):
        class Shared(cps_scenario.CpsScenario):
            one_run_per_dir = False

        d = tempfile.mkdtemp()
        open(os.path.join(d, "progress.jsonl"), "w").close()
        args = default_args(Shared(), out_dir=d)
        self.assertEqual(lifecycle.claim_run_dir(Shared(), args), d)


class WhatARunLeaves(unittest.TestCase):
    def setUp(self):
        self._settle = cps_scenario.SERVICE_SETTLE_S
        cps_scenario.SERVICE_SETTLE_S = 0.0
        self.addCleanup(setattr, cps_scenario, "SERVICE_SETTLE_S", self._settle)
        self.root = tempfile.mkdtemp(prefix="runs-")

    def run_it(self, mgr=None, **over):
        args = default_args(
            cps_scenario.CpsScenario(),
            out_root=self.root,
            seed=1,
            normal_duration=0.2,
            learn_seconds=0.1,
            poll_interval=0.05,
            **over,
        )
        mgr = mgr or FakeManager(frames=[frame(i) for i in range(1, 50)])
        with fake_downloads():
            rc = cps.run(args, manager=mgr)
        return rc, args

    def test_its_card_says_what_it_was_made_with_and_how_it_ended(self):
        rc, args = self.run_it(run_name="probe")
        self.assertEqual(rc, 0)
        self.assertTrue(args.out_dir.startswith(os.path.join(self.root, "cps", "runs")))
        card = runcard.read(args.out_dir)
        self.assertEqual(
            (card["scenario"], card["run_id"]), ("cps", os.path.basename(args.out_dir))
        )
        for key in ("commit", "dirty", "python"):
            self.assertIn(key, card["code"])
        self.assertEqual(card["options"]["seed"], 1)
        self.assertTrue(card["lab"]["topology"], "the card does not say which lab was deployed")
        self.assertIn("kathara/cps", card["lab"]["images"])
        self.assertEqual(card["outcome"]["status"], "ok")
        self.assertEqual(card["outcome"]["components_down"], [])

    def test_its_score_is_kept_next_to_its_artifacts(self):
        _rc, args = self.run_it()
        with open(os.path.join(args.out_dir, "metrics.json")) as f:
            m = json.load(f)
        self.assertEqual(m["run"]["run_id"], os.path.basename(args.out_dir))
        self.assertEqual(
            m["run"]["card"]["topology"], runcard.read(args.out_dir)["lab"]["topology"]
        )
        self.assertTrue(os.path.exists(os.path.join(args.out_dir, "metrics.md")))

    def test_a_service_found_dead_fails_the_run_and_says_which(self):
        # pgrep answers 1, "nothing matched", for the SOC's analytics only.
        mgr = FakeManager(
            frames=[frame(i) for i in range(1, 50)],
            responses={"pgrep -f [s]oc_analytics.py": (b"", b"", 1)},
        )
        with self.assertRaises(lifecycle.ComponentDown) as why:
            self.run_it(mgr, respond="rules")
        self.assertIn("soc_analytics", str(why.exception))
        run_dir = os.path.realpath(os.path.join(self.root, "cps", "latest"))
        with open(os.path.join(run_dir, "progress.jsonl")) as f:
            evs = [json.loads(line) for line in f]
        self.assertEqual(
            [e["component"] for e in evs if e["kind"] == "component_down"],
            ["soc_analytics"],
            "the ledger does not say which component died",
        )
        self.assertEqual(
            evs[-1]["status"],
            "failed",
            "a run whose SOC was not running is on record as a valid one",
        )
        self.assertEqual(runcard.read(run_dir)["outcome"]["components_down"], ["soc_analytics"])
        self.assertEqual(mgr.undeployed[-1], "cps", "the lab of a failed run was left up")
        self.assertFalse(os.path.exists(os.path.join(run_dir, "metrics.json")))

    def test_a_node_that_cannot_say_is_not_a_dead_component(self):
        mgr = FakeManager(
            frames=[frame(i) for i in range(1, 50)],
            responses={"pgrep -f": (b"", b"sh: pgrep: not found", 127)},
        )
        self.assertEqual(self.run_it(mgr)[0], 0)


class TheCard(unittest.TestCase):
    def test_a_secret_option_is_not_kept_with_the_run(self):
        s = CpsAdvisorScenario()
        args = default_args(s, teams=True, playground=True, blue_token="b1ue", red_token="r3d")
        kept = json.dumps(runcard.options(args, s.secret_options(args)))
        self.assertNotIn("b1ue", kept, "a team's token is in a file kept with the run")
        self.assertNotIn("r3d", kept)
        self.assertIn(runcard.MASKED, kept)

    def test_two_games_played_under_the_same_terms_have_the_same_card(self):
        s = CpsAdvisorScenario()
        both = dict(teams=True, red_harness="scripted", blue_harness="scripted")
        a = s.run_card(default_args(s, **both))
        b = s.run_card(default_args(s, **both, seed=7))
        self.assertEqual(a, b)
        for key in ("seat_adapter", "player_kit", "briefing_red", "briefing_blue"):
            self.assertTrue(a[key], f"the card does not fingerprint {key}")
        longer = s.run_card(default_args(s, **both, engagement_s=60))
        self.assertNotEqual(
            a["briefing_red"],
            longer["briefing_red"],
            "two games with different clocks are on record as played under the same terms",
        )
        self.assertEqual(s.run_card(default_args(s)), {})

    def test_the_runs_under_a_root_are_listed_oldest_first(self):
        root = tempfile.mkdtemp(prefix="runs-")
        for name, started, status in (("b", 200.0, "ok"), ("a", 100.0, "failed")):
            runcard.write(
                os.path.join(root, "cps", "runs", name),
                {"scenario": "cps", "started": started, "outcome": {"status": status}},
            )
        found = runcard.runs(root)
        self.assertEqual([os.path.basename(r["dir"]) for r in found], ["a", "b"])
        self.assertEqual(runcard.runs(root, "cps-advisor"), [])
        text = runcard.format_runs(found, lambda name, card, metrics: f"scored: {metrics}")
        self.assertIn("failed", text.splitlines()[0])
        self.assertIn("scored: None", text)


if __name__ == "__main__":
    unittest.main()
