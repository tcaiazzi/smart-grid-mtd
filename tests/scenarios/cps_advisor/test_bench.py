"""The benchmark of harnesses (cyberrange/scenarios/cps_advisor/campaign.py):
the grid it plays, who sits where in each game, and what it leaves — with the
runs and their scores faked, so no lab and no model.

Run: `.venv/bin/python -m pytest tests/scenarios/cps_advisor/test_bench.py`.
"""

import json
import os
import tempfile
import types
import unittest
from unittest import mock

from cyberrange.core.progress import read_events
from cyberrange.scenarios.cps.metrics import compute_metrics
from cyberrange.scenarios.cps_advisor import campaign as bench


def cfg(root, **over):
    base = dict(
        name="t",
        out_root=root,
        harness="scripted",
        sides="red,blue",
        opponents=None,
        seeds="1-2",
        retries=1,
        resume=True,
        engagement_s=30.0,
    )
    return types.SimpleNamespace(**{**base, **over})


class TheGrid(unittest.TestCase):
    def test_a_harness_meets_every_opponent_of_the_other_side_at_each_seat(self):
        grid = bench.build_grid([("h1", "m1")], ["red", "blue"], [1])
        self.assertEqual(
            [(g["side"], g["opponent"]) for g in grid],
            [
                ("red", "scripted-fast"),
                ("red", "scripted-slow"),
                ("red", "scripted-absent"),
                ("blue", "scripted-loud"),
                ("blue", "scripted-quiet"),
                ("blue", "scripted-idle"),
            ],
            "a harness playing red must meet defenders, one playing blue attackers",
        )
        self.assertEqual(grid[0]["group"], "red:h1:m1 vs scripted-fast")
        self.assertEqual(grid[0]["run_id"], "red-h1-m1-vs-scripted-fast-s1")

    def test_it_is_seed_major_so_a_campaign_stopped_early_has_every_cell(self):
        grid = bench.build_grid([("a", None), ("b", None)], ["red"], [1, 2], "scripted-fast")
        self.assertEqual(
            [(g["seed"], g["harness"]) for g in grid], [(1, "a"), (1, "b"), (2, "a"), (2, "b")]
        )
        self.assertEqual(len({g["run_id"] for g in grid}), 4, "two games share a directory")

    def test_an_opponent_of_the_same_side_is_not_one(self):
        self.assertEqual(
            bench.opponents_of("red", "scripted-slow,scripted-loud"), ["scripted-slow"]
        )
        with self.assertRaises(SystemExit):
            bench.opponents_of("red", "nobody")

    def test_harnesses_are_named_with_their_model(self):
        self.assertEqual(
            bench.parse_subjects("claude-code:model-a, scripted"),
            [("claude-code", "model-a"), ("scripted", None)],
        )
        with self.assertRaises(SystemExit):
            bench.parse_subjects("no-such-harness")


class AGame(unittest.TestCase):
    def args(self, side, **over):
        entry = bench.build_grid([("scripted", "m1")], [side], [7])[0]
        return bench.run_args(cfg("/tmp/x", **over), entry, "/tmp/x/run"), entry

    def test_the_harness_sits_at_its_side_and_the_opponent_at_the_other(self):
        a, _e = self.args("red")
        self.assertEqual((a.red_harness, a.red_model), ("scripted", "m1"))
        self.assertEqual((a.blue_harness, a.blue_model), ("scripted-fast", None))
        b, _e = self.args("blue")
        self.assertEqual((b.blue_harness, b.red_harness), ("scripted", "scripted-loud"))

    def test_nobody_has_to_be_there_and_nothing_drives_the_attack(self):
        a, e = self.args("red")
        self.assertTrue(a.teams)
        self.assertFalse(a.playground, "a game of a campaign would wait for a Ctrl-C")
        self.assertFalse(a.attack, "with teams the attack is the red seat's, nothing drives it")
        self.assertEqual((a.seed, a.run_id, a.out_dir), (7, e["run_id"], "/tmp/x/run"))
        self.assertEqual(a.engagement_s, 30.0)

    def test_every_game_has_a_budget_unless_told_otherwise(self):
        self.assertEqual(self.args("red")[0].max_calls, bench.DEFAULT_MAX_CALLS)
        self.assertEqual(self.args("red", max_calls=5)[0].max_calls, 5)

    def test_a_harness_that_cannot_log_in_stops_the_campaign_before_any_game(self):
        with mock.patch.dict(os.environ, clear=False) as env:
            env.pop("ANTHROPIC_API_KEY", None)
            env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
            with self.assertRaises(SystemExit) as why:
                bench.build_campaign(cfg(tempfile.mkdtemp(), harness="claude-code"))
        self.assertIn("ANTHROPIC_API_KEY", str(why.exception))

    def test_the_campaigns_directory_is_its_own(self):
        parsed = bench.parse_args(["--harness", "scripted", "--engagement-s", "45"])
        self.assertEqual(parsed.out_root, "output/campaigns")
        self.assertEqual(parsed.engagement_s, 45.0)
        self.assertFalse(hasattr(parsed, "red_harness"), "a seat was taken from the command line")


class TheBenchmark(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="bench-")
        self.played = []
        self.shape = compute_metrics(tempfile.mkdtemp())

    def fake_run(self, args, progress):
        self.played.append(args.run_id)
        emit = getattr(progress, "emit", progress)
        emit("run_start", scenario="cps-advisor")
        os.makedirs(args.out_dir, exist_ok=True)
        emit("run_end", status="ok")
        return 0

    def fake_metrics(self, run_dir):
        """A score in the real shape, with a card that depends on the game."""
        run_id = os.path.basename(run_dir)
        seed = int(run_id.rsplit("-s", 1)[1])
        slow = "slow" in run_id or "absent" in run_id
        m = json.loads(json.dumps(self.shape))
        card = {
            "calls": 10 + seed,
            "failed_call_rate": 0.0,
            "cost_usd": 0.1 * seed,
            "decision": {"think_median_s": 2.0},
        }
        if run_id.startswith("red"):
            card |= {
                "impact": {"plant_affected": slow, "out_of_band_s": 5.0 * seed if slow else 0.0},
                "progress": {
                    "stages_reached": 6 if slow else 3,
                    "step_success_rate": 0.5,
                    "repeats_after_failure": seed,
                },
                "adaptation": {"turned_after_median_s": None},
                "stealth": {"noise_mean": 0.4, "detection_latency_s": 8.0},
            }
            m["players"] = {"red": card}
        else:
            card |= {
                "containment": {
                    "plant_affected": False,
                    "out_of_band_s": 0.0,
                    "first_countermeasure_s": 9.0,
                },
                "verdicts": {
                    "approved_called_for": 2,
                    "approved_not_called_for": 0,
                    "expired": 0,
                    "latency_median_s": 3.0,
                },
                "cost": {"hmi_unavailable_s": 100.0},
            }
            m["players"] = {"blue": card}
        return m

    def play(self, **over):
        return bench.run_campaign(
            cfg(self.root, **over), run_fn=self.fake_run, metrics_fn=self.fake_metrics
        )

    def test_every_game_is_played_scored_and_tabulated_per_cell(self):
        res = self.play()
        self.assertEqual((res["status"], res["ok"], res["failed"]), ("done", 12, 0))
        d = os.path.join(self.root, "t")
        for name in ("campaign.json", "summary.md", "harness.csv", "ci.csv"):
            self.assertTrue(os.path.exists(os.path.join(d, name)), name)
        with open(os.path.join(d, "summary.md")) as f:
            summary = f.read()
        self.assertEqual(
            summary.count("\n## Harnesses\n"), 1, "the table is appended at every game"
        )
        self.assertIn("### Harnesses playing red", summary)
        self.assertIn("| red:scripted vs scripted-slow | 2 | 1 [1, 1] | 7.5 [", summary)
        self.assertIn("### Harnesses playing blue", summary)
        last = [
            e for e in read_events(os.path.join(d, "progress.jsonl")) if e["kind"] == "aggregate"
        ][-1]
        cells = {r["group"]: r for r in last["harness"]}
        self.assertEqual(len(cells), 6)
        fast = cells["red:scripted vs scripted-fast"]
        self.assertEqual((fast["side"], fast["runs"]), ("red", 2))
        self.assertEqual(fast["plant affected"]["mean"], 0.0)
        self.assertEqual(fast["calls"]["mean"], 11.5)
        self.assertEqual(
            fast["turned after (s)"]["n"], 0, "a figure no game had was given a mean all the same"
        )
        with open(os.path.join(d, "runs", "red-scripted-vs-scripted-fast-s1", "metrics.json")) as f:
            run = json.load(f)["run"]
        self.assertEqual(
            (run["group"], run["side"], run["seed"]), ("red:scripted vs scripted-fast", "red", 1)
        )

    def test_a_benchmark_run_again_under_its_name_plays_only_what_is_missing(self):
        self.play(seeds="1")
        first = list(self.played)
        self.play(seeds="1-2")
        self.assertEqual(len(first), 6)
        self.assertEqual(len(self.played), 12, "the games already scored were played again")
        self.assertTrue(all(r.endswith("-s2") for r in self.played[6:]))

    def test_no_teams_token_is_kept_with_the_campaign(self):
        self.play(seeds="1", sides="red", opponents="scripted-fast")
        with open(os.path.join(self.root, "t", "campaign.json")) as f:
            kept = json.load(f)
        self.assertNotIn("blue_token", kept["params"])
        self.assertNotIn("red_token", kept["params"])
        self.assertEqual([u["id"] for u in kept["units"]], ["red-scripted-vs-scripted-fast-s1"])


if __name__ == "__main__":
    unittest.main()
