"""Tests for the CPS campaign runner (network_scenario/cps_campaign.py) and the
campaign aggregation (monitor/cps_metrics.aggregate). The experiment and the
scoring are injected fakes: no Docker, no Kathará.

Checks the seed grammar, the seed-major grid order, the ledger event sequence,
resume (runs with metrics.json are skipped), retry-then-continue on failures,
the aggregate numbers, and the dry run.

Run: `.venv/bin/python -m unittest tests.test_cps_campaign`.
"""

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from monitor.cps_metrics import aggregate, compute_metrics, format_aggregate   # noqa: E402
from monitor.progress import read_events                        # noqa: E402
from network_scenario import cps_campaign as cc                 # noqa: E402


def _metrics(attack, rules_lat=None, model_lat=None, before=(True, True), fa=(0, 0),
             persists=False, recovered=False, abnormal=0):
    def det(lat, b, f):
        return {"detected": lat is not None, "latency_from_write_s": lat,
                "detection_latency_s": lat, "before_impact": b, "classes": [],
                "false_alarms": f, "false_alarms_in_operator_windows": 0, "findings": 1}
    rl = det(rules_lat, before[0], fa[0])
    ml = det(model_lat, before[1], fa[1])
    comb_lat = min(x for x in (rules_lat, model_lat, 99) if x is not None)
    base = compute_metrics(tempfile.mkdtemp(prefix="empty-run-"))   # every key, real shape
    return {**base, "attack": attack, "detected": rl["detected"] or ml["detected"],
        "detectors": {
        "rules": rl, "model": ml,
        "combined": det(comb_lat if comb_lat != 99 else None, any(before), sum(fa))},
        "false_alarms": sum(fa), "abnormal_frames": abnormal,
        "impact_persists_after_attack": persists, "recovered": recovered,
        "time_to_impact_s": 0.8 if abnormal else None, "impact_duration_s": 29.0 if abnormal else 0.0,
        "max_abs_deviation_pu": 0.08, "manual_mode_s": 0.0}


def cfg(root, **kw):
    base = dict(name="t", out_root=root, modes="normal,manual-hijack", seeds="1-2",
                normal_duration=60.0, learn_seconds=45.0, post_attack_duration=30.0,
                step_interval=1.0, detectors="rules,model", poll_interval=2.0,
                dashboard_port=0, retries=1, resume=True)
    base.update(kw)
    return types.SimpleNamespace(**base)


class Grammar(unittest.TestCase):
    def test_parse_seeds(self):
        self.assertEqual(cc.parse_seeds("1-3,7,2"), [1, 2, 3, 7])
        self.assertEqual(cc.parse_seeds("5"), [5])
        for bad in ("", "3-1", "x"):
            with self.assertRaises(ValueError):
                cc.parse_seeds(bad)

    def test_modes_validated(self):
        with self.assertRaises(ValueError):
            cc.parse_modes("normal,nope")

    def test_grid_is_seed_major(self):
        g = cc.build_grid(["normal", "manual-hijack"], [1, 2])
        self.assertEqual([e["run_id"] for e in g],
                         ["normal-s1", "manual-hijack-s1", "normal-s2", "manual-hijack-s2"])
        self.assertEqual([e["attack"] for e in g], [False, True, False, True])

    def test_run_args_shape(self):
        e = {"run_id": "manual-hijack-s3", "mode": "manual-hijack", "seed": 3, "attack": True}
        a = cc.run_args(cfg("/tmp"), e, "/x")
        self.assertEqual((a.attack, a.attack_mode, a.seed, a.out_dir), (True, "manual-hijack", 3, "/x"))
        n = cc.run_args(cfg("/tmp"), {"run_id": "normal-s1", "mode": "normal", "seed": 1,
                                      "attack": False}, "/y")
        self.assertFalse(n.attack)
        self.assertEqual((a.respond, a.approval), ("off", "auto"))   # default: no responder
        r = cc.run_args(cfg("/tmp", respond="solver", approval="delay:2"), e, "/x")
        self.assertEqual((r.respond, r.approval), ("solver", "delay:2"))


class Campaign(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="campaign-")
        self.calls = []

    def fake_run(self, fail_ids=(), fail_once=()):
        seen = {}

        def run_fn(args, progress):
            rid = args.run_id
            seen[rid] = seen.get(rid, 0) + 1
            self.calls.append(rid)
            progress.emit("run_start", mode=args.attack_mode if args.attack else "normal",
                          seed=args.seed, phases=[])
            if rid in fail_ids or (rid in fail_once and seen[rid] == 1):
                progress.emit("run_end", status="failed", error="boom")
                raise RuntimeError(f"boom {rid}")
            os.makedirs(args.out_dir, exist_ok=True)
            progress.emit("run_end", status="ok")
        return run_fn

    @staticmethod
    def fake_metrics(out_dir):
        if os.path.basename(out_dir).startswith("normal"):
            return _metrics(False)
        return _metrics(True, rules_lat=1.2, model_lat=0.02, before=(False, True),
                        abnormal=29, persists=True)

    def ledger(self, name="t"):
        return read_events(os.path.join(self.root, name, "progress.jsonl"))

    def test_full_campaign_events_and_outputs(self):
        res = cc.run_campaign(cfg(self.root), run_fn=self.fake_run(), metrics_fn=self.fake_metrics)
        self.assertEqual((res["status"], res["ok"], res["failed"]), ("done", 4, 0))
        evs = self.ledger()
        kinds = [e["kind"] for e in evs]
        self.assertEqual(kinds[0], "campaign_start")
        self.assertEqual(kinds[-1], "campaign_end")
        self.assertEqual(kinds.count("run_metrics"), 4)
        self.assertEqual(kinds.count("aggregate"), 4)
        self.assertEqual(len(evs[0]["grid"]), 4)
        self.assertGreater(evs[0]["planned_total_s"], 4 * 60)
        starts = [e for e in evs if e["kind"] == "run_start"]
        self.assertEqual([e["run_id"] for e in starts], self.calls)
        self.assertTrue(all(e["attempt"] == 1 for e in starts))
        d = os.path.join(self.root, "t")
        for f in ("campaign.json", "summary.md", "summary.csv", "impact.csv"):
            self.assertTrue(os.path.exists(os.path.join(d, f)), f)
        with open(os.path.join(d, "runs", "manual-hijack-s1", "metrics.json")) as f:
            m = json.load(f)
        self.assertEqual(m["run"], {"run_id": "manual-hijack-s1", "mode": "manual-hijack", "seed": 1})

    def test_resume_skips_scored_runs(self):
        cc.run_campaign(cfg(self.root, seeds="1"), run_fn=self.fake_run(), metrics_fn=self.fake_metrics)
        self.calls.clear()
        res = cc.run_campaign(cfg(self.root, seeds="1-2"), run_fn=self.fake_run(),
                              metrics_fn=self.fake_metrics)
        self.assertEqual(self.calls, ["normal-s2", "manual-hijack-s2"])
        self.assertEqual((res["ok"], res["skipped"]), (2, 2))
        evs = self.ledger()
        self.assertEqual([e["seq"] for e in evs], list(range(len(evs))))   # one ledger, appended
        skipped = [e for e in evs if e["kind"] == "run_skipped"]
        self.assertEqual({e["run_id"] for e in skipped}, {"normal-s1", "manual-hijack-s1"})
        self.assertIn("metrics", skipped[0])
        last_agg = [e for e in evs if e["kind"] == "aggregate"][-1]
        hij = [r for r in last_agg["detection"] if r["mode"] == "manual-hijack"]
        self.assertTrue(all(r["runs"] == 2 for r in hij))

    def test_no_resume_reruns(self):
        cc.run_campaign(cfg(self.root, seeds="1"), run_fn=self.fake_run(), metrics_fn=self.fake_metrics)
        self.calls.clear()
        cc.run_campaign(cfg(self.root, seeds="1", resume=False), run_fn=self.fake_run(),
                        metrics_fn=self.fake_metrics)
        self.assertEqual(len(self.calls), 2)

    def test_retry_then_continue(self):
        res = cc.run_campaign(cfg(self.root, seeds="1"),
                              run_fn=self.fake_run(fail_ids={"normal-s1"},
                                                   fail_once={"manual-hijack-s1"}),
                              metrics_fn=self.fake_metrics)
        self.assertEqual(self.calls, ["normal-s1", "normal-s1", "manual-hijack-s1", "manual-hijack-s1"])
        self.assertEqual((res["status"], res["ok"], res["failed"]), ("done_with_failures", 1, 1))
        kinds = [e["kind"] for e in self.ledger()]
        self.assertEqual(kinds.count("run_retry"), 2)
        self.assertEqual(kinds.count("run_failed"), 1)
        self.assertFalse(os.path.exists(os.path.join(self.root, "t", "runs", "normal-s1", "metrics.json")))

    def test_interrupt_closes_campaign(self):
        def run_fn(args, progress):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            cc.run_campaign(cfg(self.root, seeds="1"), run_fn=run_fn, metrics_fn=self.fake_metrics)
        end = self.ledger()[-1]
        self.assertEqual((end["kind"], end["status"]), ("campaign_end", "interrupted"))

    def test_bad_timing_rejected_before_running(self):
        with self.assertRaises(SystemExit):
            cc.run_campaign(cfg(self.root, normal_duration=30.0), run_fn=self.fake_run(),
                            metrics_fn=self.fake_metrics)
        self.assertEqual(self.calls, [])

    def test_dry_run(self):
        lines = []
        grid, total = cc.dry_run(cfg(self.root), out=lines.append)
        self.assertEqual(len(grid), 4)
        self.assertIn("4 runs", lines[-1])
        self.assertFalse(os.path.exists(os.path.join(self.root, "t")))


class Aggregate(unittest.TestCase):
    def test_numbers(self):
        rows = [
            {"mode": "manual-hijack", "seed": 1, "metrics": _metrics(True, 1.0, 0.02, (False, True), abnormal=29, persists=True)},
            {"mode": "manual-hijack", "seed": 2, "metrics": _metrics(True, 2.0, None, (False, False), fa=(0, 1), abnormal=29, persists=True)},
            {"mode": "manual-hijack", "seed": 3, "metrics": _metrics(True, 1.5, 0.04, (False, True), abnormal=29, persists=True)},
            {"mode": "normal", "seed": 1, "metrics": _metrics(False, fa=(0, 2))},
        ]
        agg = aggregate(rows)
        d = {(r["mode"], r["detector"]): r for r in agg["detection"]}
        rules, model = d[("manual-hijack", "rules")], d[("manual-hijack", "model")]
        self.assertEqual((rules["detected"], rules["detection_rate"]), (3, 1.0))
        self.assertEqual(rules["latency_median_s"], 1.5)
        self.assertEqual((rules["latency_min_s"], rules["latency_max_s"]), (1.0, 2.0))
        self.assertEqual(rules["before_impact_rate"], 0.0)
        self.assertEqual((model["detected"], model["detection_rate"]), (2, 0.667))
        self.assertEqual(model["latency_median_s"], 0.03)
        self.assertEqual(model["before_impact_rate"], 0.667)
        self.assertEqual((model["false_alarms"], model["runs_with_false_alarms"]), (1, 1))
        norm = d[("normal", "model")]
        self.assertIsNone(norm["detection_rate"])
        self.assertEqual(norm["false_alarms"], 2)
        imp = {r["mode"]: r for r in agg["impact"]}
        self.assertEqual(imp["manual-hijack"]["persists_rate"], 1.0)
        self.assertEqual(imp["normal"]["impact_rate"], 0.0)
        md = format_aggregate(agg)
        self.assertIn("| manual-hijack | model | 3 | 0.667 |", md)


if __name__ == "__main__":
    unittest.main()
