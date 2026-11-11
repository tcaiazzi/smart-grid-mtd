"""Tree-guided attacker (cyberrange.planes.attack.planner): step registry, profile choice,
reactive replanning on a blocked step, reproducibility — all with a fake
exec_step, no Docker.

Run: `.venv/bin/python -m unittest tests.test_attack_planner`.
"""

import unittest


from cyberrange.planes.attack.planner import steps as S  # noqa: E402
from cyberrange.planes.attack.planner.planner import AttackPlanner  # noqa: E402
from cyberrange.planes.defense.soar import trees  # noqa: E402
from cyberrange.scenarios.cps import kg as cps_kg

CTX = {
    "target_url": "http://10.10.0.20:8080",
    "engine_ip": "10.20.0.20",
    "engine_port": 5020,
    "ot_write_path": "/ot_write.py",
}


class Recorder:
    """exec_step that reports success, except for nodes in ``block``."""

    def __init__(self, block=(), writes_per_impact=3):
        self.block, self.calls = set(block), []
        self.wpi = writes_per_impact

    def __call__(self, node):
        self.calls.append(node)
        if node in self.block:
            return {"ok": False, "writes": 0}
        return {"ok": True, "writes": self.wpi if node in S.IMPACT_MODE else 0}


class Steps(unittest.TestCase):
    def test_command_and_parse(self):
        cmd = S.step_command("it_access", CTX)
        self.assertIn("--step it_access", cmd)
        self.assertIn("--target-url http://10.10.0.20:8080", cmd)
        self.assertIn("--step impact --attack manual-hijack", S.step_command("mode_hijack", CTX))
        out = '{"t":1,"phase":"pivot","ok":true}\nnoise\n'
        self.assertEqual(S.parse_outcome("pivot", out)["ok"], True)
        imp = '{"phase":"modbus_write","ok":true}\n{"phase":"impact","attack":"x","ok":true}'
        r = S.parse_outcome("setpoint_oor", imp)
        self.assertEqual((r["ok"], r["writes"]), (True, 1))

    def test_non_step_node_rejected(self):
        with self.assertRaises(KeyError):
            S.step_command("via_hmi", CTX)


class Planner(unittest.TestCase):
    def setUp(self):
        self.g = cps_kg.build()
        self.tree = trees.cps_attack_tree(self.g)

    def plan(self, profile="opportunistic", goal=None, block=(), dwell=0.0, seed=1):
        p = AttackPlanner(self.tree, self.g, profile=profile, goal=goal, seed=seed)
        rec = Recorder(block=block)
        summary = p.run(rec, record=lambda **f: None, dwell=dwell)
        return summary, rec

    def test_full_chain_reaches_impact(self):
        s, rec = self.plan()
        self.assertTrue(s["success"])
        self.assertEqual(s["stage_reached"], "impact")
        # Opportunistic aims at the biggest impact first: breaker_open (1.0)
        self.assertEqual(rec.calls, ["it_access", "it_exec", "pivot", "breaker_open"])

    def test_targeted_goal(self):
        s, rec = self.plan(profile="targeted", goal="mode_hijack")
        self.assertTrue(s["success"])
        self.assertEqual(rec.calls[-1], "mode_hijack")

    def test_stealthy_prefers_quiet_impact(self):
        s, rec = self.plan(profile="stealthy")
        self.assertEqual(rec.calls[-1], "mode_hijack")  # lowest detectability

    def test_blocked_pivot_defends(self):
        # The responder blocked the flow: the pivot probe fails, every OT leaf
        # shares it, so the attacker runs out of moves before any write.
        s, rec = self.plan(block={"pivot"})
        self.assertFalse(s["success"])
        self.assertTrue(s["defended"])
        self.assertEqual(s["stage_reached"], "it_exec")
        self.assertEqual(s["writes_ok"], 0)
        self.assertEqual(rec.calls.count("pivot"), 1)  # not retried pointlessly

    def test_blocked_impact_tries_alternative_then_stops(self):
        # The write of the first-choice leaf fails; the planner tries another
        # impact leaf (prereqs already done) and, that failing too, stops.
        s, rec = self.plan(block={"setpoint_oor", "breaker_open", "mode_hijack"})
        self.assertFalse(s["success"])
        self.assertEqual(s["stage_reached"], "pivot")
        self.assertGreaterEqual(len([c for c in rec.calls if c in S.IMPACT_MODE]), 2)

    def test_reproducible(self):
        a, ra = self.plan(seed=7)
        b, rb = self.plan(seed=7)
        self.assertEqual(ra.calls, rb.calls)

    def test_dwell_between_steps(self):
        waits = []
        p = AttackPlanner(self.tree, self.g, seed=1)
        p.run(Recorder(), sleep=lambda s: waits.append(s), dwell=2.0)
        self.assertTrue(waits and all(w == 2.0 for w in waits))


class FakeManager:
    """exec_obj that answers each exploit_client --step with matching JSON, and
    fails the pivot once blocked (as a boundary DROP would)."""

    def __init__(self, block=()):
        self.block, self.cmds = set(block), []

    def exec_obj(self, machine, cmd, stream=False):
        self.cmds.append(cmd)
        if "--step impact" in cmd:
            ok = "impact" not in self.block
            lines = [
                f'{{"phase":"modbus_write","t_send":1.0,"register":0,"value":60.0,"ok":{str(ok).lower()},"attempt":1}}',
                f'{{"phase":"impact","attack":"x","ok":{str(ok).lower()}}}',
            ]
            return ("\n".join(lines).encode(), b"", 0 if ok else 1)
        node = next((n for n in ("it_access", "it_exec", "pivot") if f"--step {n}" in cmd), "?")
        ok = node not in self.block
        return (f'{{"phase":"{node}","ok":{str(ok).lower()}}}'.encode(), b"", 0 if ok else 1)


class GT:
    def __init__(self):
        self.rows = []

    def record(self, kind, **f):
        self.rows.append({"kind": kind, **f})


class PlannedDriver(unittest.TestCase):
    def setUp(self):
        from cyberrange.planes.attack import active_attack

        self.drive = active_attack.drive_attack_planned
        self.g = cps_kg.build()

    def run_driver(self, block=(), profile="opportunistic", goal=None):
        mgr, gt, ledger = FakeManager(block=block), GT(), []
        summary = self.drive(
            mgr,
            {"attacker": "attacker"},
            gt,
            self.g,
            target_url="http://10.10.0.20:8080",
            engine_ip="10.20.0.20",
            engine_port=5020,
            profile=profile,
            goal=goal,
            seed=1,
            emit=lambda k, **f: ledger.append((k, f)),
        )
        return summary, gt, ledger

    def test_records_ground_truth_and_ledger(self):
        s, gt, ledger = self.run_driver()
        kinds = [r["kind"] for r in gt.rows]
        self.assertEqual(kinds[0], "attack_start")
        self.assertEqual(kinds[-1], "attack_end")
        self.assertIn("plan_step", kinds)
        self.assertIn("rce", kinds)  # it_access mapped for metrics
        self.assertTrue(any(r["kind"] == "modbus_write" and r["ok"] for r in gt.rows))
        self.assertTrue(s["success"])
        self.assertEqual([k for k, _ in ledger].count("plan_step"), len(s["steps"]))

    def test_blocked_pivot_no_writes(self):
        s, gt, _ = self.run_driver(block={"pivot"})
        self.assertFalse(s["success"])
        self.assertEqual(s["stage_reached"], "it_exec")
        self.assertFalse(any(r["kind"] == "modbus_write" and r.get("ok") for r in gt.rows))


if __name__ == "__main__":
    unittest.main()
