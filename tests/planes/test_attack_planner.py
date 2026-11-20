"""Tree-guided attacker (nodes/redteam): the step registry and the console's
view of it (red_steps), profile choice and reactive replanning of the planner,
the in-lab agent that drives it (red_agent), and the host that reconstructs the
ground truth from the agent's record — all with a fake exploit_client, no Docker.

Run: `.venv/bin/python -m unittest tests.planes.test_attack_planner`.
"""

import json
import tempfile
import unittest


from tests.helpers import guest_paths

# The planner is node software (nodes/redteam), imported flat as in a
# container; SOC/DEFENSE supply the code that builds the tree document under test.
guest_paths.add(guest_paths.REDTEAM, guest_paths.SOC, guest_paths.DEFENSE)

import soar_kg as _kg  # noqa: E402  (node code, to build the tree document under test)
import attack_graph  # noqa: E402
import soar_trees as _trees  # noqa: E402

import red_steps  # noqa: E402  (nodes/redteam, flat as on the attacker)
import steps as S  # noqa: E402  (nodes/redteam, flat as on the attacker)
import tree_doc  # noqa: E402  (nodes/redteam, flat as on the attacker)
from planner import AttackPlanner  # noqa: E402

from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402


def _attack_tree():
    """The attack tree as the document the planner reads (tree.json's
    ``attack_tree``), built from the node's own code."""
    g = _kg.build_kg(cps_inv.inventory())
    return _trees.to_json(attack_graph.attack_tree(g), attack_graph.countermeasures(g), g)[
        "attack_tree"
    ]


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


class RedSteps(unittest.TestCase):
    """red_steps.build_steps: the tree's steps as the red console lists them."""

    def build(self, tree):
        return red_steps.build_steps(tree, CTX["target_url"], CTX["engine_ip"], CTX["engine_port"])

    def test_stage_order_needs_and_commands(self):
        steps = self.build(_attack_tree())
        self.assertEqual(
            [s["id"] for s in steps][:3],
            ["it_access", "it_exec", "pivot"],
            "the console would list the steps out of the order they build on each other",
        )
        by_id = {s["id"]: s for s in steps}
        self.assertEqual(
            by_id["pivot"]["needs"],
            ["it_access", "it_exec"],
            "the console would call the pivot ready before its prerequisites succeeded",
        )
        self.assertEqual(
            sorted(by_id["meas_fdi"]["needs"]),
            ["it_access", "it_exec", "ot_aitm", "ot_foothold"],
            "the console would offer the workstation's branch with no foothold on the HMI",
        )
        self.assertEqual(by_id["breaker_open"]["stage"], "impact")
        self.assertIn("--step impact --attack breaker-open", by_id["breaker_open"]["command"])
        self.assertIn(f"--target-url {CTX['target_url']}", by_id["it_access"]["command"])

    def test_infeasible_step_is_left_out(self):
        tree = _attack_tree()
        tree_doc.index(tree)["breaker_open"]["feasible"] = False
        self.assertNotIn(
            "breaker_open",
            [s["id"] for s in self.build(tree)],
            "the console would offer a step the lab cannot run",
        )


class Planner(unittest.TestCase):
    def setUp(self):
        self.tree = _attack_tree()

    def plan(self, profile="opportunistic", goal=None, block=(), dwell=0.0, seed=1):
        p = AttackPlanner(self.tree, profile=profile, goal=goal, seed=seed)
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
        self.assertEqual(rec.calls[-1], "setpoint_ramp")  # lowest detectability

    def test_blocked_pivot_sends_the_attacker_round_by_the_workstation(self):
        # The responder blocked the flow: the pivot probe fails and every leaf
        # behind it is lost. The workstation's branch does not use the flow.
        s, rec = self.plan(block={"pivot"})
        self.assertTrue(s["success"], "blocking the flow alone no longer defends the plant")
        self.assertEqual(rec.calls.count("pivot"), 1)  # not retried pointlessly
        self.assertEqual(rec.calls[-3:], ["ot_foothold", "ot_aitm", "meas_fdi"])

    def test_blocked_pivot_and_workstation_defend(self):
        s, rec = self.plan(block={"pivot", "ot_foothold"})
        self.assertFalse(s["success"])
        self.assertTrue(s["defended"])
        self.assertEqual(s["stage_reached"], "it_exec")
        self.assertEqual(s["writes_ok"], 0)

    def test_the_workstation_is_reached_through_the_hmi(self):
        p = AttackPlanner(self.tree, profile="targeted", goal="meas_fdi", seed=1)
        self.assertEqual(
            p.sequence_for("meas_fdi"),
            ["it_access", "it_exec", "ot_foothold", "ot_aitm", "meas_fdi"],
            "the tree does not name the HMI steps on this branch: the lab needs them",
        )

    def test_blocked_impact_tries_alternative_then_stops(self):
        # The write of the first-choice leaf fails; the planner tries another
        # impact leaf (prereqs already done) and, that failing too, stops.
        s, rec = self.plan(block=set(S.IMPACT_MODE))
        self.assertFalse(s["success"])
        # Every impact fails, the one behind the workstation last.
        self.assertEqual(s["stage_reached"], "ot_aitm")
        self.assertGreaterEqual(len([c for c in rec.calls if c in S.IMPACT_MODE]), 2)

    def test_reproducible(self):
        a, ra = self.plan(seed=7)
        b, rb = self.plan(seed=7)
        self.assertEqual(ra.calls, rb.calls)

    def test_every_choice_of_impact_is_told_with_what_was_open(self):
        plans = []
        p = AttackPlanner(self.tree, seed=1)
        p.run(Recorder(block=set(S.IMPACT_MODE)), on_plan=lambda **plan: plans.append(plan))
        self.assertGreaterEqual(len(plans), 2, "a re-plan after a failed impact went untold")
        first, second = plans[0], plans[1]
        self.assertEqual((first["reason"], second["reason"]), ("initial", "replan"))
        self.assertEqual(first["target"], "breaker_open")
        self.assertEqual(first["sequence"][-1], "breaker_open")
        self.assertIn("mode_hijack", [c["node"] for c in first["candidates"]])
        self.assertNotIn(first["target"], [c["node"] for c in second["candidates"]])
        self.assertIn("breaker_open", second["blocked"])

    def test_a_step_names_the_impacts_it_was_chosen_among(self):
        steps = []
        p = AttackPlanner(self.tree, seed=1)
        p.run(Recorder(), record=lambda **step: steps.append(step))
        self.assertEqual(steps[0]["chosen_among"][0], "breaker_open")
        self.assertGreater(len(steps[0]["chosen_among"]), 1, "the alternatives went unrecorded")

    def test_dwell_between_steps(self):
        waits = []
        p = AttackPlanner(self.tree, seed=1)
        p.run(Recorder(), sleep=lambda s: waits.append(s), dwell=2.0)
        self.assertTrue(waits and all(w == 2.0 for w in waits))


def _two_ways_two_feeders():
    """The tree of a lab with two HMIs, each a way in, and two feeders."""
    from tests.nodes.test_attack_graph import two_ways_two_feeders

    g = two_ways_two_feeders()
    return _trees.to_json(attack_graph.attack_tree(g), attack_graph.countermeasures(g), g)[
        "attack_tree"
    ]


WAYS = {"hmi": "http://10.10.0.20:8080", "hmib": "http://10.10.0.21:8080"}


class SeveralWaysAndFeeders(unittest.TestCase):
    """A lab with two ways in and two feeders has every step in several places:
    the attacker must be able to take each, and say which it took."""

    def setUp(self):
        self.tree = _two_ways_two_feeders()

    def run_planner(self, block=(), **kw):
        p = AttackPlanner(self.tree, seed=1, **kw)
        rec = Recorder(block=block)
        steps = []
        summary = p.run(rec, record=lambda **step: steps.append(step))
        return summary, rec, steps

    def test_every_write_on_every_way_and_feeder_is_a_candidate(self):
        got = set(AttackPlanner(self.tree, seed=1).impact_candidates())
        for leaf in ("breaker_open@hmi:u1", "breaker_open@hmi:u2", "breaker_open@hmib:u2"):
            self.assertIn(leaf, got, "the attacker cannot see a step the tree has")
        self.assertIn("meas_fdi", got)

    def test_the_attacker_reaches_an_impact(self):
        s, rec, _steps = self.run_planner()
        self.assertTrue(s["success"], "a lab of two substations stopped the planner by itself")
        self.assertEqual(rec.calls, ["it_access@hmi", "it_exec@hmi", "pivot@hmi", rec.calls[-1]])
        self.assertTrue(rec.calls[-1].startswith("breaker_open@hmi:"))

    def test_it_is_kept_to_the_way_and_the_feeder_it_is_given(self):
        s, rec, steps = self.run_planner(profile="targeted", goal="mode_hijack", via="hmib", unit=2)
        self.assertTrue(s["success"])
        self.assertEqual(
            rec.calls, ["it_access@hmib", "it_exec@hmib", "pivot@hmib", "mode_hijack@hmib:u2"]
        )
        last = steps[-1]
        self.assertEqual((last["step_kind"], last["via"], last["unit"]), ("mode_hijack", "hmib", 2))
        self.assertEqual(last["stage"], "impact")

    def test_a_closed_way_sends_it_round_by_the_other(self):
        s, rec, _steps = self.run_planner(block={"pivot@hmi"})
        self.assertTrue(s["success"], "one blocked flow defended a plant with two ways in")
        self.assertIn("pivot@hmib", rec.calls)

    def test_the_workstation_is_reached_through_a_way_still_open(self):
        p = AttackPlanner(self.tree, profile="targeted", goal="meas_fdi", seed=1)
        self.assertEqual(
            p.sequence_for("meas_fdi"),
            ["it_access@hmi", "it_exec@hmi", "ot_foothold", "ot_aitm", "meas_fdi"],
        )
        self.assertEqual(
            p.sequence_for("meas_fdi", failed={"it_access@hmi"})[:2],
            ["it_access@hmib", "it_exec@hmib"],
            "with the first HMI closed the workstation is still one HMI away",
        )

    def test_each_step_runs_against_its_own_way_and_unit(self):
        idx, places = tree_doc.index(self.tree), S.places(self.tree)
        ctx = dict(CTX, ways=WAYS, plant_b64="PLANT")
        leaf = "mode_hijack@hmib:u2"
        cmd = S.step_command(idx[leaf], ctx, places[leaf])
        self.assertIn(f"--target-url {WAYS['hmib']} ", cmd)
        self.assertIn("--unit-id 2 ", cmd)
        self.assertIn("--plant-b64 PLANT", cmd)
        self.assertIn("--step impact --attack manual-hijack", cmd)
        access = S.step_command(idx["it_access@hmi"], ctx, places["it_access@hmi"])
        self.assertIn(f"--target-url {WAYS['hmi']} ", access)
        self.assertNotIn("--unit-id", access, "a step that touches no register names no feeder")

    def test_the_agent_runs_the_workstation_steps_from_the_way_it_holds(self):
        import red_agent

        fake = FakeExploit(block={"pivot"})
        with tempfile.NamedTemporaryFile("w+", suffix=".jsonl") as f:
            planner = AttackPlanner(self.tree, seed=1, via="hmib")
            agent = red_agent.RedAgent(dict(CTX, ways=WAYS), f.name, run_cmd=fake)
            agent.run(planner, "opportunistic", dwell=0.0)
            f.seek(0)
            rows = [json.loads(line) for line in f if line.strip()]
        foothold = next(c for c in fake.cmds if "--step ot_foothold" in c)
        self.assertIn(f"--target-url {WAYS['hmib']} ", foothold)
        step = next(r for r in rows if r.get("node") == "ot_foothold")
        self.assertEqual(step["via"], "hmib", "the record does not say which HMI it went by")

    def test_the_console_lists_every_place_with_its_own_command(self):
        steps = red_steps.build_steps(
            self.tree, CTX["target_url"], CTX["engine_ip"], CTX["engine_port"], ways=WAYS
        )
        by_id = {s["id"]: s for s in steps}
        self.assertIn(f"--target-url {WAYS['hmib']} ", by_id["breaker_open@hmib:u2"]["command"])
        self.assertIn("--unit-id 2 ", by_id["breaker_open@hmib:u2"]["command"])
        self.assertEqual(by_id["pivot@hmib"]["needs"], ["it_access@hmib", "it_exec@hmib"])


class FakeExploit:
    """Stands in for exploit_client.py on the attacker node: answers each --step
    with the JSON that step prints, failing the nodes in ``block`` as a boundary
    DROP would. Signature matches red_agent's run_cmd: (cmd) -> (rc, text)."""

    def __init__(self, block=()):
        self.block, self.cmds = set(block), []

    def __call__(self, cmd):
        self.cmds.append(cmd)
        if "--step impact" in cmd:
            ok = "impact" not in self.block
            low = str(ok).lower()
            lines = [
                f'{{"phase":"modbus_write","t_send":1.0,"register":0,"value":60.0,"ok":{low},"attempt":1}}',
                f'{{"phase":"impact","attack":"x","ok":{low}}}',
            ]
            return (0 if ok else 1, "\n".join(lines))
        names = ("it_access", "it_exec", "pivot", "ot_foothold", "ot_aitm")
        node = next((n for n in names if f"--step {n}" in cmd), "?")
        ok = node not in self.block
        return (0 if ok else 1, f'{{"phase":"{node}","ok":{str(ok).lower()}}}')


def _drive_in_lab(tree, block=(), profile="opportunistic", goal=None):
    """Run the in-lab agent with a fake exploit_client and return (summary, rows):
    the JSON lines it left in its record, exactly what the host reads back."""
    import red_agent

    ticks = iter(range(1, 10000))
    with tempfile.NamedTemporaryFile("w+", suffix=".jsonl") as f:
        planner = AttackPlanner(tree, profile=profile, goal=goal, seed=1)
        agent = red_agent.RedAgent(
            CTX, f.name, run_cmd=FakeExploit(block=block), clock=lambda: next(ticks)
        )
        summary = agent.run(planner, profile, dwell=0.0)
        f.seek(0)
        rows = [json.loads(line) for line in f if line.strip()]
    return summary, rows


class GT:
    def __init__(self):
        self.rows = []

    def record(self, kind, **f):
        self.rows.append({"kind": kind, **f})


class FakeCtx:
    """The run context the host component needs: it serves the agent's record
    back (as reading /red_actions.jsonl would) and collects ground truth + ledger.
    ``rc`` and ``out`` are what the agent's own exec gave."""

    def __init__(self, record_text, gt, ledger, seed=1, rc=0, out=b""):
        self.record_text, self.gt, self.ledger, self.seed = record_text, gt, ledger, seed
        self.rc, self.out = rc, out

    def run(self, node, cmd, wait=False):
        return (self.out, b"", self.rc)  # the agent already ran; its record is the truth

    def exec_text(self, node, cmd):
        # As `tail -n +N` over the record: from line N on, each line ended by the
        # newline the agent writes after every row.
        start = int(cmd.split("tail -n +", 1)[1].split()[0]) if "tail -n +" in cmd else 1
        lines = [line for line in self.record_text.split("\n") if line]
        return "".join(line + "\n" for line in lines[start - 1 :])

    def emit(self, kind, **f):
        self.ledger.append((kind, f))


class InLabAgent(unittest.TestCase):
    """The agent decides in the lab and leaves a record; the host reconstructs
    the ground truth from it."""

    def setUp(self):
        self.tree = _attack_tree()

    def test_agent_record_schema(self):
        summary, rows = _drive_in_lab(self.tree)
        self.assertTrue(summary["success"])
        self.assertEqual(rows[0]["kind"], "attack_start")
        self.assertEqual(rows[-1]["kind"], "attack_end")
        steps = [r for r in rows if r["kind"] == "plan_step"]
        self.assertTrue(steps)
        self.assertTrue(all(r.get("mode") == "planner:opportunistic" for r in steps))
        # What it aimed at comes before the first step taken towards it.
        self.assertEqual(rows[1]["kind"], "attack_plan")
        self.assertEqual(rows[1]["target"], steps[-1]["target"])
        # The impact step carries its Modbus write under "phases".
        self.assertTrue(
            any(
                any(p.get("phase") == "modbus_write" and p.get("ok") for p in r.get("phases") or [])
                for r in steps
            )
        )

    def _replay(self, rows, profile="opportunistic", goal=None, rc=0, out=b""):
        """Hand ``rows`` to the host component as the record the agent left."""
        from cyberrange.planes.attack.components import PlannedAttacker

        record_text = "\n".join(json.dumps(r) for r in rows)
        gt, ledger = GT(), []
        ctx = FakeCtx(record_text, gt, ledger, rc=rc, out=out)
        pa = PlannedAttacker(
            profile,
            CTX["target_url"],
            CTX["engine_ip"],
            CTX["engine_port"],
            goal=goal,
            tree=lambda _c: self.tree,
        )
        summary = pa.attack(ctx)
        return summary, gt, ledger

    def _reconstruct(self, block=(), profile="opportunistic", goal=None):
        _s, rows = _drive_in_lab(self.tree, block=block, profile=profile, goal=goal)
        return self._replay(rows, profile=profile, goal=goal)

    def test_host_reconstructs_ground_truth(self):
        s, gt, ledger = self._reconstruct()
        kinds = [r["kind"] for r in gt.rows]
        self.assertEqual(kinds[0], "attack_start")
        self.assertEqual(kinds[-1], "attack_end")
        self.assertIn("plan_step", kinds)
        self.assertIn("rce", kinds)  # it_access mapped for metrics
        self.assertTrue(any(r["kind"] == "modbus_write" and r["ok"] for r in gt.rows))
        self.assertTrue(s["success"])
        self.assertTrue(any(k == "plan_step" for k, _ in ledger))
        start = next(r for r in gt.rows if r["kind"] == "attack_start")
        self.assertEqual(start["mode"], "planner:opportunistic")

    def test_blocked_pivot_no_writes(self):
        # Both ways to the plant closed: the flow and the workstation.
        s, gt, _ = self._reconstruct(block={"pivot", "ot_foothold"})
        self.assertFalse(s["success"])
        self.assertEqual(s["stage_reached"], "it_exec")
        self.assertFalse(any(r["kind"] == "modbus_write" and r.get("ok") for r in gt.rows))

    def test_no_record_fails_the_run(self):
        # The agent died before its first line (a module not staged, a bad
        # argument): nothing was attacked, and the run must not pass for a quiet one.
        with self.assertRaises(RuntimeError) as raised:
            self._replay([], rc=1, out=b"ModuleNotFoundError: No module named 'planner'")
        self.assertIn(
            "No module named 'planner'",
            str(raised.exception),
            "the failed run would not say why the agent died",
        )

    def test_live_poll_and_final_read_record_each_row_once(self):
        from cyberrange.planes.attack.components import PlannedAttacker

        _s, rows = _drive_in_lab(self.tree)
        gt, ledger = GT(), []
        ctx = FakeCtx("\n".join(json.dumps(r) for r in rows[:2]), gt, ledger)
        pa = PlannedAttacker(
            "opportunistic",
            CTX["target_url"],
            CTX["engine_ip"],
            CTX["engine_port"],
            tree=lambda _c: self.tree,
        )
        pa.poll(ctx)  # the live thread, while the agent is still at its first step
        self.assertEqual(
            [k for k, _ in ledger][0],
            "attack_start",
            "the attack reached the dashboard only once it was over",
        )
        ctx.record_text = "\n".join(json.dumps(r) for r in rows)  # the agent has exited
        pa.attack(ctx)
        pa.poll(ctx)  # ctx.live polls once more on its way out
        steps = [r for r in rows if r["kind"] == "plan_step"]
        self.assertEqual(len(steps), len([r for r in gt.rows if r["kind"] == "plan_step"]))
        self.assertEqual(len(steps), [k for k, _ in ledger].count("plan_step"))
        self.assertEqual(
            1, [r["kind"] for r in gt.rows].count("attack_start"), "a row was recorded twice"
        )

    def test_the_ledger_carries_what_the_attacker_saw(self):
        _s, gt, ledger = self._reconstruct()
        kinds = [k for k, _ in ledger]
        self.assertEqual((kinds[0], kinds[-1]), ("attack_start", "attack_end"))
        seen = [f["observed"] for k, f in ledger if k == "plan_step"]
        self.assertTrue(
            any(w["ok"] for o in seen for w in o.get("writes", [])),
            "the impact step's accepted writes are what the attacker saw of the plant",
        )
        end = dict(ledger)["attack_end"]
        self.assertTrue(end["success"])

    def test_record_cut_short_is_closed_by_the_host(self):
        _s, rows = _drive_in_lab(self.tree)
        # The agent died after the pivot: no impact step, no attack_end.
        s, gt, _ = self._replay(rows[:-2], rc=137)
        end = gt.rows[-1]
        self.assertEqual(end["kind"], "attack_end", "the metrics would find no outcome")
        self.assertTrue(end["aborted"])
        self.assertEqual((end["success"], end["stage_reached"]), (False, "pivot"))
        self.assertEqual((s["success"], s["stage_reached"], s["writes_ok"]), (False, "pivot", 0))


if __name__ == "__main__":
    unittest.main()
