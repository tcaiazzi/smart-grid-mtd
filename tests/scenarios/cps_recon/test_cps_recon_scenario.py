"""The cps-recon scenario (cyberrange/scenarios/cps_recon): the cps lab with an
attacker that derives its own attack tree by reconnaissance. The attacker runs on
its own red-team image; the host reconstructs the ground truth from the agent's
record and scores how close the derived tree was. No Docker.

Run: `.venv/bin/python -m pytest tests/scenarios/cps_recon`.
"""

import json
import os
import tempfile
import unittest

from cyberrange.core import registry
from cyberrange.core.cli import default_args
from cyberrange.planes.attack import components as attack
from cyberrange.scenarios.cps.metrics import _tree_fidelity
from cyberrange.scenarios.cps_recon.scenario import CpsReconScenario


class Options(unittest.TestCase):
    def setUp(self):
        self.s = CpsReconScenario()
        self.args = default_args(self.s)

    def test_registered_under_its_own_name_and_lab(self):
        self.assertEqual(registry.get("cps-recon").name, "cps-recon")
        self.assertEqual(self.s.lab_name, "cps-recon")
        self.assertEqual(self.args.out_dir, "output/cps-recon/run-1")

    def test_recon_scope_defaults(self):
        self.assertEqual(self.args.it_cidr, "10.10.0.0/24")
        self.assertIn("8080", self.args.scan_ports)

    def test_attacker_is_recon_driven(self):
        a = self.s.attacker(self.args)
        self.assertIsInstance(a, attack.ReconAttacker)
        self.assertEqual(a.label, "recon:opportunistic")

    def test_attacker_runs_on_the_redteam_image_the_hmi_does_not(self):
        topo = self.s.topology(self.args)
        nodes = {n.name: n for n in topo.nodes}
        self.assertEqual(topo.image_of(nodes["attacker"]), "kathara/redteam")
        self.assertEqual(topo.image_of(nodes["hmi"]), "kathara/cps")
        staged = [guest for _host, guest in nodes["attacker"].files]
        for f in ("/recon.py", "/belief_tree.py", "/red_recon_agent.py"):
            self.assertIn(f, staged)


class GT:
    def __init__(self):
        self.rows = []

    def record(self, kind, **f):
        self.rows.append({"kind": kind, **f})


class FakeCtx:
    """What the host component needs: it serves the agent's record back and
    collects the ground truth and the ledger."""

    def __init__(self, record_text):
        self.record_text, self.gt, self.ledger, self.seed = record_text, GT(), [], 1

    def run(self, node, cmd, wait=False):
        return (b"", b"", 0)

    def exec_text(self, node, cmd):
        # As `tail -n +N` over the record: from line N on, each line ended by the
        # newline the agent writes after every row.
        start = int(cmd.split("tail -n +", 1)[1].split()[0]) if "tail -n +" in cmd else 1
        lines = [line for line in self.record_text.split("\n") if line]
        return "".join(line + "\n" for line in lines[start - 1 :])

    def emit(self, kind, **f):
        self.ledger.append((kind, f))


class Reconstruction(unittest.TestCase):
    """The agent decided in the lab; the host turns its record into ground truth,
    the recon findings included — reusing PlannedAttacker's machinery."""

    RECORD = [
        {"kind": "recon", "t": 1.0, "stage": "it", "foothold": {"ip": "10.10.0.20", "port": 8080}},
        {"kind": "recon", "t": 2.0, "stage": "ot", "engine_ip": "10.20.0.20", "modbus_ok": True,
         "modbus_port": 5020, "registers": {"0": 20, "2": 0}},
        {"kind": "belief", "t": 2.5, "tree": {"id": "via_hmi", "children": [{"id": "it_access"}]}},
        {"kind": "attack_start", "t": 3.0, "mode": "planner:opportunistic"},
        {"kind": "plan_step", "t": 4.0, "mode": "planner:opportunistic", "node": "it_access",
         "stage": "it_access", "ok": True, "phases": []},
        {"kind": "plan_step", "t": 5.0, "mode": "planner:opportunistic", "node": "breaker_open",
         "stage": "impact", "ok": True, "writes": 1,
         "phases": [{"phase": "modbus_write", "t_send": 5.1, "register": 1, "value": 1.0,
                     "ok": True}]},
        {"kind": "attack_end", "t": 6.0, "mode": "planner:opportunistic", "success": True,
         "stage_reached": "impact", "writes_ok": 1},
    ]  # fmt: skip

    def test_the_dashboard_gets_what_recon_found_and_the_tree_it_built(self):
        ctx = FakeCtx("\n".join(json.dumps(r) for r in self.RECORD))
        attack.ReconAttacker("opportunistic", "10.10.0.0/24").attack(ctx)
        ot = [f for k, f in ctx.ledger if k == "recon" and f["stage"] == "ot"][0]
        self.assertEqual((ot["modbus_port"], ot["registers"]), (5020, {"0": 20, "2": 0}))
        belief = [f for k, f in ctx.ledger if k == "attacker_belief"]
        self.assertEqual(belief[0]["tree"]["id"], "via_hmi")
        self.assertNotIn(
            "belief",
            [r["kind"] for r in ctx.gt.rows],
            "what the attacker believes is not something that happened",
        )

    def test_host_reconstructs_recon_and_attack(self):
        ctx = FakeCtx("\n".join(json.dumps(r) for r in self.RECORD))
        pa = attack.ReconAttacker("opportunistic", "10.10.0.0/24")
        summary = pa.attack(ctx)
        kinds = [r["kind"] for r in ctx.gt.rows]
        self.assertEqual(kinds.count("recon"), 2)
        self.assertIn("attack_start", kinds)
        self.assertIn("plan_step", kinds)
        self.assertIn("modbus_write", kinds)
        self.assertIn("rce", kinds)  # it_access mapped for metrics
        self.assertEqual(kinds[-1], "attack_end")
        self.assertTrue(summary["success"])
        self.assertEqual([k for k, _ in ctx.ledger].count("recon"), 2)


class Fidelity(unittest.TestCase):
    """The scored comparison of the derived tree against the true one."""

    def _write(self, out_dir, belief_leaves, true_leaves):
        def tree(leaves):
            return {
                "id": "via_hmi", "gate": "AND",
                "children": [{"id": i, "gate": "LEAF", "feasible": i in leaves,
                              "children": []} for i in ALL],
            }  # fmt: skip

        with open(os.path.join(out_dir, "attacker.belief_tree.json"), "w") as f:
            json.dump(tree(belief_leaves), f)
        with open(os.path.join(out_dir, "tree.json"), "w") as f:
            json.dump({"attack_tree": tree(true_leaves)}, f)

    def test_precision_recall_and_id_lists(self):
        with tempfile.TemporaryDirectory() as d:
            # The attacker found it_access/pivot, missed breaker_open, and wrongly
            # believed setpoint_oor feasible.
            self._write(d, belief_leaves={"it_access", "pivot", "setpoint_oor"},
                        true_leaves={"it_access", "pivot", "breaker_open"})  # fmt: skip
            fid = _tree_fidelity(d)
        self.assertEqual(fid["discovered"], ["it_access", "pivot"])
        self.assertEqual(fid["missing"], ["breaker_open"])
        self.assertEqual(fid["extra"], ["setpoint_oor"])
        self.assertAlmostEqual(fid["precision"], 2 / 3, places=2)
        self.assertAlmostEqual(fid["recall"], 2 / 3, places=2)

    def test_absent_belief_tree_is_none(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(_tree_fidelity(d))


ALL = ["it_access", "it_exec", "pivot", "setpoint_oor", "breaker_open", "mode_hijack"]


if __name__ == "__main__":
    unittest.main()
