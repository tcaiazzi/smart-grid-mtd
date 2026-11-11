"""Response loop (cyberrange.scenarios.cps.responder) with a fake lab: incremental
telemetry reads, recorded command execution, approvals, offline replay.

Run: `.venv/bin/python -m unittest tests.test_cps_responder`.
"""

import json
import os
import tempfile
import unittest


from cyberrange.planes.defense.soar import policy  # noqa: E402
from cyberrange.scenarios.cps import topology as cps  # noqa: E402
from cyberrange.scenarios.cps import responder as cr  # noqa: E402
from tests.helpers.soar import HMI, finding  # noqa: E402

HIJACK = [
    {"i": 0, "t": 0.5, "kind": "sensor_up"},
    finding("unsafe_command", 2.0, HMI, "ctrl_mode", conf=0.85, value=1.0),
    finding("manual_mode_excursion", 3.0, None, "ctrl_mode"),
]


class FakeLab:
    """Serves the sensor telemetry a chunk at a time and records commands."""

    def __init__(self, events, chunk=1):
        self.text = "".join(json.dumps(e) + "\n" for e in events)
        self.served = 0
        self.chunk = chunk
        self.cmds = []

    def read(self, start_line):
        lines = self.text.splitlines(keepends=True)
        upto = min(len(lines), self.served + self.chunk)
        self.served = upto
        out = "".join(lines[start_line - 1 : upto])
        if upto < len(lines):  # a half-written next line
            out += lines[upto][:7]
        return out

    def exec(self, machine, cmd):
        self.cmds.append((machine, cmd))
        return 0, ""


def read_jsonl(path):
    with open(path) as f:
        return [json.loads(x) for x in f if x.strip()]


class Responder(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def make(self, events, kind="rules", approval="auto", chunk=1):
        lab = FakeLab(events, chunk)
        r = cr.Responder(
            None, {}, kind, self.dir, approval=approval, exec_fn=lab.exec, read_fn=lab.read
        )
        return r, lab

    def test_rules_hijack_applies_block_then_auto(self):
        r, lab = self.make(HIJACK)
        for _ in range(len(HIJACK) + 2):
            r.poll_once()
        r.record.close()
        machines = [m for m, _c in lab.cmds]
        self.assertEqual(machines[0], "firewall")
        self.assertIn(f"-s {cps.HMI_IP} -d {cps.ENGINE_IP}", lab.cmds[0][1])
        self.assertEqual(machines[-1], "engine")
        self.assertIn("ot_write.py 127.0.0.1", lab.cmds[-1][1])
        rows = read_jsonl(os.path.join(self.dir, "response.jsonl"))
        kinds = [x["kind"] for x in rows]
        self.assertEqual(kinds[0], "response_up")
        self.assertIn("tree_state", kinds)
        actions = [x for x in rows if x["kind"] == "action"]
        self.assertEqual([a["id"] for a in actions], ["block_flow", "force_auto"])
        self.assertTrue(all(a["ok"] for a in actions))
        dec = [x for x in rows if x["kind"] == "decision"]
        self.assertTrue(all(x["rationale"] for x in dec))
        for f in ("kg.json", "tree.json"):
            self.assertTrue(os.path.exists(os.path.join(self.dir, f)), f)

    def test_ledger_gets_compact_state_on_change(self):
        lab = FakeLab(HIJACK + [HIJACK[-1]], chunk=10)  # the repeat changes nothing
        ledger = []
        r = cr.Responder(
            None,
            {},
            "rules",
            self.dir,
            exec_fn=lab.exec,
            read_fn=lab.read,
            emit=lambda kind, **f: ledger.append((kind, f)),
        )
        r.poll_once()
        states = [f for k, f in ledger if k == "tree_state"]
        # The first finding already confirms the leaf; later ones change no state.
        self.assertEqual(len(states), 1)
        last = states[-1]
        self.assertEqual(last["nodes"]["mode_hijack"][0], "confirmed")
        self.assertEqual(last["nodes"]["pivot"][0], "inferred")
        self.assertEqual(last["hosts"], ["hmi"])
        self.assertIn("mode_hijack", last["active"])
        decisions = [f for k, f in ledger if k == "decision"]
        self.assertTrue(decisions and all(d["rationale"] for d in decisions))
        self.assertIn("covers", decisions[-1])

    def test_write_structure(self):
        cr.write_structure(self.dir)
        with open(os.path.join(self.dir, "kg.json")) as f:
            kg = json.load(f)
        with open(os.path.join(self.dir, "tree.json")) as f:
            tree = json.load(f)
        self.assertTrue(any(n["id"] == "host:hmi" for n in kg["nodes"]))
        self.assertEqual(tree["attack_tree"]["id"], "impact")

    def test_partial_lines_are_not_lost(self):
        r, lab = self.make(HIJACK, chunk=1)
        for _ in range(10):
            r.poll_once()
        self.assertEqual(r._lines, len(HIJACK))
        self.assertEqual(r.engine.state.n_findings, 2)

    def test_failed_command_recorded(self):
        r, lab = self.make(HIJACK, chunk=10)
        lab.exec = lambda machine, cmd: (1, "iptables: not found")
        r._exec = lab.exec
        r.poll_once()
        r.record.close()
        actions = [
            x for x in read_jsonl(os.path.join(self.dir, "response.jsonl")) if x["kind"] == "action"
        ]
        self.assertTrue(actions and not any(a["ok"] for a in actions))
        self.assertEqual(actions[0]["commands"][0]["rc"], 1)

    def test_it_source_triggers_early_response(self):
        # With IT telemetry, a confirmed it_exec from the HMI sensor triggers an
        # early response before any OT write.
        it_exec = {
            "i": 0,
            "t": 2.0,
            "kind": "ot_finding",
            "detector": "it",
            "klass": "web_child_process",
            "reasons": ["web_child_process"],
            "confidence": 0.9,
            "maps_to": "it_exec",
            "entities": {
                "src": cps.HMI_IP,
                "dst": None,
                "unit": None,
                "register": None,
                "name": None,
            },
            "evidence": {},
        }
        ot_lab = FakeLab([{"i": 0, "t": 0.5, "kind": "sensor_up"}])
        it_lab = FakeLab([it_exec], chunk=10)
        r = cr.Responder(
            None,
            {},
            "rules",
            self.dir,
            it=True,
            exec_fn=ot_lab.exec,
            read_fn=ot_lab.read,
            it_read_fn=it_lab.read,
        )
        for _ in range(3):
            r.poll_once()
        r.record.close()
        acted = {m for m, _c in ot_lab.cmds}
        self.assertIn("hmi", acted)  # kill_proc_tree runs on the HMI
        ids = [
            x["id"]
            for x in read_jsonl(os.path.join(self.dir, "response.jsonl"))
            if x["kind"] == "action"
        ]
        self.assertIn("kill_proc_tree", ids)

    def test_delayed_approval(self):
        r, lab = self.make([], approval="delay:0")
        d = policy.Decision(1.0, "test", ["isolate_hmi"], {}, {}, "test")
        r._dispatch(d)
        self.assertEqual(lab.cmds, [])  # waiting for the operator
        r._run_due()
        self.assertEqual(lab.cmds, [("hmi", "ip link set eth0 down")])
        r.record.close()
        states = [
            x["state"]
            for x in read_jsonl(os.path.join(self.dir, "response.jsonl"))
            if x["kind"] == "approval"
        ]
        self.assertEqual(states, ["requested", "granted"])

    def test_parse_approval(self):
        self.assertEqual(cr.parse_approval("auto"), ("auto", 0.0))
        self.assertEqual(cr.parse_approval("delay:2.5"), ("delay", 2.5))
        for bad in ("maybe", "delay:x", "delay:-1"):
            with self.assertRaises(ValueError):
                cr.parse_approval(bad)

    def test_replay(self):
        with open(os.path.join(self.dir, "sensor.telemetry.jsonl"), "w") as f:
            for e in HIJACK:
                f.write(json.dumps(e) + "\n")
        out = os.path.join(self.dir, "replay.jsonl")
        decisions, _rows = cr.replay_run(self.dir, "rules", out_path=out)
        acts = [a for d in decisions for a in d.actions if a != "notify"]
        self.assertEqual(acts, ["block_flow", "force_auto"])
        planned = [x for x in read_jsonl(out) if x["kind"] == "action"]
        self.assertTrue(all(x["planned"] for x in planned))


if __name__ == "__main__":
    unittest.main()
