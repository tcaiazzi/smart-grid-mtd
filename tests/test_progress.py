"""Tests for the progress ledger (monitor/progress.py) and the live
instrumentation of network_scenario/cps_experiment.py — with a FAKE Kathará
manager, so no Docker: the run lifecycle emits its phases in order, the live
plant/sensor poll turns container output into ledger events without
duplicates, a broken exec never breaks a run, and a failing run still closes
its ledger entry with the error.

Run: `.venv/bin/python -m unittest tests.test_progress`.
"""

import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from monitor.progress import NullProgress, ProgressLog, read_events   # noqa: E402
from network_scenario import cps_experiment as cps                  # noqa: E402


class Ledger(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(prefix="ledger-"), "sub", "progress.jsonl")

    def test_seq_continues_after_reopen(self):
        a = ProgressLog(self.path)
        a.emit("x"); a.emit("y")
        a.close()
        b = ProgressLog(self.path)
        b.bind(run_id="r1").emit("z", k=1)
        b.close()
        evs = read_events(self.path)
        self.assertEqual([e["seq"] for e in evs], [0, 1, 2])
        self.assertEqual(evs[2]["run_id"], "r1")
        self.assertEqual(evs[2]["k"], 1)
        self.assertEqual([e["seq"] for e in read_events(self.path, since=2)], [2])

    def test_threads_do_not_interleave(self):
        log = ProgressLog(self.path)
        ts = [threading.Thread(target=lambda i=i: [log.emit("e", w=i) for _ in range(200)])
              for i in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        log.close()
        evs = read_events(self.path)
        self.assertEqual(len(evs), 800)
        self.assertEqual(sorted(e["seq"] for e in evs), list(range(800)))

    def test_partial_last_line_tolerated(self):
        log = ProgressLog(self.path)
        log.emit("ok")
        log.close()
        with open(self.path, "a") as f:
            f.write('{"seq": 1, "kind": "par')
        self.assertEqual(len(read_events(self.path)), 1)

    def test_null_progress(self):
        n = NullProgress()
        self.assertIsNone(n.bind(run_id="x").emit("anything", a=1))


class FakeManager:
    """Stands in for Kathara's manager: canned exec output per machine."""

    def __init__(self, frames=None, telemetry=None, fail_exec=False, fail_deploy=False):
        self.frames = frames or []
        self.telemetry = telemetry or []
        self.fail_exec = fail_exec
        self.fail_deploy = fail_deploy
        self.calls = []

    def exec_obj(self, machine, cmd, stream=True, wait=False):
        name = getattr(machine, "name", str(machine))
        self.calls.append((name, cmd))
        if self.fail_exec and stream is False:
            raise RuntimeError("exec blew up")
        if stream is not False:
            return None                      # background start of an agent
        if "engine_frames" in cmd:
            body = (json.dumps(self.frames.pop(0)) + "\n") if self.frames else ""
            return body.encode(), b"", 0
        if "telemetry.jsonl" in cmd:
            start = int(cmd.split("+")[1].split()[0])
            lines = self.telemetry[start - 1:]
            return "".join(lines).encode(), b"", 0
        return b"", b"", 0

    def deploy_lab(self, lab):
        if self.fail_deploy:
            raise RuntimeError("deploy failed")

    def undeploy_lab(self, lab):
        pass


def _frame(step, v_dg=1.01, mode=0):
    return {"timestamp": 1000.0 + step, "step": step, "v_load": 0.99, "v_dg": v_dg,
            "abnormal": int(v_dg > 1.05), "energy_kwh": 0.1 * step,
            "actuators": {"dg_setpoint": 20.0, "switch_cmd": 0.0, "ctrl_mode": mode}}


def _tel(i, kind, **f):
    return json.dumps({"i": i, "t": 2000.0 + i, "kind": kind, **f}) + "\n"


class Collector:
    def __init__(self):
        self.events = []

    def emit(self, kind, **f):
        self.events.append({"kind": kind, **f})

    __call__ = emit

    def kinds(self):
        return [e["kind"] for e in self.events]


class PlantPoll(unittest.TestCase):
    M = {"engine": types.SimpleNamespace(name="engine"), "sensor": types.SimpleNamespace(name="sensor")}

    def test_plant_only_on_new_step_and_findings_incremental(self):
        mgr = FakeManager(frames=[_frame(1), _frame(1), _frame(2, 1.07, 1)],
                          telemetry=[_tel(0, "sensor_up")])
        col, st = Collector(), {}
        cps._poll_plant(mgr, self.M, col, st)
        mgr.telemetry += [_tel(1, "model_fitted", threshold=6.0),
                          _tel(2, "ot_finding", detector="model", klass="behavioral_anomaly",
                               entities={"src": None, "register": None})]
        cps._poll_plant(mgr, self.M, col, st)          # same step 1 -> no plant event
        mgr.telemetry += ['{"i": 3, "t": 2003, "kind": "ot_fin']      # partial line
        cps._poll_plant(mgr, self.M, col, st)
        mgr.telemetry[-1] = _tel(3, "ot_finding", detector="rules", klass="unsafe_command",
                                 entities={"src": "10.10.0.20", "register": 0})
        mgr.telemetry.append(_tel(4, "ot_alert", state="raised", detector="rules",
                                  klass="unsafe_command"))
        cps._poll_plant(mgr, self.M, col, st)
        self.assertEqual(col.kinds(), ["plant", "model_fitted", "finding", "plant",
                                       "finding", "alert"])
        plants = [e for e in col.events if e["kind"] == "plant"]
        self.assertEqual([p["step"] for p in plants], [1, 2])
        self.assertEqual(plants[1]["ctrl_mode"], 1)
        f = [e for e in col.events if e["kind"] == "finding"]
        self.assertEqual([(x["detector"], x["klass"]) for x in f],
                         [("model", "behavioral_anomaly"), ("rules", "unsafe_command")])
        self.assertEqual(f[1]["src"], "10.10.0.20")
        self.assertEqual(st["tel_lines"], 5)

    def test_exec_errors_are_swallowed(self):
        mgr = FakeManager(fail_exec=True)
        col = Collector()
        cps._poll_plant(mgr, self.M, col, {})     # must not raise
        self.assertEqual(col.events, [])

    def test_observe_keeps_phase_length(self):
        mgr = FakeManager(frames=[_frame(i) for i in range(1, 50)])
        col = Collector()
        t0 = time.time()
        cps._observe(mgr, self.M, 0.5, col, {}, poll_s=0.1)
        el = time.time() - t0
        self.assertGreaterEqual(el, 0.5)
        self.assertLess(el, 0.9)
        self.assertGreaterEqual(len([e for e in col.events if e["kind"] == "plant"]), 3)


class RunLifecycle(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="cps-run-")
        self._saved = (cps.Kathara, cps.Setting, cps._download_artifacts,
                       cps.active_attack.drive_attack, cps.time.sleep, cps.LEARN_MARGIN_S)
        cps.Setting = types.SimpleNamespace(get_instance=lambda: types.SimpleNamespace(
            load_from_dict=lambda d: None))
        cps._download_artifacts = lambda manager, m, out_dir, attack=True: None
        cps.LEARN_MARGIN_S = 0.0
        real_sleep = self._saved[4]
        cps.time.sleep = lambda s: real_sleep(min(s, 0.05))   # services' fixed 2 s pause

        def fake_attack(manager, attacker, gt, **kw):
            gt.record("attack_start", mode=kw["attack_mode"])
            gt.record("modbus_write", register=2, register_name="ctrl_mode", value=1.0, ok=True)
            gt.record("attack_end", rc=0)
            return 0
        cps.active_attack.drive_attack = fake_attack

    def tearDown(self):
        (cps.Kathara, cps.Setting, cps._download_artifacts, cps.active_attack.drive_attack,
         cps.time.sleep, cps.LEARN_MARGIN_S) = self._saved

    def _args(self, attack=True):
        return types.SimpleNamespace(
            out_dir=self.out, seed=1, step_interval=1.0, normal_duration=0.2, learn_seconds=0.1,
            detectors="rules,model", attack=attack, attack_mode="manual-hijack",
            attack_repeat=None, attack_interval=0.5, post_attack_duration=0.2,
            dashboard_port=0, poll_interval=0.05, progress_file=None)

    def _use(self, mgr):
        cps.Kathara = types.SimpleNamespace(get_instance=lambda: mgr)

    def test_phases_in_order_with_own_ledger(self):
        self._use(FakeManager(frames=[_frame(i) for i in range(1, 200)]))
        cps.run(self._args())
        evs = read_events(os.path.join(self.out, "progress.jsonl"))
        kinds = [e["kind"] for e in evs]
        self.assertEqual(kinds[0], "run_start")
        self.assertEqual(kinds[-1], "run_end")
        self.assertEqual(evs[-1]["status"], "ok")
        self.assertTrue(all(e["run_id"] == os.path.basename(self.out) for e in evs))
        phases = [(e["name"], e["state"]) for e in evs if e["kind"] == "phase"]
        names = ["deploy", "services", "normal", "attack", "post_attack", "download", "undeploy"]
        self.assertEqual(phases, [(n, s) for n in names for s in ("start", "end")])
        self.assertEqual([p["name"] for p in evs[0]["phases"]], names)
        self.assertIn("plant", kinds)
        w = [e for e in evs if e["kind"] == "attack_write"]
        self.assertEqual([(x["register_name"], x["value"]) for x in w], [("ctrl_mode", 1.0)])

    def test_normal_run_has_no_attack_phases(self):
        self._use(FakeManager())
        cps.run(self._args(attack=False), progress=(col := Collector()))
        names = [e["name"] for e in col.events if e["kind"] == "phase" and e["state"] == "start"]
        self.assertEqual(names, ["deploy", "services", "normal", "download", "undeploy"])
        self.assertEqual(col.events[0]["mode"], "normal")

    def test_failure_is_recorded_and_raised(self):
        self._use(FakeManager(fail_deploy=True))
        col = Collector()
        with self.assertRaises(RuntimeError):
            cps.run(self._args(), progress=col)
        end = col.events[-1]
        self.assertEqual(end["kind"], "run_end")
        self.assertEqual(end["status"], "failed")
        self.assertIn("deploy failed", end["error"])
        deploy = [e for e in col.events if e["kind"] == "phase" and e["name"] == "deploy"]
        self.assertEqual(deploy[-1]["ok"], False)


if __name__ == "__main__":
    unittest.main()
