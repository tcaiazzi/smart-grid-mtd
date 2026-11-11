"""Tests for the progress ledger (cyberrange/core/progress.py) and the live
instrumentation of a run (cyberrange/core lifecycle + the CPS scenario's
monitor components) — with a FAKE Kathará manager, so no Docker: the run
lifecycle emits its phases in order, the live plant/sensor mirrors turn
container output into ledger events without duplicates, a broken exec never
breaks a run, and a failing run still closes its ledger entry with the error.

Run: `.venv/bin/python -m unittest tests.test_progress`.
"""

import json
import os
import tempfile
import threading
import time
import types
import unittest


from cyberrange.planes.attack import active_attack  # noqa: E402
from cyberrange.planes.defense.components import OtSensor  # noqa: E402
from cyberrange.planes.monitor.components import PlantMirror, TelemetryMirror  # noqa: E402
from cyberrange.core.progress import NullProgress, ProgressLog, read_events  # noqa: E402
from cyberrange.scenarios.cps import cli as cps  # noqa: E402
from cyberrange.core.cli import default_args  # noqa: E402
from cyberrange.core.context import RunContext  # noqa: E402
from cyberrange.scenarios.cps import scenario as cps_scenario  # noqa: E402
from tests.helpers.kathara import FakeManager, fake_downloads  # noqa: E402


class Ledger(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(prefix="ledger-"), "sub", "progress.jsonl")

    def test_seq_continues_after_reopen(self):
        a = ProgressLog(self.path)
        a.emit("x")
        a.emit("y")
        a.close()
        b = ProgressLog(self.path)
        b.bind(run_id="r1").emit("z", k=1)
        b.close()
        evs = read_events(self.path)
        self.assertEqual([e["seq"] for e in evs], [0, 1, 2])
        self.assertEqual(evs[2]["run_id"], "r1")
        self.assertEqual(evs[2]["k"], 1)
        self.assertEqual([e["seq"] for e in read_events(self.path, since=2)], [2])

    def test_an_open_ledger_stays_fresh_without_events(self):
        """A step that emits nothing for minutes (training) must not look dead:
        the reader decides "interrupted" from the file's modification time."""
        from cyberrange.core import progress

        saved, progress.HEARTBEAT_S = progress.HEARTBEAT_S, 0.05
        try:
            log = ProgressLog(self.path)
        finally:
            progress.HEARTBEAT_S = saved
        log.emit("campaign_start")
        old = time.time() - 3600
        os.utime(self.path, (old, old))
        deadline = time.time() + 5
        while os.path.getmtime(self.path) < old + 1 and time.time() < deadline:
            time.sleep(0.02)
        self.assertGreater(
            os.path.getmtime(self.path),
            old + 1,
            "a silent but live writer left its ledger stale: the dashboard would "
            "show a healthy campaign as interrupted",
        )
        log.close()
        os.utime(self.path, (old, old))
        time.sleep(0.3)
        self.assertLess(
            os.path.getmtime(self.path), old + 1, "a closed ledger is still being kept alive"
        )
        self.assertEqual(1, len(read_events(self.path)), "the heartbeat wrote an event")

    def test_a_caller_cannot_overwrite_the_ledger_keys(self):
        log = ProgressLog(self.path)
        log.emit("a")
        log.emit("mtd_action", seq=0, t=1.0, action="hop")  # a mirrored guest event
        log.emit("b")
        log.close()
        evs = read_events(self.path)
        self.assertEqual(
            [e["seq"] for e in evs],
            [0, 1, 2],
            "a mirrored event kept its own seq: readers page on seq, so the dashboard "
            "would drop it or fetch the whole ledger again on every poll",
        )
        self.assertGreater(evs[1]["t"], 1.0, "the ledger's clock was replaced by the guest's")
        self.assertEqual(evs[1]["action"], "hop")

    def test_threads_do_not_interleave(self):
        log = ProgressLog(self.path)
        ts = [
            threading.Thread(target=lambda i=i: [log.emit("e", w=i) for _ in range(200)])
            for i in range(4)
        ]
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


def _frame(step, v_dg=1.01, mode=0):
    return {
        "timestamp": 1000.0 + step,
        "step": step,
        "v_load": 0.99,
        "v_dg": v_dg,
        "abnormal": int(v_dg > 1.05),
        "energy_kwh": 0.1 * step,
        "actuators": {"dg_setpoint": 20.0, "switch_cmd": 0.0, "ctrl_mode": mode},
    }


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


def _live_ctx(mgr, col):
    """A RunContext with the CPS sensor started and the two live mirrors."""
    machines = {n: types.SimpleNamespace(name=n) for n in ("engine", "sensor")}
    ctx = RunContext(
        mgr,
        None,
        machines,
        types.SimpleNamespace(poll_interval=0),
        tempfile.mkdtemp(prefix="cps-live-"),
        col,
    )
    ctx.start(
        OtSensor(
            "sensor", "eth0", "10.20.0.20", 5020, "10.20.0.10", "10.10.0.20", "rules,model", 45
        )
    )
    ctx.start(PlantMirror("engine"))
    ctx.start(TelemetryMirror())
    return ctx


class PlantPoll(unittest.TestCase):
    def test_plant_only_on_new_step_and_findings_incremental(self):
        mgr = FakeManager(
            frames=[_frame(1), _frame(1), _frame(2, 1.07, 1)],
            files={"/telemetry.jsonl": [_tel(0, "sensor_up")]},
        )
        col = Collector()
        ctx = _live_ctx(mgr, col)
        tel = mgr.files["/telemetry.jsonl"]
        ctx.poll()
        tel += [
            _tel(1, "model_fitted", threshold=6.0),
            _tel(
                2,
                "ot_finding",
                detector="model",
                klass="behavioral_anomaly",
                entities={"src": None, "register": None},
            ),
        ]
        ctx.poll()  # same step 1 -> no plant event
        tel += ['{"i": 3, "t": 2003, "kind": "ot_fin']  # partial line
        ctx.poll()
        tel[-1] = _tel(
            3,
            "ot_finding",
            detector="rules",
            klass="unsafe_command",
            entities={"src": "10.10.0.20", "register": 0},
        )
        tel.append(_tel(4, "ot_alert", state="raised", detector="rules", klass="unsafe_command"))
        ctx.poll()
        self.assertEqual(
            col.kinds(), ["plant", "model_fitted", "finding", "plant", "finding", "alert"]
        )
        plants = [e for e in col.events if e["kind"] == "plant"]
        self.assertEqual([p["step"] for p in plants], [1, 2])
        self.assertEqual(plants[1]["ctrl_mode"], 1)
        f = [e for e in col.events if e["kind"] == "finding"]
        self.assertEqual(
            [(x["detector"], x["klass"]) for x in f],
            [("model", "behavioral_anomaly"), ("rules", "unsafe_command")],
        )
        self.assertEqual(f[1]["src"], "10.10.0.20")
        mirror = ctx.components[-1]
        self.assertEqual(mirror.lines[("sensor", "/telemetry.jsonl")], 5)

    def test_exec_errors_are_swallowed(self):
        col = Collector()
        _live_ctx(FakeManager(fail_exec=True), col).poll()  # must not raise
        self.assertEqual(col.events, [])

    def test_observe_keeps_phase_length(self):
        col = Collector()
        ctx = _live_ctx(FakeManager(frames=[_frame(i) for i in range(1, 50)]), col)
        t0 = time.time()
        ctx.observe(0.5, poll_s=0.1)
        el = time.time() - t0
        self.assertGreaterEqual(el, 0.5)
        self.assertLess(el, 0.9)
        self.assertGreaterEqual(len([e for e in col.events if e["kind"] == "plant"]), 3)


class RunLifecycle(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="cps-run-")
        self._saved = (
            active_attack.drive_attack,
            cps_scenario.LEARN_MARGIN_S,
            cps_scenario.SERVICE_SETTLE_S,
        )
        cps_scenario.LEARN_MARGIN_S = 0.0
        cps_scenario.SERVICE_SETTLE_S = 0.0

        def fake_attack(manager, attacker, gt, **kw):
            gt.record("attack_start", mode=kw["attack_mode"])
            gt.record("modbus_write", register=2, register_name="ctrl_mode", value=1.0, ok=True)
            gt.record("attack_end", rc=0)
            return 0

        active_attack.drive_attack = fake_attack

    def tearDown(self):
        (active_attack.drive_attack, cps_scenario.LEARN_MARGIN_S, cps_scenario.SERVICE_SETTLE_S) = (
            self._saved
        )

    def _args(self, attack=True):
        return default_args(
            cps_scenario.CpsScenario(),
            out_dir=self.out,
            seed=1,
            normal_duration=0.2,
            learn_seconds=0.1,
            attack=attack,
            attack_mode="manual-hijack",
            post_attack_duration=0.2,
            poll_interval=0.05,
        )

    def _run(self, mgr, progress=None, attack=True):
        with fake_downloads():
            return cps.run(self._args(attack), progress=progress, manager=mgr)

    def test_phases_in_order_with_own_ledger(self):
        mgr = FakeManager(frames=[_frame(i) for i in range(1, 200)])
        self.assertEqual(self._run(mgr), 0)
        evs = read_events(os.path.join(self.out, "progress.jsonl"))
        kinds = [e["kind"] for e in evs]
        self.assertEqual(kinds[0], "run_start")
        self.assertEqual(evs[0]["scenario"], "cps")
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
        self.assertEqual(mgr.deployed, ["cps"])
        self.assertEqual(mgr.undeployed, ["cps", "cps"])  # stale lab first, then ours
        self.assertTrue(os.path.exists(os.path.join(self.out, "topology.json")))

    def test_planner_label_on_run_start(self):
        args = self._args()
        args.attack_driver, args.attacker_profile = "planner", "stealthy"
        info = cps_scenario.CpsScenario().run_info(args)
        self.assertEqual(info["mode"], "planner:stealthy")

    def test_normal_run_has_no_attack_phases(self):
        col = Collector()
        self._run(FakeManager(), progress=col, attack=False)
        names = [e["name"] for e in col.events if e["kind"] == "phase" and e["state"] == "start"]
        self.assertEqual(names, ["deploy", "services", "normal", "download", "undeploy"])
        self.assertEqual(col.events[0]["mode"], "normal")

    def test_failure_is_recorded_and_raised(self):
        col = Collector()
        with self.assertRaises(RuntimeError):
            self._run(FakeManager(fail_deploy=True), progress=col)
        end = col.events[-1]
        self.assertEqual(end["kind"], "run_end")
        self.assertEqual(end["status"], "failed")
        self.assertIn("deploy failed", end["error"])
        deploy = [e for e in col.events if e["kind"] == "phase" and e["name"] == "deploy"]
        self.assertEqual(deploy[-1]["ok"], False)

    def test_lab_is_undeployed_when_the_episode_fails(self):
        def boom(*a, **k):
            raise RuntimeError("attack exploded")

        active_attack.drive_attack = boom
        mgr = FakeManager()
        with self.assertRaises(RuntimeError):
            self._run(mgr, progress=Collector())
        self.assertEqual(mgr.undeployed, ["cps", "cps"])

    def test_artifacts_are_downloaded_when_the_episode_fails(self):
        def boom(*a, **k):
            raise RuntimeError("attack exploded")

        active_attack.drive_attack = boom
        col = Collector()
        with self.assertRaises(RuntimeError):
            self._run(FakeManager(), progress=col)
        started = [e["name"] for e in col.events if e["kind"] == "phase" and e["state"] == "start"]
        self.assertIn(
            "download",
            started,
            "a failed episode was torn down without its artifacts: the console logs "
            "holding the crash traceback are gone",
        )
        self.assertLess(started.index("download"), started.index("undeploy"))

    def test_lab_is_undeployed_when_the_deploy_fails(self):
        mgr = FakeManager(fail_deploy=True)
        with self.assertRaises(RuntimeError):
            self._run(mgr, progress=Collector())
        self.assertEqual(
            mgr.undeployed,
            ["cps", "cps"],
            "a deploy that died halfway left its containers and networks running",
        )


if __name__ == "__main__":
    unittest.main()
