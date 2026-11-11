"""Test cyberrange.scenarios.cps.metrics against synthetic run artifacts: a normal phase with
no findings, then an attack that drives abnormal frames and a DPI finding. Checks
detection latency, zero false alarms, physical deviation and energy accounting.

Run: `.venv/bin/python -m unittest tests.test_cps_metrics`.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.scenarios.cps.metrics import compute_metrics, format_report  # noqa: E402


def _write(p, rows):
    with open(p, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


class CpsMetrics(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="cps-metrics-"))
        t0 = 1000.0
        self.attack_t = t0 + 10.0
        # engine frames: 10 normal (in band) then 6 abnormal (overvoltage)
        frames = []
        e = 0.0
        for i in range(10):
            e += 0.01
            frames.append({"timestamp": t0 + i, "step": i, "v_load": 0.99, "v_dg": 1.00,
                           "abnormal": 0, "energy_kwh": round(e, 5), "dg_setpoint": 20.0})
        for j in range(6):
            e += 0.02
            frames.append({"timestamp": self.attack_t + j, "step": 10 + j, "v_load": 1.08,
                           "v_dg": 1.15, "abnormal": 1, "energy_kwh": round(e, 5),
                           "dg_setpoint": 200.0})
        _write(self.d / "engine.engine_frames.jsonl", frames)
        # telemetry: a finding 2s after the attack start
        _write(self.d / "sensor.telemetry.jsonl", [
            {"i": 0, "t": t0, "kind": "sensor_up"},
            {"i": 1, "t": self.attack_t + 2.0, "kind": "ot_finding",
             "klass": "out_of_range_command", "confidence": 0.9,
             "entities": {"src": "10.10.0.20", "register": 0}},
            {"i": 2, "t": self.attack_t + 2.0, "kind": "ot_alert", "state": "raised"},
        ])
        # ground truth: the attack window
        _write(self.d / "ground_truth.jsonl", [
            {"t": self.attack_t, "kind": "attack_start", "mode": "setpoint-overvoltage"},
            {"t": self.attack_t + 4.0, "kind": "modbus_write", "register": 0, "value": 200.0},
            {"t": self.attack_t + 5.0, "kind": "attack_end", "rc": 0},
        ])

    def test_metrics(self):
        m = compute_metrics(str(self.d))
        self.assertTrue(m["attack"])
        self.assertTrue(m["detected"])
        self.assertAlmostEqual(m["detection_latency_s"], 2.0, places=3)
        self.assertEqual(m["false_alarms"], 0)
        self.assertEqual(m["abnormal_frames"], 6)
        self.assertGreater(m["max_abs_deviation_pu"], 0.1)   # v_dg 1.15 -> 0.15
        self.assertGreater(m["energy_kwh_total"], 0)
        self.assertGreater(m["energy_kwh_during_attack"], 0)
        # report renders
        self.assertIn("detected: yes", format_report(m))

    def test_normal_only_no_false_alarm(self):
        # Remove the ground truth and the finding -> a clean normal run.
        (self.d / "ground_truth.jsonl").unlink()
        _write(self.d / "sensor.telemetry.jsonl", [{"i": 0, "t": 1000.0, "kind": "sensor_up"}])
        m = compute_metrics(str(self.d))
        self.assertFalse(m["attack"])
        self.assertEqual(m["false_alarms"], 0)
        self.assertFalse(m["detected"])


class CpsMetricsV2(unittest.TestCase):
    """manual-hijack shaped run: a legitimate operator MANUAL window in the
    normal phase (with one model false alarm inside it), then the hijack: the
    model flags it at write time, the rules once the physics moves, and the
    impact lasts to the end of the run."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="cps-metrics-v2-"))
        t0 = 2000.0
        self.attack_t = t0 + 30.0
        self.write_t = self.attack_t + 2.0
        frames = []
        for i in range(60):
            t = t0 + i
            op = 10 <= i < 15                      # operator window
            hijacked = t >= self.write_t + 1.0
            frames.append({
                "timestamp": t, "step": i, "v_load": 1.01 if hijacked else 0.995,
                "v_dg": 1.068 if hijacked else 1.01, "abnormal": int(hijacked),
                "energy_kwh": round(0.01 * (i + 1), 5),
                "actuators": {"dg_setpoint": 60.0 if hijacked else 20.0,
                              "ctrl_mode": 1 if (op or t >= self.write_t) else 0}})
        _write(self.d / "engine.engine_frames.jsonl", frames)
        _write(self.d / "sensor.telemetry.jsonl", [
            {"t": t0, "kind": "sensor_up"},
            {"t": t0 + 20.0, "kind": "model_fitted", "threshold": 6.0},
            {"t": t0 + 12.0, "kind": "ot_finding", "detector": "model",
             "klass": "behavioral_anomaly", "entities": {}},
            {"t": self.write_t + 0.6, "kind": "ot_finding", "detector": "model",
             "klass": "behavioral_anomaly", "entities": {}},
            {"t": self.write_t + 2.1, "kind": "ot_finding", "detector": "rules",
             "klass": "unsafe_command", "entities": {"src": "10.10.0.20", "register": 0}},
        ])
        _write(self.d / "ground_truth.jsonl", [
            {"t": self.attack_t, "kind": "attack_start", "mode": "manual-hijack"},
            {"t": self.write_t, "kind": "modbus_write", "register": 2, "value": 1.0, "ok": True},
            {"t": self.write_t, "kind": "modbus_write", "register": 0, "value": 60.0, "ok": True},
            {"t": self.write_t + 0.5, "kind": "attack_end", "rc": 0},
        ])

    def test_per_detector(self):
        m = compute_metrics(str(self.d))
        rules, model = m["detectors"]["rules"], m["detectors"]["model"]
        self.assertTrue(rules["detected"] and model["detected"])
        self.assertAlmostEqual(model["latency_from_write_s"], 0.6, places=3)
        self.assertAlmostEqual(rules["latency_from_write_s"], 2.1, places=3)
        self.assertTrue(model["before_impact"])
        self.assertFalse(rules["before_impact"])
        self.assertEqual(rules["classes"], ["unsafe_command"])
        self.assertEqual((model["false_alarms"], model["false_alarms_in_operator_windows"]), (1, 1))
        self.assertEqual(rules["false_alarms"], 0)
        self.assertEqual(m["detectors"]["combined"]["detection_latency_s"], 2.6)
        self.assertEqual(m["model_threshold"], 6.0)

    def test_impact_persists(self):
        m = compute_metrics(str(self.d))
        self.assertAlmostEqual(m["time_to_impact_s"], 1.0, places=3)
        self.assertTrue(m["impact_ongoing_at_end"])
        self.assertTrue(m["impact_persists_after_attack"])
        self.assertFalse(m["recovered"])
        self.assertIsNone(m["recovery_s"])
        self.assertAlmostEqual(m["manual_mode_s"], 28.0, places=3)   # 2032 -> 2060
        report = format_report(m)
        self.assertIn("| model | yes |", report)
        self.assertIn("persists after attack=True", report)

    def test_recovered_run(self):
        # Same run, but the plant comes back in band 5 s after the impact.
        with open(self.d / "engine.engine_frames.jsonl") as f:
            rows = [json.loads(x) for x in f]
        for r in rows:
            if r["timestamp"] >= self.write_t + 6.0:
                r.update(abnormal=0, v_dg=1.01, v_load=0.995)
        _write(self.d / "engine.engine_frames.jsonl", rows)
        m = compute_metrics(str(self.d))
        self.assertTrue(m["recovered"])
        self.assertFalse(m["impact_ongoing_at_end"])
        self.assertAlmostEqual(m["recovery_s"], 5.0, places=3)
        # MTM: first normal frame after the last abnormal one, from the first write.
        self.assertAlmostEqual(m["mitigated_s"], 6.0, places=3)
        self.assertIsNone(m["response"])          # no responder ran

    def test_response_metrics(self):
        # Responder: block at write+1.0 (a later attacker write still lands
        # before it, one after it fails), back to AUTO at write+1.2.
        with open(self.d / "ground_truth.jsonl", "a") as f:
            f.write(json.dumps({"t": self.write_t + 0.8, "kind": "modbus_write",
                                "register": 0, "value": 60.0, "ok": True}) + "\n")
            f.write(json.dumps({"t": self.write_t + 1.5, "kind": "modbus_write",
                                "register": 0, "value": 60.0, "ok": False}) + "\n")
        covers = {"block_flow": {"prevents": ["pivot"], "restores": []},
                  "force_auto": {"prevents": [], "restores": ["mode_hijack"]}}
        end_t = 2000.0 + 60
        _write(self.d / "response.jsonl", [
            {"t": 2000.0, "kind": "response_up", "policy": "rules", "approval": "auto"},
            {"t": self.write_t + 0.7, "kind": "decision", "actions": ["notify"],
             "covers": {"notify": {"prevents": [], "restores": []}}, "rationale": "suspicion"},
            {"t": self.write_t + 0.9, "kind": "decision", "actions": ["block_flow", "force_auto"],
             "covers": covers, "rationale": "mode_hijack confirmed"},
            {"t": self.write_t + 1.0, "kind": "action", "id": "block_flow", "ok": True,
             "issued_t": self.write_t + 0.95, "done_t": self.write_t + 1.0},
            {"t": self.write_t + 1.2, "kind": "action", "id": "force_auto", "ok": True,
             "issued_t": self.write_t + 1.1, "done_t": self.write_t + 1.2},
        ])
        r = compute_metrics(str(self.d))["response"]
        self.assertEqual(r["policy"], "rules")
        self.assertEqual(r["actions"], ["block_flow", "force_auto"])
        self.assertTrue(r["accurate"])
        self.assertEqual(r["over_response"], [])
        self.assertEqual(r["attacker_writes_after_block"], 0)   # the late write failed
        self.assertEqual(r["false_responses"], 0)
        self.assertEqual((r["decisions"], r["explained_decisions"]), (2, 2))
        # first finding of the attack at write+0.6 -> first countermeasure at write+1.0
        self.assertAlmostEqual(r["decision_latency_s"], 0.4, places=3)
        self.assertAlmostEqual(r["hmi_unavailable_s"], end_t - (self.write_t + 1.0), places=3)
        self.assertIn("## Response (policy: rules", format_report(compute_metrics(str(self.d))))

    def test_response_inaccurate_and_false(self):
        _write(self.d / "response.jsonl", [
            {"t": 2000.0, "kind": "response_up", "policy": "solver", "approval": "auto"},
            {"t": 2005.0, "kind": "action", "id": "restore_breaker", "ok": True,
             "issued_t": 2005.0, "done_t": 2005.0},           # before the attack
            {"t": self.write_t + 1.0, "kind": "action", "id": "block_flow", "ok": False,
             "issued_t": self.write_t + 1.0, "done_t": self.write_t + 1.0},
        ])
        r = compute_metrics(str(self.d))["response"]
        self.assertFalse(r["accurate"])                       # force_auto missing, block failed
        self.assertEqual(r["false_responses"], 1)
        self.assertEqual(r["over_response"], ["restore_breaker"])
        self.assertEqual(r["failed_actions"], ["block_flow"])
        self.assertIsNone(r["attacker_writes_after_block"])


class PlannerRun(unittest.TestCase):
    """A tree-guided attack stopped at the pivot (defended): no writes landed."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="cps-plan-"))
        t0 = 1000.0
        _write(self.d / "engine.engine_frames.jsonl", [
            {"timestamp": t0 + i, "step": i, "v_load": 0.99, "v_dg": 1.0, "abnormal": 0,
             "energy_kwh": 0.01 * (i + 1)} for i in range(12)])
        _write(self.d / "sensor.telemetry.jsonl", [{"t": t0, "kind": "sensor_up"}])
        _write(self.d / "ground_truth.jsonl", [
            {"t": t0 + 10, "kind": "attack_start", "mode": "planner:opportunistic"},
            {"t": t0 + 10, "kind": "plan_step", "node": "it_access", "stage": "it_access", "ok": True},
            {"t": t0 + 11, "kind": "rce", "mode": "planner:opportunistic"},
            {"t": t0 + 11, "kind": "plan_step", "node": "it_exec", "stage": "it_exec", "ok": True},
            {"t": t0 + 12, "kind": "plan_step", "node": "pivot", "stage": "pivot", "ok": False},
            {"t": t0 + 12, "kind": "attack_end", "mode": "planner:opportunistic",
             "success": False, "stage_reached": "it_exec", "writes_ok": 0},
        ])

    def test_planner_metrics(self):
        m = compute_metrics(str(self.d))
        self.assertTrue(m["planner"])
        self.assertEqual(m["attacker_profile"], "opportunistic")
        self.assertEqual(m["stage_reached"], "it_exec")
        self.assertFalse(m["attack_succeeded"])
        self.assertTrue(m["prevented"])
        self.assertEqual(len(m["plan_steps"]), 3)
        self.assertIn("tree-guided attacker", format_report(m))

    def test_scripted_run_has_no_planner_fields(self):
        _write(self.d / "ground_truth.jsonl", [
            {"t": 1010.0, "kind": "attack_start", "mode": "setpoint-overvoltage"},
            {"t": 1011.0, "kind": "modbus_write", "register": 0, "value": 200.0, "ok": True},
            {"t": 1012.0, "kind": "attack_end"}])
        m = compute_metrics(str(self.d))
        self.assertFalse(m["planner"])
        self.assertIsNone(m["stage_reached"])


if __name__ == "__main__":
    unittest.main()
