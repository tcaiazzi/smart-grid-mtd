"""Test monitor.cps_metrics against synthetic run artifacts: a normal phase with
no findings, then an attack that drives abnormal frames and a DPI finding. Checks
detection latency, zero false alarms, physical deviation and energy accounting.

Run: `.venv/bin/python -m unittest tests.test_cps_metrics`.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from monitor.cps_metrics import compute_metrics, format_report  # noqa: E402


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
            {"t": self.write_t, "kind": "modbus_write", "register": 2, "value": 1.0},
            {"t": self.write_t, "kind": "modbus_write", "register": 0, "value": 60.0},
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


if __name__ == "__main__":
    unittest.main()
