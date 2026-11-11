"""Unit test for the sensor's learned detector (cyberrange/planes/defense/agents/ot_model.py).

Feeds the WindowFeaturizer a synthetic but protocol-faithful normal phase — the
PLC polling and regulating every second, the HMI polling every 2 s and doing a
legitimate MANUAL dispatch (15-35 kW for 5 s) every ~12 s — calibrates the
RobustAnomalyModel on it, then checks:
  - fresh normal traffic (incl. operator dispatches) stays under the threshold;
  - a manual-hijack (new pivot session from the HMI's IP, MANUAL + a 60 kW
    in-range setpoint) is flagged at write time, before any voltage moves;
  - a hijack left in place keeps scoring anomalous (manual_run_s grows).
Deterministic (seeded), off-wire.

Run: `.venv/bin/python -m unittest tests.test_ot_model`.
"""

import random
import sys
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from tests.helpers import guest_paths  # noqa: E402
sys.path.insert(0, str(guest_paths.DEFENSE))
sys.path.insert(0, str(guest_paths.DEFENSE_AGENTS))

import ot_registers as reg                                       # noqa: E402
from ot_model import FEATURES, RobustAnomalyModel, WindowFeaturizer   # noqa: E402

PLC, HMI = "10.20.0.10", "10.10.0.20"


class Plant:
    """Drives a featurizer with what the sensor would decode off the wire."""

    def __init__(self, seed=1):
        self.rng = random.Random(seed)
        self.fz = WindowFeaturizer(PLC, setpoint_register=reg.HR_DG_SETPOINT,
                                   mode_register=reg.HR_CTRL_MODE,
                                   manual_value=reg.CTRL_MANUAL)
        self.windows = []
        self.setpoint = 20.0
        self.mode = reg.CTRL_AUTO
        self.v_extra = 0.0
        self._next_op = 12.0
        self._release = None
        self._take = lambda t, closed: self.windows.extend(closed)
        self._take(0.0, self.fz.observe_syn(0.05, PLC))
        self._take(0.0, self.fz.observe_syn(0.06, HMI))

    def _voltages(self):
        v = 1.0 + 0.0005 * (self.setpoint - 20.0) + self.rng.gauss(0, 0.002) + self.v_extra
        return {"v_load": v - 0.008, "v_dg": v}

    def second(self, t, operator=True):
        fz, take = self.fz, self._take
        # PLC: read IR + HR, regulate (AUTO only).
        take(t, fz.observe_read(t + 0.10, PLC, 0x04))
        take(t, fz.observe_state(t + 0.11, self._voltages()))
        take(t, fz.observe_read(t + 0.12, PLC, 0x03))
        take(t, fz.observe_state(t + 0.13, {"ctrl_mode": self.mode, "dg_setpoint": self.setpoint}))
        if self.mode == reg.CTRL_AUTO:
            if self.setpoint > 20.0:
                self.setpoint = max(20.0, self.setpoint - 2.0)
            elif self.setpoint < 20.0:
                self.setpoint = min(20.0, self.setpoint + 2.0)
            take(t, fz.observe_write(t + 0.15, PLC, reg.HR_DG_SETPOINT, self.setpoint))
        # HMI: poll every 2 s.
        if int(t) % 2 == 0:
            take(t, fz.observe_read(t + 0.50, HMI, 0x04))
            take(t, fz.observe_state(t + 0.51, self._voltages()))
            take(t, fz.observe_read(t + 0.52, HMI, 0x03))
            take(t, fz.observe_state(t + 0.53, {"ctrl_mode": self.mode,
                                                "dg_setpoint": self.setpoint}))
        # HMI operator: legitimate MANUAL dispatch.
        if operator and self._release is None and t >= self._next_op:
            self.mode = reg.CTRL_MANUAL
            self.setpoint = round(self.rng.uniform(15.0, 35.0), 1)
            take(t, fz.observe_write(t + 0.60, HMI, reg.HR_CTRL_MODE, 1.0))
            take(t, fz.observe_write(t + 0.61, HMI, reg.HR_DG_SETPOINT, self.setpoint))
            self._release = t + 5.0
        elif self._release is not None and t >= self._release:
            self.mode = reg.CTRL_AUTO
            take(t, fz.observe_write(t + 0.60, HMI, reg.HR_CTRL_MODE, 0.0))
            self._release = None
            self._next_op = t + 12.0 + self.rng.uniform(-3, 3)

    def hijack(self, t):
        """The pivot: a NEW TCP session from the HMI's IP, MANUAL, then 60 kW."""
        fz, take = self.fz, self._take
        take(t, fz.observe_syn(t + 0.70, HMI))
        take(t, fz.observe_write(t + 0.71, HMI, reg.HR_CTRL_MODE, 1.0))
        take(t, fz.observe_write(t + 0.72, HMI, reg.HR_DG_SETPOINT, 60.0))
        self.mode, self.setpoint = reg.CTRL_MANUAL, 60.0
        self._release = None
        self._next_op = 1e9   # a careful operator does not fight a foreign MANUAL

    def run(self, t0, t1, **kw):
        for t in range(t0, t1):
            self.second(float(t), **kw)
        self._take(t1, self.fz.flush(float(t1)))


class Model(unittest.TestCase):
    def setUp(self):
        self.p = Plant(seed=1)
        self.p.run(0, 45)                       # calibration (normal + operator)
        self.model = RobustAnomalyModel()
        for _ws, vec in self.p.windows:
            self.model.add_calibration(vec)
        self.model.fit()
        self.p.windows.clear()

    def test_features_shape(self):
        self.assertEqual(len(self.model.center), len(FEATURES))
        self.assertGreaterEqual(self.model.threshold, self.model.k)

    def test_needs_calibration(self):
        m = RobustAnomalyModel(min_calibration=10)
        with self.assertRaises(ValueError):
            m.fit()

    def test_normal_with_operator_dispatches_is_quiet(self):
        self.p.run(45, 105)                    # a minute more, ~4 dispatches
        flagged = [(ws, self.model.explain(self.model.score(v)[1]))
                   for ws, v in self.p.windows if self.model.is_anomalous(v)[0]]
        self.assertEqual(flagged, [], f"false alarms on normal traffic: {flagged}")

    def test_hijack_flagged_at_write_time(self):
        self.p.run(45, 50, operator=False)
        self.p.windows.clear()
        self.p.hijack(50.0)
        self.p.run(50, 52, operator=False)     # voltages not yet moved (v_extra = 0)
        ws, vec = self.p.windows[0]
        self.assertEqual(ws, 50.0)
        anomalous, score, z = self.model.is_anomalous(vec)
        self.assertTrue(anomalous, f"score {score} <= {self.model.threshold}")
        top = [x["feature"] for x in self.model.explain(z)]
        self.assertIn("max_dsetpoint", top)

    def test_persistent_hijack_keeps_scoring(self):
        self.p.hijack(45.0)
        self.p.v_extra = 0.06                   # the overvoltage it causes
        self.p.run(45, 75, operator=False)
        late = [v for ws, v in self.p.windows if ws >= 65.0]
        self.assertTrue(late)
        self.assertTrue(all(self.model.is_anomalous(v)[0] for v in late))


if __name__ == "__main__":
    unittest.main()
