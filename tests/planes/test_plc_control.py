"""Unit test for the PLC's control decision (cyberrange/planes/traffic/agents/
plc_controller.py: control() / decide()). Pure logic, no Modbus.

Pins the two behaviours the scenario relies on:
  - AUTO: the PLC rejects an out-of-envelope setpoint in force (falls back to its
    own command), regulates on the WORST bus voltage, and relaxes back to the
    nominal setpoint once in band (no permanent curtailment after a disturbance);
  - MANUAL: the PLC hands off (never writes) — the operator authority an attacker
    abuses to make an impact persist.

Run: `.venv/bin/python -m unittest tests.test_plc_control`.
"""

import sys
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from tests.helpers import guest_paths  # noqa: E402
sys.path.insert(0, str(guest_paths.DEFENSE))
sys.path.insert(0, str(guest_paths.TRAFFIC_AGENTS))

import ot_registers as reg   # noqa: E402

try:
    import plc_controller as plc   # imports pymodbus
    HAVE = True
except Exception:
    HAVE = False

IN_BAND = {"v_load": 1.00, "v_dg": 1.01}
OVER_DG = {"v_load": 1.01, "v_dg": 1.07}     # only the DG bus overvolts
UNDER = {"v_load": 0.96, "v_dg": 0.965}
AUTO = reg.CTRL_AUTO
MANUAL = reg.CTRL_MANUAL


@unittest.skipUnless(HAVE, "pymodbus not installed")
class Decide(unittest.TestCase):
    def test_manual_hands_off(self):
        write, sp = plc.decide(OVER_DG, {"ctrl_mode": MANUAL, "dg_setpoint": 60.0}, 20.0)
        self.assertFalse(write)
        self.assertEqual(sp, 20.0)

    def test_out_of_envelope_in_force_is_rejected(self):
        write, sp = plc.decide(IN_BAND, {"ctrl_mode": AUTO, "dg_setpoint": 200.0}, 20.0)
        self.assertTrue(write)
        self.assertEqual(sp, 20.0)    # own command, not 200 nor the clamp 60

    def test_regulates_on_dg_bus_overvoltage(self):
        write, sp = plc.decide(OVER_DG, {"ctrl_mode": AUTO, "dg_setpoint": 60.0}, 20.0)
        self.assertTrue(write)
        self.assertEqual(sp, 60.0 - plc.SETPOINT_STEP_KW)

    def test_raises_on_undervoltage(self):
        _w, sp = plc.decide(UNDER, {"ctrl_mode": AUTO, "dg_setpoint": 20.0}, 20.0)
        self.assertEqual(sp, 20.0 + plc.SETPOINT_STEP_KW)

    def test_relaxes_back_to_nominal(self):
        sp = 14.0
        for _ in range(10):
            _w, sp = plc.decide(IN_BAND, {"ctrl_mode": AUTO, "dg_setpoint": sp}, sp)
        self.assertEqual(sp, reg.DG_NOMINAL_KW)
        sp = 30.0   # an operator dispatch handed back to AUTO
        for _ in range(10):
            _w, sp = plc.decide(IN_BAND, {"ctrl_mode": AUTO, "dg_setpoint": sp}, sp)
        self.assertEqual(sp, reg.DG_NOMINAL_KW)

    def test_no_upward_relax_without_headroom(self):
        near_edge = {"v_load": 1.0, "v_dg": reg.V_REG_HIGH - plc.RELAX_MARGIN_PU / 2}
        _w, sp = plc.decide(near_edge, {"ctrl_mode": AUTO, "dg_setpoint": 18.0}, 18.0)
        self.assertEqual(sp, 18.0)


if __name__ == "__main__":
    unittest.main()
