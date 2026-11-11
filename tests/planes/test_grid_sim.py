"""Regression test for the cyber-physical scenario's physical engine
(cyberrange/planes/traffic/agents/grid_sim.py, the pandapower digital twin) and its
plant contract (cyberrange/planes/defense/ot_registers.py).

Checks the three states the scenario relies on — normal operation in band, a DG
setpoint forced out of range driving an overvoltage, and an opened feeder
breaker de-energizing the load — plus seed reproducibility and the register
encode/decode round-trip. Pure power flow, no Modbus and no containers.

Guest modules are imported from their source dirs (as test_guest_imports stages
them). Run: `.venv/bin/python -m unittest tests.test_grid_sim`.
"""

import sys
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from tests.helpers import guest_paths  # noqa: E402
sys.path.insert(0, str(guest_paths.DEFENSE))                 # flat ot_registers
sys.path.insert(0, str(guest_paths.TRAFFIC_AGENTS))  # flat grid_sim

import ot_registers as reg      # noqa: E402
import grid_sim                 # noqa: E402


def _settle(actuators, n=5, seed=7):
    st = grid_sim.build_grid(seed=seed)
    out = None
    for _ in range(n):
        out = grid_sim.step_grid(st, actuators)
    return st, out


class NormalOperation(unittest.TestCase):
    def test_in_band(self):
        _, r = _settle({"dg_setpoint": grid_sim.DG_NOMINAL_KW, "switch_cmd": 0})
        self.assertTrue(r["converged"])
        self.assertEqual(r["abnormal"], 0)
        for v in (r["v_load"], r["v_dg"]):
            self.assertGreaterEqual(v, reg.V_BAND_LOW)
            self.assertLessEqual(v, reg.V_BAND_HIGH)


class SetpointManipulation(unittest.TestCase):
    def test_out_of_range_setpoint_drives_overvoltage(self):
        _, r = _settle({"dg_setpoint": 200.0, "switch_cmd": 0})
        self.assertEqual(r["abnormal"], 1)
        self.assertGreater(r["v_dg"], reg.V_BAND_HIGH)

    def test_full_rated_in_range_setpoint_is_unsafe(self):
        # The stealthy attack's premise: 60 kW is inside the DG's legitimate
        # command envelope (no out-of-range rule fires) yet overvolts the DG bus.
        raw = reg.encode(60.0, reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1])
        self.assertIsNone(reg.actuator_out_of_range(reg.HR_DG_SETPOINT, raw))
        _, r = _settle({"dg_setpoint": 60.0, "switch_cmd": 0})
        self.assertEqual(r["abnormal"], 1)
        self.assertGreater(r["v_dg"], reg.V_BAND_HIGH)

    def test_operator_dispatch_range_is_safe(self):
        # The HMI's legitimate dispatches (15-35 kW) and the PLC's nominal keep
        # the feeder in band, over a load random walk.
        for sp in (15.0, 20.0, 35.0):
            st = grid_sim.build_grid(seed=3)
            for _ in range(60):
                r = grid_sim.step_grid(st, {"dg_setpoint": sp, "switch_cmd": 0})
                self.assertEqual(r["abnormal"], 0, f"{sp} kW went abnormal: {r}")

    def test_envelope_flagged_by_register_map(self):
        # The plant contract itself must call 200 kW out of range and 30 kW ok.
        self.assertIsNotNone(reg.actuator_out_of_range(reg.HR_DG_SETPOINT, reg.encode(200.0, 10.0)))
        self.assertIsNone(reg.actuator_out_of_range(reg.HR_DG_SETPOINT, reg.encode(30.0, 10.0)))


class BreakerManipulation(unittest.TestCase):
    def test_open_feeder_deenergizes_load(self):
        _, r = _settle({"dg_setpoint": grid_sim.DG_NOMINAL_KW, "switch_cmd": 1})
        self.assertEqual(r["abnormal"], 1)
        self.assertLess(r["v_load"], reg.V_BAND_LOW)


class Reproducibility(unittest.TestCase):
    def test_same_seed_same_trajectory(self):
        st1 = grid_sim.build_grid(seed=11); st2 = grid_sim.build_grid(seed=11)
        seq1 = [grid_sim.step_grid(st1, {"dg_setpoint": 20.0, "switch_cmd": 0})["v_load"] for _ in range(6)]
        seq2 = [grid_sim.step_grid(st2, {"dg_setpoint": 20.0, "switch_cmd": 0})["v_load"] for _ in range(6)]
        self.assertEqual(seq1, seq2)
        # a different seed should (almost surely) diverge somewhere
        st3 = grid_sim.build_grid(seed=12)
        seq3 = [grid_sim.step_grid(st3, {"dg_setpoint": 20.0, "switch_cmd": 0})["v_load"] for _ in range(6)]
        self.assertNotEqual(seq1, seq3)


class EnergyAccounting(unittest.TestCase):
    def test_energy_accumulates_under_import(self):
        st, r = _settle({"dg_setpoint": grid_sim.DG_NOMINAL_KW, "switch_cmd": 0}, n=6)
        self.assertGreater(r["energy_kwh"], 0.0)  # importing from the grid


class RegisterRoundTrip(unittest.TestCase):
    def test_encode_decode(self):
        for val, scale in [(1.023, 1000.0), (41.6, 10.0), (0.0, 1.0), (60.0, 10.0)]:
            self.assertAlmostEqual(reg.decode(reg.encode(val, scale), scale), val, places=3)

    def test_clamp(self):
        self.assertEqual(reg.encode(1e9, 10.0), reg.REG_WORD_MAX)
        self.assertEqual(reg.encode(-5.0, 10.0), 0)


if __name__ == "__main__":
    unittest.main()
