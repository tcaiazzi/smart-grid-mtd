"""The plant as a description (cyberrange/planes/defense/ot_registers.py): what
every party reads the same way — the engine, the PLC, the OT sensor — and what
each one does with a plant of several feeders. The physics of such a plant is in
test_grid_sim.py; the knowledge graph's view of it in tests/nodes/test_soar_kg.py.

Run: `.venv/bin/python -m pytest tests/planes/test_plant.py`.
"""

import unittest

from tests.helpers import guest_paths

guest_paths.add(
    guest_paths.DEFENSE,
    guest_paths.DEFENSE_AGENTS,
    guest_paths.TRAFFIC_AGENTS,
    guest_paths.ATTACK_AGENTS,
)

import ot_registers as reg  # noqa: E402  (flat guest imports, need the path set above)
import ot_sensor as s  # noqa: E402
import ot_write  # noqa: E402
import plc_controller as plc  # noqa: E402

PLC_A, PLC_B, ENGINE = "10.20.0.10", "10.20.0.11", "10.20.0.20"


def two_feeders():
    p = reg.plant()
    p["feeders"].append(dict(p["feeders"][0], unit=2, dg_kw=30.0, dg_rating_kw=80.0))
    return p


class Description(unittest.TestCase):
    def test_the_default_plant_is_the_constants(self):
        p = reg.plant()
        self.assertEqual(reg.units(p), [reg.UNIT_ID])
        self.assertEqual(reg.feeder(p)["dg_kw"], reg.DG_NOMINAL_KW)
        self.assertEqual(
            reg.envelope(p)[reg.HR_DG_SETPOINT], reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT]
        )
        self.assertEqual(tuple(p["limits"]["v_band"]), (reg.V_BAND_LOW, reg.V_BAND_HIGH))

    def test_it_travels_on_a_command_line_unchanged(self):
        p = two_feeders()
        arg = reg.plant_b64(p)
        self.assertTrue(arg.isascii() and " " not in arg and not arg.startswith("-"))
        self.assertEqual(reg.plant(arg), p)

    def test_a_malformed_plant_is_refused_by_everyone_alike(self):
        p = two_feeders()
        p["feeders"][1]["unit"] = 1
        with self.assertRaisesRegex(ValueError, "distinct"):
            reg.plant(p)
        p = two_feeders()
        p["feeders"][1]["dg_kw"] = 90.0
        with self.assertRaisesRegex(ValueError, "rating"):
            reg.plant(p)
        p = two_feeders()
        del p["feeders"][1]["load_kw"]
        with self.assertRaisesRegex(ValueError, "load_kw"):
            reg.plant(p)

    def test_each_feeder_has_its_envelope(self):
        p = two_feeders()
        self.assertEqual(reg.envelope(p, 2)[reg.HR_DG_SETPOINT][3], 80.0)
        raw = reg.encode(70.0, reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1])
        self.assertIsNotNone(reg.actuator_out_of_range(reg.HR_DG_SETPOINT, raw, reg.envelope(p, 1)))
        self.assertIsNone(reg.actuator_out_of_range(reg.HR_DG_SETPOINT, raw, reg.envelope(p, 2)))


class Controller(unittest.TestCase):
    def test_each_plc_regulates_to_its_own_feeder(self):
        t = plc.Tuning(two_feeders(), 2)
        self.assertEqual((t.nominal, t.hi), (30.0, 80.0))
        in_band = {"v_load": 1.0, "v_dg": 1.0}
        self.assertEqual(plc.control(in_band, 40.0, t), 38.0, "it relaxes toward its own nominal")
        self.assertEqual(plc.control(in_band, 40.0), 38.0)
        self.assertEqual(plc.control(in_band, 21.0), 20.0, "the default plant's PLC changed")


class Writer(unittest.TestCase):
    """ot_write, as the responses use it: the writes, and the feeder they go to."""

    def test_a_feeder_is_addressed_by_its_unit(self):
        argv = ["ot_write.py", ENGINE, "5020", "--unit=2", "1=0"]
        self.assertEqual(ot_write.parse_args(argv), (ENGINE, 5020, [(1, 0)], 2))

    def test_without_one_the_default_plant_s_unit(self):
        argv = ["ot_write.py", ENGINE, "5020", "2=0", "0=200"]
        self.assertEqual(ot_write.parse_args(argv), (ENGINE, 5020, [(2, 0), (0, 200)], reg.UNIT_ID))
        legacy = ["ot_write.py", ENGINE, "5020", "1", "0", "3"]
        self.assertEqual(ot_write.parse_args(legacy), (ENGINE, 5020, [(1, 0)], 3))


class Telemetry:
    def __init__(self):
        self.rows = []

    def emit(self, kind, **fields):
        self.rows.append({"kind": kind, **fields})


class Sensor(unittest.TestCase):
    def setUp(self):
        self.tel = Telemetry()
        self.sensor = s.OTSensor(
            "eth0",
            ENGINE,
            reg.MODBUS_PORT,
            PLC_A,
            self.tel,
            detectors=("rules",),
            plant=two_feeders(),
            clients=[(PLC_B, "plc", 2)],
        )

    def write(self, src, unit, value):
        raw = reg.encode(value, reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1])
        w = {"unit": unit, "fc": reg.FC_WRITE_SINGLE_REGISTER, "address": reg.HR_DG_SETPOINT,
             "values": [raw]}  # fmt: skip
        return s.classify_write(
            src,
            ENGINE,
            w,
            PLC_A,
            policy=self.sensor.policy,
            actuators=self.sensor.envelope(unit),
            unit_of=self.sensor.unit_of,
        )

    def test_a_plc_commands_its_own_feeder(self):
        self.assertIsNone(self.write(PLC_A, 1, 25.0))
        self.assertIsNone(self.write(PLC_B, 2, 35.0))

    def test_a_plc_commanding_another_feeder_violates_the_policy(self):
        f = self.write(PLC_A, 2, 25.0)
        self.assertEqual(f["klass"], "policy_violation")
        self.assertEqual(f["evidence"]["own_unit"], 1)

    def test_the_envelope_is_the_feeders(self):
        self.assertIsNone(self.write(PLC_B, 2, 70.0), "inside feeder 2's 80 kW rating")
        f = self.write(PLC_A, 1, 70.0)
        self.assertIn("out_of_range_command", f["reasons"])

    def test_each_feeder_keeps_its_own_state(self):
        a, b = self.sensor.rules_for(1), self.sensor.rules_for(2)
        self.assertIsNot(a, b)
        b.on_state(1.0, {"ctrl_mode": reg.CTRL_MANUAL, "v_load": 1.0, "v_dg": 1.0})
        self.assertEqual(b.ctrl_mode, reg.CTRL_MANUAL)
        self.assertEqual(a.ctrl_mode, reg.CTRL_AUTO, "a feeder taken to MANUAL moved the other")
        self.assertIs(self.sensor.rules, a, "the model's feeder is the plant's first")

    def test_clients_are_bound_from_the_command_line(self):
        got = s.bound_clients(f"{PLC_A},{PLC_B}@2", "plc", two_feeders())
        self.assertEqual(got, [(PLC_A, "plc", 1), (PLC_B, "plc", 2)])


if __name__ == "__main__":
    unittest.main()
