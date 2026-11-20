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

from tests.planes import test_ot_sensor as wire  # noqa: E402  (its frame builders)

PLC_A, PLC_B, ENGINE = "10.20.0.10", "10.20.0.11", "10.20.0.20"
HMI_A, HMI_B, STRANGER = "10.10.0.20", "10.10.0.21", "10.20.0.99"


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

    def test_clients_are_bound_from_the_command_line(self):
        got = s.bound_clients(f"{PLC_A},{PLC_B}@2", "plc", two_feeders())
        self.assertEqual(got, [(PLC_A, "plc", 1), (PLC_B, "plc", 2)])


class FeederModels(unittest.TestCase):
    """The behavioural model, one per feeder: each learns its own feeder, so a
    quiet attack on any of them is the model's to see."""

    T0, LEARN_S = 1000.0, 20.0

    def setUp(self):
        self.tel = Telemetry()
        self.sensor = s.OTSensor(
            "eth0",
            ENGINE,
            reg.MODBUS_PORT,
            PLC_A,
            self.tel,
            hmi_ip=HMI_A,
            detectors=("model",),
            learn_seconds=self.LEARN_S,
            plant=two_feeders(),
            clients=[(PLC_B, "plc", 2), (HMI_B, "hmi", 2)],
        )
        self.txn = 0
        for sec in range(30):
            self.second(self.T0 + sec)

    def frame(self, t, src, adu, **kw):
        self.sensor._handle_frame(wire.build_frame(src, ENGINE, reg.MODBUS_PORT, adu, **kw), now=t)

    def second(self, t):
        """Both controllers poll and regulate their own feeder."""
        for plc_ip, unit, kw in ((PLC_A, 1, 20.0), (PLC_B, 2, 30.0)):
            self.txn += 1
            read = wire.modbus_read(0x04, 0, reg.SENSOR_COUNT, unit=unit, txn=self.txn)
            self.frame(t, plc_ip, read)
            hold = wire.modbus_write_single(
                reg.HR_DG_SETPOINT, reg.encode(kw, 10.0), unit=unit, txn=self.txn
            )
            self.frame(t + 0.1, plc_ip, hold)

    def hijack(self, t, src, unit, kw):
        """A new session taking MANUAL, then an in-range setpoint."""
        self.frame(t, src, b"", sport=41000, flags=s.TCP_SYN)
        mode = wire.modbus_write_single(reg.HR_CTRL_MODE, reg.CTRL_MANUAL, unit=unit)
        self.frame(t + 0.01, src, mode, sport=41000)
        setpoint = wire.modbus_write_single(reg.HR_DG_SETPOINT, reg.encode(kw, 10.0), unit=unit)
        self.frame(t + 0.02, src, setpoint, sport=41000)

    def rows(self, kind):
        return [r for r in self.tel.rows if r["kind"] == kind]

    def test_every_feeder_calibrates_its_own_model(self):
        fitted = {r["unit"]: r for r in self.rows("model_fitted")}
        self.assertEqual(sorted(fitted), [1, 2], "a feeder was left without a model")
        self.assertEqual(self.rows("ot_finding"), [], "normal traffic of two feeders alarmed")

    def test_a_quiet_attack_on_the_second_feeder_is_seen_there(self):
        # 80 kW is feeder 2's full rating: in range, from its own HMI.
        self.hijack(self.T0 + 30.3, HMI_B, 2, 80.0)
        self.sensor._tick(self.T0 + 33.0)
        units = {f["entities"]["unit"] for f in self.rows("ot_finding")}
        self.assertEqual(units, {2}, "the hijack of feeder 2 must be feeder 2's finding only")
        raised = [a["entities"]["unit"] for a in self.rows("ot_alert") if a["state"] == "raised"]
        self.assertEqual(raised, [2])

    def test_each_feeder_raises_its_own_alert(self):
        self.hijack(self.T0 + 30.3, HMI_A, 1, 60.0)
        self.hijack(self.T0 + 30.4, HMI_B, 2, 80.0)
        raised = {a["entities"]["unit"] for a in self.rows("ot_alert") if a["state"] == "raised"}
        self.assertEqual(raised, {1, 2}, "one alert per feeder, not one for the plant")

    def test_a_stranger_s_session_counts_for_every_feeder(self):
        for i in range(5):
            self.frame(self.T0 + 30.3 + 0.01 * i, STRANGER, b"", sport=42000 + i, flags=s.TCP_SYN)
        self.sensor._tick(self.T0 + 33.0)
        units = {f["entities"]["unit"] for f in self.rows("ot_finding")}
        self.assertEqual(units, {1, 2}, "a client bound to no feeder is nobody's normal")


if __name__ == "__main__":
    unittest.main()
