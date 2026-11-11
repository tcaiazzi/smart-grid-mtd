"""Off-wire unit test for the Modbus-DPI sensor (cyberrange/planes/defense/agents/ot_sensor.py).

Crafts real Modbus/TCP ADUs (and full Ethernet/IPv4/TCP frames) by hand and
checks the sensor's pure logic: the PLC's in-range setpoint write raises nothing,
while an out-of-range value or an unauthorized write to a sensitive actuator
becomes a finding. No raw socket, no containers.

Run: `.venv/bin/python -m unittest tests.test_ot_sensor`.
"""

import struct
import sys
import unittest


from tests.helpers import guest_paths  # noqa: E402

sys.path.insert(0, str(guest_paths.DEFENSE))
sys.path.insert(0, str(guest_paths.DEFENSE_AGENTS))

import ot_registers as reg  # noqa: E402
import ot_sensor as s  # noqa: E402
from mtd_telemetry import Telemetry  # noqa: E402

PLC_IP = "10.20.0.10"
ATTACKER_IP = "10.10.0.20"  # app server / pivot host (pre-v2 tests: an unknown client)
HMI_IP = "10.10.0.20"  # v2: the same host is the HMI, a known role
ENGINE_IP = "10.20.0.20"
OTHER_IP = "10.10.0.10"  # the attacker box itself (no role)


def modbus_write_single(address, value, unit=reg.UNIT_ID, txn=1):
    pdu = struct.pack("!BHH", reg.FC_WRITE_SINGLE_REGISTER, address, value)
    length = len(pdu) + 1  # +unit
    return struct.pack("!HHHB", txn, 0, length, unit) + pdu


def modbus_write_multiple(address, values, unit=reg.UNIT_ID, txn=1):
    bc = 2 * len(values)
    pdu = struct.pack("!BHHB", reg.FC_WRITE_MULTIPLE_REGISTERS, address, len(values), bc)
    pdu += b"".join(struct.pack("!H", v) for v in values)
    length = len(pdu) + 1
    return struct.pack("!HHHB", txn, 0, length, unit) + pdu


def modbus_read(fc, address, qty, unit=reg.UNIT_ID, txn=1):
    pdu = struct.pack("!BHH", fc, address, qty)
    return struct.pack("!HHHB", txn, 0, len(pdu) + 1, unit) + pdu


def modbus_read_response(fc, words, unit=reg.UNIT_ID, txn=1):
    pdu = struct.pack("!BB", fc, 2 * len(words)) + b"".join(struct.pack("!H", w) for w in words)
    return struct.pack("!HHHB", txn, 0, len(pdu) + 1, unit) + pdu


def ir_words(v_load, v_dg, abnormal=0):
    w = [0] * reg.SENSOR_COUNT
    w[reg.IR_V_LOAD] = reg.encode(v_load, 1000.0)
    w[reg.IR_V_DG] = reg.encode(v_dg, 1000.0)
    w[reg.IR_ABNORMAL] = abnormal
    return w


def build_frame(src_ip, dst_ip, dport, modbus_adu, sport=50000, flags=0x18):
    tcp = struct.pack("!HHLLBBHHH", sport, dport, 0, 0, (5 << 4), flags, 0, 0, 0)
    ihl_ver = (4 << 4) | 5
    total = 20 + len(tcp) + len(modbus_adu)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_ver,
        0,
        total,
        0,
        0,
        64,
        6,
        0,
        bytes(map(int, src_ip.split("."))),
        bytes(map(int, dst_ip.split("."))),
    )
    eth = b"\x00" * 6 + b"\x11" * 6 + struct.pack("!H", s.ETHERTYPE_IPV4)
    return eth + ip + tcp + modbus_adu


class ParseWrites(unittest.TestCase):
    def test_single(self):
        adu = modbus_write_single(reg.HR_DG_SETPOINT, reg.encode(200.0, 10.0))
        w = s.parse_modbus_writes(adu)
        self.assertEqual(len(w), 1)
        self.assertEqual(w[0]["fc"], reg.FC_WRITE_SINGLE_REGISTER)
        self.assertEqual(w[0]["address"], reg.HR_DG_SETPOINT)
        self.assertEqual(w[0]["values"], [reg.encode(200.0, 10.0)])

    def test_multiple_and_pipelined(self):
        adu = modbus_write_single(reg.HR_SWITCH_CMD, 1) + modbus_write_multiple(
            reg.HR_DG_SETPOINT, [reg.encode(90.0, 10.0)]
        )
        w = s.parse_modbus_writes(adu)
        self.assertEqual(len(w), 2)

    def test_read_is_ignored(self):
        # fc 0x04 read input registers — not a write.
        pdu = struct.pack("!BHH", 0x04, 0, reg.SENSOR_COUNT)
        adu = struct.pack("!HHHB", 1, 0, len(pdu) + 1, reg.UNIT_ID) + pdu
        self.assertEqual(s.parse_modbus_writes(adu), [])


class Classify(unittest.TestCase):
    def test_plc_in_range_setpoint_is_benign(self):
        w = {
            "unit": reg.UNIT_ID,
            "fc": 0x06,
            "address": reg.HR_DG_SETPOINT,
            "values": [reg.encode(20.0, 10.0)],
        }
        self.assertIsNone(s.classify_write(PLC_IP, "10.20.0.20", w, PLC_IP))

    def test_out_of_range_from_plc_still_flagged(self):
        w = {
            "unit": reg.UNIT_ID,
            "fc": 0x06,
            "address": reg.HR_DG_SETPOINT,
            "values": [reg.encode(200.0, 10.0)],
        }
        f = s.classify_write(PLC_IP, "10.20.0.20", w, PLC_IP)
        self.assertIsNotNone(f)
        self.assertIn("out_of_range_command", f["reasons"])

    def test_unauthorized_switch_write(self):
        w = {"unit": reg.UNIT_ID, "fc": 0x06, "address": reg.HR_SWITCH_CMD, "values": [1]}
        f = s.classify_write(ATTACKER_IP, "10.20.0.20", w, PLC_IP)
        self.assertIsNotNone(f)
        self.assertEqual(f["klass"], "unauthorized_write_to_actuator")
        self.assertGreaterEqual(f["confidence"], 0.9)
        self.assertEqual(f["entities"]["src"], ATTACKER_IP)


class FullFramePath(unittest.TestCase):
    def _sensor(self):
        tel = Telemetry()  # in-memory
        sensor = s.OTSensor("eth0", "10.20.0.20", reg.MODBUS_PORT, PLC_IP, tel)
        return sensor, tel

    def test_attacker_frame_raises_finding_and_alert(self):
        sensor, tel = self._sensor()
        adu = modbus_write_single(reg.HR_DG_SETPOINT, reg.encode(200.0, 10.0))
        frame = build_frame(ATTACKER_IP, "10.20.0.20", reg.MODBUS_PORT, adu)
        sensor._handle_frame(frame)
        kinds = [e["kind"] for e in tel.events()]
        self.assertIn("ot_finding", kinds)
        self.assertIn("ot_alert", kinds)

    def test_plc_frame_is_silent(self):
        sensor, tel = self._sensor()
        adu = modbus_write_single(reg.HR_DG_SETPOINT, reg.encode(20.0, 10.0))
        frame = build_frame(PLC_IP, "10.20.0.20", reg.MODBUS_PORT, adu)
        sensor._handle_frame(frame)
        self.assertEqual([e for e in tel.events() if e["kind"] == "ot_finding"], [])

    def test_wrong_port_ignored(self):
        sensor, tel = self._sensor()
        adu = modbus_write_single(reg.HR_SWITCH_CMD, 1)
        frame = build_frame(ATTACKER_IP, "10.20.0.20", 12345, adu)  # not the Modbus port
        sensor._handle_frame(frame)
        self.assertEqual(tel.events(), [])


class PolicyRules(unittest.TestCase):
    POLICY = {PLC_IP: "plc", HMI_IP: "hmi"}

    def _w(self, addr, raw):
        return {"unit": reg.UNIT_ID, "fc": 0x06, "address": addr, "values": [raw]}

    def test_hmi_operator_writes_are_allowed(self):
        for addr, raw in (
            (reg.HR_CTRL_MODE, 1),
            (reg.HR_DG_SETPOINT, reg.encode(30.0, 10.0)),
            (reg.HR_DG_SETPOINT, reg.encode(60.0, 10.0)),
        ):  # in range: legal
            self.assertIsNone(
                s.classify_write(HMI_IP, ENGINE_IP, self._w(addr, raw), PLC_IP, policy=self.POLICY)
            )

    def test_breaker_from_hmi_is_policy_violation(self):
        f = s.classify_write(
            HMI_IP, ENGINE_IP, self._w(reg.HR_SWITCH_CMD, 1), PLC_IP, policy=self.POLICY
        )
        self.assertEqual(f["klass"], "policy_violation")
        self.assertEqual(f["evidence"]["role"], "hmi")

    def test_plc_may_not_take_manual(self):
        f = s.classify_write(
            PLC_IP, ENGINE_IP, self._w(reg.HR_CTRL_MODE, 1), PLC_IP, policy=self.POLICY
        )
        self.assertEqual(f["klass"], "policy_violation")

    def test_unknown_client_read_is_recon(self):
        f = s.classify_read(OTHER_IP, ENGINE_IP, 0x03, reg.UNIT_ID, self.POLICY)
        self.assertEqual(f["klass"], "unauthorized_read")
        self.assertIsNone(s.classify_read(HMI_IP, ENGINE_IP, 0x04, reg.UNIT_ID, self.POLICY))


class WireProcess(unittest.TestCase):
    """Full frames, both directions: the sensor reconstructs the plant state from
    the read responses and applies the process rules to it."""

    def setUp(self):
        self.tel = Telemetry()
        self.sensor = s.OTSensor(
            "eth0",
            ENGINE_IP,
            reg.MODBUS_PORT,
            PLC_IP,
            self.tel,
            hmi_ip=HMI_IP,
            detectors=("rules",),
        )
        self.txn = 0

    def _req(self, t, src, adu, sport):
        self.sensor._handle_frame(
            build_frame(src, ENGINE_IP, reg.MODBUS_PORT, adu, sport=sport), now=t
        )

    def _resp(self, t, dst, adu, dport):
        self.sensor._handle_frame(
            build_frame(ENGINE_IP, dst, dport, adu, sport=reg.MODBUS_PORT), now=t
        )

    def poll(self, t, src, v_load, v_dg, mode, setpoint, sport=40001):
        """One client poll: fc04 + fc03, each answered by the engine."""
        self.txn += 1
        self._req(t, src, modbus_read(0x04, 0, reg.SENSOR_COUNT, txn=self.txn), sport)
        abn = int(not (reg.V_BAND_LOW <= v_dg <= reg.V_BAND_HIGH))
        self._resp(
            t + 0.01,
            src,
            modbus_read_response(0x04, ir_words(v_load, v_dg, abn), txn=self.txn),
            sport,
        )
        self.txn += 1
        hr = [0] * reg.ACTUATOR_COUNT
        hr[reg.HR_DG_SETPOINT] = reg.encode(setpoint, 10.0)
        hr[reg.HR_CTRL_MODE] = mode
        self._req(t + 0.02, src, modbus_read(0x03, 0, reg.ACTUATOR_COUNT, txn=self.txn), sport)
        self._resp(t + 0.03, src, modbus_read_response(0x03, hr, txn=self.txn), sport)

    def write(self, t, src, addr, raw, sport=40002):
        self.txn += 1
        self._req(t, src, modbus_write_single(addr, raw, txn=self.txn), sport)

    def findings(self, klass=None):
        return [
            e
            for e in self.tel.events()
            if e["kind"] == "ot_finding" and (klass is None or e["klass"] == klass)
        ]

    def test_request_response_pairing_decodes_state(self):
        self.poll(1.0, PLC_IP, 0.99, 1.01, 0, 20.0)
        st = s.registers_to_state(0x04, 0, ir_words(0.99, 1.01))
        self.assertAlmostEqual(st["v_dg"], 1.01)
        self.assertEqual(self.sensor._pending, {})  # every request answered
        self.assertEqual(self.findings(), [])

    def test_unanswered_response_is_ignored(self):
        self._resp(1.0, PLC_IP, modbus_read_response(0x04, ir_words(1.2, 1.2, 1), txn=99), 40001)
        self.assertEqual(self.findings(), [])

    def test_legit_operator_manual_window_is_silent(self):
        t = 1.0
        for _ in range(5):
            self.poll(t, PLC_IP, 0.99, 1.01, 0, 20.0)
            t += 1
        self.write(t, HMI_IP, reg.HR_CTRL_MODE, 1, sport=40100)
        self.write(t + 0.01, HMI_IP, reg.HR_DG_SETPOINT, reg.encode(30.0, 10.0), sport=40100)
        for _ in range(5):
            self.poll(t, PLC_IP, 1.0, 1.035, 1, 30.0)
            t += 1
        self.write(t, HMI_IP, reg.HR_CTRL_MODE, 0, sport=40100)
        self.poll(t + 1, PLC_IP, 0.99, 1.01, 0, 30.0)
        self.assertEqual(self.findings(), [])

    def test_manual_hijack_is_caught_by_process_rules(self):
        t = 1.0
        for _ in range(3):
            self.poll(t, PLC_IP, 0.99, 1.01, 0, 20.0)
            t += 1
        # In-range writes from the HMI's IP: no write-time rule can fire.
        self.write(t, HMI_IP, reg.HR_CTRL_MODE, 1, sport=40200)
        self.write(t + 0.01, HMI_IP, reg.HR_DG_SETPOINT, reg.encode(60.0, 10.0), sport=40200)
        self.assertEqual(self.findings(), [])
        t_write = t
        for _ in range(5):
            t += 1
            self.poll(t, PLC_IP, 1.013, 1.068, 1, 60.0)
        unsafe = self.findings("unsafe_command")
        self.assertTrue(unsafe)
        self.assertEqual(unsafe[0]["entities"]["src"], HMI_IP)
        blamed = {f["entities"]["register"] for f in unsafe}
        self.assertEqual(blamed, {reg.HR_CTRL_MODE, reg.HR_DG_SETPOINT})
        self.assertLessEqual(unsafe[0]["evidence"]["lag_s"], s.UNSAFE_WINDOW_S)
        self.assertGreater(unsafe[0]["evidence"]["write_t"], t_write - 0.1)
        self.assertTrue(self.findings("manual_mode_excursion"))
        alerts = [e for e in self.tel.events() if e["kind"] == "ot_alert"]
        self.assertIn("manual_mode_excursion", {a["klass"] for a in alerts})
        # Back in band in AUTO -> the excursion alert clears.
        self.poll(t + 1, PLC_IP, 0.99, 1.01, 0, 20.0)
        cleared = [
            a
            for a in self.tel.events()
            if a["kind"] == "ot_alert"
            and a.get("state") == "cleared"
            and a["klass"] == "manual_mode_excursion"
        ]
        self.assertEqual(len(cleared), 1)

    def test_unsafe_blame_skips_rewrites_and_acquitted_writes(self):
        # Live-run regression: the PLC's identical re-writes and the operator's
        # earlier hand-back to AUTO (followed by in-band observations) must not
        # be blamed; only the hijack writes are.
        t = 1.0
        self.write(t, HMI_IP, reg.HR_CTRL_MODE, 0, sport=40100)  # operator hand-back
        for _ in range(4):
            t += 1
            self.poll(t, PLC_IP, 0.99, 1.01, 0, 17.4)
            self.write(t + 0.05, PLC_IP, reg.HR_DG_SETPOINT, reg.encode(17.4, 10.0))
        t += 0.5
        self.write(t, HMI_IP, reg.HR_CTRL_MODE, 1, sport=40200)
        self.write(t + 0.01, HMI_IP, reg.HR_DG_SETPOINT, reg.encode(60.0, 10.0), sport=40200)
        self.poll(t + 0.2, PLC_IP, 0.99, 1.01, 1, 60.0)  # physics not stepped yet
        self.poll(t + 1.0, PLC_IP, 1.013, 1.068, 1, 60.0)
        unsafe = self.findings("unsafe_command")
        self.assertEqual(
            {(f["entities"]["src"], f["entities"]["register"]) for f in unsafe},
            {(HMI_IP, reg.HR_CTRL_MODE), (HMI_IP, reg.HR_DG_SETPOINT)},
        )
        self.assertTrue(all(f["evidence"]["value"] in (1.0, 60.0) for f in unsafe))

    def test_breaker_write_from_hmi_flagged_on_wire(self):
        self.write(1.0, HMI_IP, reg.HR_SWITCH_CMD, 1)
        self.assertEqual([f["klass"] for f in self.findings()], ["policy_violation"])

    def test_zero_register_write_does_not_stop_the_sensor(self):
        adu = modbus_write_multiple(reg.HR_DG_SETPOINT, [])
        self.assertIsNone(
            s.decode_request(s.parse_modbus_adus(adu)[0]),
            "a write of zero registers was decoded as a write with no values",
        )
        self._req(1.0, OTHER_IP, adu, 40002)  # must not raise
        self.write(2.0, HMI_IP, reg.HR_SWITCH_CMD, 1)
        self.assertIn(
            "policy_violation",
            [f["klass"] for f in self.findings()],
            "the sensor stopped detecting after a malformed write",
        )

    def test_every_register_of_a_multiple_write_is_judged(self):
        """The HMI may write the setpoint (register 0) but not the breaker
        (register 1): a write spanning both must not pass on its start address."""
        self.txn += 1
        adu = modbus_write_multiple(reg.HR_DG_SETPOINT, [reg.encode(30.0, 10.0), 1], txn=self.txn)
        self._req(1.0, HMI_IP, adu, 40002)
        found = self.findings("policy_violation")
        self.assertEqual(
            [f["entities"]["register"] for f in found],
            [reg.HR_SWITCH_CMD],
            "a breaker command hidden behind a legal setpoint write went unnoticed",
        )

    def test_write_alert_clears_after_quiet(self):
        self.write(1.0, OTHER_IP, reg.HR_DG_SETPOINT, reg.encode(200.0, 10.0))
        self.poll(1.0 + s.ALERT_QUIET_S + 1, PLC_IP, 0.99, 1.01, 0, 20.0)
        states = [a["state"] for a in self.tel.events() if a["kind"] == "ot_alert"]
        self.assertEqual(states, ["raised", "cleared"])


class WireModel(unittest.TestCase):
    def test_model_calibrates_then_flags_burst(self):
        tel = Telemetry()
        sensor = s.OTSensor(
            "eth0",
            ENGINE_IP,
            reg.MODBUS_PORT,
            PLC_IP,
            tel,
            hmi_ip=HMI_IP,
            detectors=("model",),
            learn_seconds=20.0,
        )
        txn = 0
        for sec in range(30):
            t = 1000.0 + sec
            txn += 1
            sensor._handle_frame(
                build_frame(
                    PLC_IP,
                    ENGINE_IP,
                    reg.MODBUS_PORT,
                    modbus_read(0x04, 0, reg.SENSOR_COUNT, txn=txn),
                ),
                now=t,
            )
            sensor._handle_frame(
                build_frame(
                    PLC_IP,
                    ENGINE_IP,
                    reg.MODBUS_PORT,
                    modbus_write_single(reg.HR_DG_SETPOINT, reg.encode(20.0, 10.0), txn=txn),
                ),
                now=t + 0.1,
            )
        self.assertTrue(any(e["kind"] == "model_fitted" for e in tel.events()))
        self.assertFalse([e for e in tel.events() if e["kind"] == "ot_finding"])
        # A burst of new sessions writing big setpoint jumps.
        t = 1030.2
        for i in range(5):
            sensor._handle_frame(
                build_frame(
                    HMI_IP, ENGINE_IP, reg.MODBUS_PORT, b"", sport=41000 + i, flags=s.TCP_SYN
                ),
                now=t + 0.01 * i,
            )
            sensor._handle_frame(
                build_frame(
                    HMI_IP,
                    ENGINE_IP,
                    reg.MODBUS_PORT,
                    modbus_write_single(reg.HR_DG_SETPOINT, reg.encode(60.0, 10.0)),
                    sport=41000 + i,
                ),
                now=t + 0.01 * i + 0.005,
            )
        # Flagged at write time (open window scored early), not a window later.
        early = [e for e in tel.events() if e["kind"] == "ot_finding"]
        self.assertTrue(early)
        self.assertTrue(early[0]["evidence"]["partial"])
        self.assertEqual(len(early), 1)  # once per window
        sensor._tick(1033.0)
        model_f = [e for e in tel.events() if e["kind"] == "ot_finding"]
        self.assertTrue(model_f)
        self.assertEqual(model_f[0]["detector"], "model")
        self.assertEqual(model_f[0]["klass"], "behavioral_anomaly")


if __name__ == "__main__":
    unittest.main()
