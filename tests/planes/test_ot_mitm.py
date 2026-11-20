"""The man-in-the-middle's frame work (cyberrange/planes/attack/agents/ot_mitm.py):
ARP frames, the in-place rewrite of a Modbus reading and its TCP checksum, and
what each mode gives the PLC. Pure functions, no socket and no lab — the position
on a real link is proven by the scenario's live runs.

Run: `.venv/bin/python -m pytest tests/planes/test_ot_mitm.py`.
"""

import os
import socket
import struct
import tempfile
import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.ATTACK_AGENTS, guest_paths.DEFENSE)

import ot_mitm as m  # noqa: E402  (flat guest imports, need the path set above)
import ot_registers as reg  # noqa: E402

PLC, ENGINE = "10.20.0.10", "10.20.0.20"
MAC_A, MAC_B = bytes.fromhex("aa0000000001"), bytes.fromhex("bb0000000002")


def reading(words, txn=7):
    body = struct.pack(f"!{len(words)}H", *words)
    pdu = bytes([reg.FC_READ_INPUT_REGISTERS, len(body)]) + body
    return struct.pack("!HHHB", txn, 0, len(pdu) + 1, reg.UNIT_ID) + pdu


def tcp_frame(src, dst, sport, dport, payload):
    tcp = struct.pack("!HHLLBBHHH", sport, dport, 100, 200, 5 << 4, 0x18, 8192, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        0,
        0,
        64,
        6,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return MAC_B + MAC_A + struct.pack("!H", m.ETH_P_IP) + ip + tcp + payload


def words(v_load=1.0, v_dg=1.02, abnormal=0):
    w = [0] * reg.SENSOR_COUNT
    w[reg.IR_V_LOAD] = reg.encode(v_load, 1000.0)
    w[reg.IR_V_DG] = reg.encode(v_dg, 1000.0)
    w[reg.IR_LINE_LOAD] = 400
    w[reg.IR_ABNORMAL] = abnormal
    return w


class Frames(unittest.TestCase):
    def test_arp_reply_says_who_is_where(self):
        frame = m.arp_frame(m.ARP_REPLY, MAC_A, ENGINE, MAC_B, PLC)
        self.assertEqual(frame[:6], MAC_B, "the claim must reach the victim it is meant for")
        self.assertEqual(m.parse_arp(frame), (m.ARP_REPLY, MAC_A, ENGINE))
        self.assertIsNone(m.parse_arp(tcp_frame(PLC, ENGINE, 40000, 5020, b"")))

    def test_rewrite_keeps_the_length_and_the_checksum_valid(self):
        frame = tcp_frame(ENGINE, PLC, reg.MODBUS_PORT, 40000, reading(words()))
        seg = m.parse_tcp(frame)
        payload = frame[seg["payload"] : seg["end"]]
        forged = m.with_payload(frame, seg, m.with_words(payload, words(0.96, 0.96)))
        self.assertEqual(len(forged), len(frame), "a longer segment breaks the TCP sequence")
        self.assertEqual(forged[: seg["payload"] - 4], frame[: seg["payload"] - 4])
        segment = forged[seg["tcp"] : seg["end"]]
        pseudo = forged[26:34] + struct.pack("!BBH", 0, 6, len(segment))
        self.assertEqual(
            m.checksum(pseudo + segment), 0, "the PLC's kernel would drop the forged reading"
        )
        self.assertEqual(
            m.read_response(forged[seg["payload"] : seg["end"]]), (7, words(0.96, 0.96))
        )

    def test_a_rewrite_of_another_length_is_refused(self):
        frame = tcp_frame(ENGINE, PLC, reg.MODBUS_PORT, 40000, reading(words()))
        with self.assertRaises(ValueError):
            m.with_payload(frame, m.parse_tcp(frame), b"short")

    def test_request_names_what_was_asked(self):
        pdu = struct.pack("!BHH", reg.FC_READ_INPUT_REGISTERS, 0, reg.SENSOR_COUNT)
        adu = struct.pack("!HHHB", 9, 0, len(pdu) + 1, reg.UNIT_ID) + pdu
        self.assertEqual(m.read_request(adu), (9, 0, reg.SENSOR_COUNT))
        write = struct.pack("!HHHB", 9, 0, 6, reg.UNIT_ID) + struct.pack("!BHH", 6, 0, 200)
        self.assertIsNone(m.read_request(write), "a write must go through untouched")
        self.assertIsNone(m.read_response(write))


class Modes(unittest.TestCase):
    def test_forge_reports_the_chosen_voltage_and_hides_the_alarm(self):
        true = words(1.01, 1.06, abnormal=1)
        sent = m.Rewriter("forge", report_v=0.96).rewrite(0, true)
        got = m.named(0, sent)
        self.assertEqual((got["v_load"], got["v_dg"], got["abnormal"]), (0.96, 0.96, 0.0))
        self.assertEqual(sent[reg.IR_LINE_LOAD], true[reg.IR_LINE_LOAD], "only voltages change")
        self.assertLess(0.96, reg.V_REG_LOW, "the PLC must read a voltage it will raise")
        self.assertGreater(0.96, reg.V_BAND_LOW, "and one that is no alarm in itself")

    def test_replay_records_first_then_serves_the_recording(self):
        r = m.Rewriter("replay", window=2)
        first, second, later = words(1.00), words(1.01), words(1.07, abnormal=1)
        self.assertEqual(r.rewrite(0, first), first)
        self.assertEqual(r.rewrite(0, second), second)
        self.assertEqual([r.rewrite(0, later) for _ in range(3)], [first, second, first])

    def test_relay_changes_nothing(self):
        true = words(1.07, abnormal=1)
        self.assertIs(m.Rewriter("relay").rewrite(0, true), true)

    def test_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            m.Rewriter("drop")


class Interface(unittest.TestCase):
    """The tool finds its interface on the plant's link from the host's routing
    table: the platform does not tell it, and on another lab it is another NIC."""

    def routes(self, *rows):
        def word(dotted):
            return f"{struct.unpack('=I', socket.inet_aton(dotted))[0]:08X}"

        lines = ["Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT"]
        for iface, dest, gw, mask in rows:
            lines.append(f"{iface}\t{word(dest)}\t{word(gw)}\t0001\t0\t0\t0\t{word(mask)}\t0\t0\t0")
        f = tempfile.NamedTemporaryFile("w", delete=False, suffix=".route")
        f.write("\n".join(lines) + "\n")
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_the_nic_on_the_engines_link(self):
        table = self.routes(
            ("eth0", "0.0.0.0", "10.10.0.1", "0.0.0.0"),  # the default route, via the boundary
            ("eth0", "10.10.0.0", "0.0.0.0", "255.255.255.0"),
            ("eth2", "10.20.0.0", "0.0.0.0", "255.255.255.0"),
        )
        self.assertEqual(m.iface_towards(ENGINE, table), "eth2")

    def test_no_link_of_its_own_to_the_engine(self):
        table = self.routes(("eth0", "0.0.0.0", "10.10.0.1", "0.0.0.0"))
        with self.assertRaises(RuntimeError):
            m.iface_towards(ENGINE, table)


if __name__ == "__main__":
    unittest.main()
