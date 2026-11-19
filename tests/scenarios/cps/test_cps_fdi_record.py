"""An attack that writes nothing still acts on the plant: the falsified readings
of meas-fdi. The driver must put them in the ground truth, and the metrics must
count them as the act the detection is timed against and the response answers.

Run: `.venv/bin/python -m pytest tests/scenarios/cps/test_cps_fdi_record.py`.
"""

import json
import unittest

from cyberrange.planes.attack import active_attack
from cyberrange.scenarios.cps import metrics


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, kind, **fields):
        self.events.append({"kind": kind, **fields})


class FakeManager:
    """A lab manager whose attacker prints ``lines`` and exits 0."""

    def __init__(self, lines):
        self.out = "\n".join(json.dumps(line) for line in lines).encode()

    def exec_obj(self, _machine, _cmd, stream=False):
        return self.out, b"", 0


FDI_OUTPUT = [
    {"t": 10.0, "phase": "ingress"},
    {"t": 10.1, "phase": "rce", "whoami": "root"},
    {"t": 10.2, "phase": "ot_foothold", "ok": True, "detail": "ews"},
    {"t": 12.0, "phase": "ot_aitm", "ok": True},
    {"t": 56.0, "phase": "fdi", "ok": True, "t_start": 14.0, "t_end": 54.0, "readings": 40},
    {"t": 56.0, "phase": "done"},
]


class DriverRecord(unittest.TestCase):
    def drive(self, lines):
        gt = Recorder()
        rc = active_attack.drive_attack(
            FakeManager(lines), None, gt, "http://hmi", "10.20.0.20", 5020, attack_mode="meas-fdi"
        )
        self.assertEqual(rc, 0)
        return gt.events

    def test_the_falsification_is_recorded_when_it_began(self):
        events = self.drive(FDI_OUTPUT)
        kinds = [e["kind"] for e in events]
        self.assertEqual(
            kinds, ["attack_start", "rce", "ot_foothold", "ot_aitm", "fdi", "attack_end"]
        )
        fdi = events[kinds.index("fdi")]
        self.assertEqual(
            (fdi["t"], fdi["t_end"], fdi["readings"]),
            (14.0, 54.0, 40),
            "timed at the step's end, detection latency would be off by the whole attack",
        )
        self.assertNotIn("modbus_write", kinds, "the attacker wrote nothing: none to invent")

    def test_a_lost_output_invents_no_write(self):
        self.assertEqual([e["kind"] for e in self.drive([])], ["attack_start", "attack_end"])


class Scoring(unittest.TestCase):
    def test_falsified_readings_are_an_act_on_the_plant(self):
        gt = [{"kind": "fdi", "t": 14.0, "ok": True}, {"kind": "rce", "t": 10.1}]
        self.assertEqual([e["kind"] for e in metrics._plant_acts(gt)], ["fdi"])
        self.assertEqual(metrics._plant_acts([{"kind": "fdi", "ok": False}], ok_only=True), [])

    def test_the_answer_to_falsified_readings_is_to_isolate_and_repair(self):
        fdi = {"kind": "fdi", "t": 14.0, "ok": True}
        self.assertEqual(metrics.expected_response([fdi]), {"isolate_ews", "repair_arp"})
        self.assertEqual(
            metrics.expected_response([{"kind": "fdi", "ok": False}]),
            set(),
            "a falsification that never took place needs no response",
        )
        hijack = {"kind": "modbus_write", "register_name": "ctrl_mode", "ok": True}
        self.assertEqual(
            metrics.expected_response([fdi, hijack]),
            {"isolate_ews", "repair_arp", "block_flow", "force_auto"},
        )


if __name__ == "__main__":
    unittest.main()
