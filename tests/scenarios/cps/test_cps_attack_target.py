"""Where an attack is aimed, in a CPS lab with several ways in and several
feeders: the scenario's ``--attack-via`` / ``--attack-unit``, the drivers they
configure, the HMIs that are made real ways in, and the scoring of the feeder
that was attacked. No Docker: the lab is a description, the drivers are built
and inspected, the metrics read artifacts written here.

Run: `.venv/bin/python -m pytest tests/scenarios/cps/test_cps_attack_target.py`.
"""

import json
import os
import tempfile
import unittest

from cyberrange.core.cli import default_args
from cyberrange.planes.attack import active_attack
from cyberrange.planes.attack import components as attack
from cyberrange.planes.defense import ot_registers as reg
from cyberrange.scenarios.cps import lab as L
from cyberrange.scenarios.cps import metrics
from cyberrange.scenarios.cps import scenario as cps_scenario

HMI_URL, HMIB_URL = "http://10.10.0.20:8080", "http://10.10.0.21:8080"


def two_ways():
    """The default lab with a second HMI serving the application, for feeder 2."""
    d = L.default_spec()
    hosts = list(d.hosts)
    at = [h.name for h in hosts].index("hmi") + 1
    web = L.Service("diag-http", "tcp", L.APP_PORT, "http")
    hosts.insert(at, L.Host("hmib", "hmi", [L.Nic(L.IT, 21), L.Nic(L.MGMT, 31)], [web], unit=2))
    return L.LabSpec(
        name="cps",
        zones=d.zones,
        hosts=tuple(hosts),
        boundary=d.boundary,
        flows=(*d.flows, L.Flow("hmib", "engine", "modbus")),
    )


def two_feeders():
    p = reg.plant()
    p["feeders"].append(dict(p["feeders"][0], unit=2, dg_kw=30.0, dg_rating_kw=80.0))
    return p


class TwoSubstations(cps_scenario.CpsScenario):
    def lab_spec(self, args):
        return two_ways()

    def plant_spec(self, args):
        return two_feeders()


def args_for(scenario, **overrides):
    return default_args(scenario, attack=True, **overrides)


class WaysIn(unittest.TestCase):
    def test_every_hmi_serving_the_application_is_a_way_in(self):
        self.assertEqual(cps_scenario.plant_of(two_ways()).ways, {"hmi": HMI_URL, "hmib": HMIB_URL})
        self.assertEqual(cps_scenario.plant_of(L.default_spec()).ways, {"hmi": HMI_URL})

    def test_an_attack_aimed_at_nothing_is_refused(self):
        s = TwoSubstations()
        s.validate(args_for(s, attack_via="hmib", attack_unit=2))
        with self.assertRaisesRegex(SystemExit, "ways in are hmi, hmib"):
            s.validate(args_for(s, attack_via="plc"))
        with self.assertRaisesRegex(SystemExit, r"units are \[1, 2\]"):
            s.validate(args_for(s, attack_unit=3))

    def test_the_workstation_s_credential_is_on_every_way_in(self):
        ran = []
        ctx = type("Ctx", (), {"run": lambda self, node, cmd, wait=False: ran.append((node, cmd))})
        ews = attack.EwsMaintenance(
            "ews",
            8081,
            [("hmi", "10.10.0.20", "http://10.10.0.30:8081"), ("hmib", "10.10.0.21", "http://e")],
            token="T",
        )
        self.assertIn("--allow 10.10.0.20 --allow 10.10.0.21", ews.command)
        try:
            ews.start(ctx())
        except Exception:
            pass  # the fake context starts nothing: only the credential files matter here
        wrote = {node: cmd for node, cmd in ran if ews.CONF in cmd}
        self.assertEqual(sorted(wrote), ["hmi", "hmib"], "an HMI holds no way to the workstation")
        self.assertIn("url=http://e", wrote["hmib"])


class Drivers(unittest.TestCase):
    def setUp(self):
        self.s = TwoSubstations()

    def test_the_scripted_chain_goes_where_it_is_told(self):
        d = self.s.attacker(args_for(self.s, attack_via="hmib", attack_unit=2))
        self.assertEqual((d.target_url, d.via, d.unit), (HMIB_URL, "hmib", 2))
        self.assertEqual(reg.plant(d.plant_b64), two_feeders())

    def test_untold_it_takes_the_first_way_and_the_first_feeder(self):
        d = self.s.attacker(args_for(self.s))
        self.assertEqual((d.target_url, d.via, d.unit), (HMI_URL, "hmi", 1))

    def test_the_planner_is_given_every_way_and_left_free(self):
        d = self.s.attacker(args_for(self.s, attack_driver="planner"))
        self.assertEqual(d.ways, {"hmi": HMI_URL, "hmib": HMIB_URL})
        self.assertEqual((d.via, d.unit), (None, None), "an attacker told nothing chooses itself")
        d = self.s.attacker(args_for(self.s, attack_driver="planner", attack_unit=2))
        self.assertEqual(d.unit, 2)

    def test_the_command_names_the_feeder_and_its_plant(self):
        ran, rows = [], []

        class Manager:
            def exec_obj(self, machine, cmd, stream=False):
                ran.append(cmd)
                line = {"t": 5.0, "phase": "modbus_write", "unit": 2, "register": 0, "ok": True}
                return json.dumps(line).encode(), b"", 0

        gt = type("GT", (), {"record": lambda self, kind, **f: rows.append({"kind": kind, **f})})
        active_attack.drive_attack(
            Manager(),
            "attacker",
            gt(),
            HMIB_URL,
            "10.20.0.20",
            5020,
            attack_mode="manual-hijack",
            unit=2,
            plant=two_feeders(),
            via="hmib",
        )
        self.assertIn("--unit-id 2 ", ran[0])
        self.assertIn(f"--plant-b64 {reg.plant_b64(two_feeders())} ", ran[0])
        start = rows[0]
        self.assertEqual((start["via"], start["unit"]), ("hmib", 2))
        self.assertEqual(
            start["writes"][-1]["value"], 80.0, "the hijack's setpoint is feeder 2's rating"
        )
        write = next(r for r in rows if r["kind"] == "modbus_write")
        self.assertEqual(write["unit"], 2, "the ground truth does not say which feeder was hit")


class ExploitValues(unittest.TestCase):
    """What an attack writes is the attacked feeder's: full rating, out of range."""

    @classmethod
    def setUpClass(cls):
        from tests.helpers import guest_paths

        guest_paths.add(guest_paths.DEFENSE, guest_paths.ATTACK_AGENTS)
        import exploit_client

        cls.exploit = exploit_client

    def setpoints(self, mode, feeder, repeat=None):
        return [
            v
            for writes, _hold in self.exploit.schedule(mode, repeat, feeder)
            for r, v, _raw in writes
            if r == reg.HR_DG_SETPOINT
        ]

    def test_values_follow_the_feeder(self):
        second = reg.feeder(two_feeders(), 2)
        self.assertEqual(self.setpoints("manual-hijack", second), [80.0])
        ramp = self.setpoints("slow-ramp", second, 5)
        self.assertEqual(ramp, [40.0, 50.0, 60.0, 70.0, 80.0], "from its nominal to its rating")
        lo, hi = reg.envelope(two_feeders(), 2)[reg.HR_DG_SETPOINT][2:4]
        for mode in ("manual-hijack", "slow-ramp", "setpoint-oscillation"):
            for v in self.setpoints(mode, second):
                self.assertTrue(lo <= v <= hi, f"{mode} writes {v}: no longer a quiet attack")
        self.assertGreater(self.setpoints("setpoint-overvoltage", second)[0], hi)

    def test_the_host_s_hint_agrees_with_the_guest(self):
        for unit in (1, 2):
            f = reg.feeder(two_feeders(), unit)
            for mode, targets in active_attack.attack_targets(f).items():
                hinted = {t["value"] for t in targets if t["register"] == reg.HR_DG_SETPOINT}
                self.assertLessEqual(
                    hinted,
                    set(self.setpoints(mode, f)),
                    f"{mode} on unit {unit}: the ground truth's hint names a value never written",
                )


class Scoring(unittest.TestCase):
    """The metrics of a run whose attack hit the second feeder."""

    def write(self, name, rows):
        with open(os.path.join(self.out, name), "w") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)

    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="cps-target-")
        frames = []
        for i in range(20):
            manual = int(i >= 10)
            frames.append(
                {
                    "timestamp": 100.0 + i,
                    "v_load": 1.0,
                    "v_dg": 1.0,
                    "abnormal": 0,
                    "actuators": {"ctrl_mode": 0},
                    "units": {
                        "1": {"v_load": 1.0, "v_dg": 1.0, "actuators": {"ctrl_mode": 0}},
                        "2": {"v_load": 1.0, "v_dg": 1.0, "actuators": {"ctrl_mode": manual}},
                    },
                }
            )
        self.write("engine.engine_frames.jsonl", frames)
        self.write(
            "ground_truth.jsonl",
            [
                {"t": 110.0, "kind": "attack_start", "mode": "manual-hijack", "unit": 2},
                {"t": 110.1, "kind": "modbus_write", "unit": 2, "register": 2, "ok": True},
                {"t": 111.0, "kind": "attack_end"},
            ],
        )

    def finding(self, detector, unit, t=110.5):
        return {"t": t, "kind": "ot_finding", "detector": detector, "klass": "x",
                "entities": {"unit": unit}}  # fmt: skip

    def test_manual_time_is_the_attacked_feeder_s(self):
        self.write("sensor.telemetry.jsonl", [])
        m = metrics.compute_metrics(self.out)
        self.assertEqual(m["attack_unit"], 2)
        self.assertGreater(m["manual_mode_s"], 0, "feeder 2 in MANUAL went unseen: only feeder 1")

    def test_a_finding_on_another_feeder_is_not_the_attack_seen(self):
        self.write(
            "sensor.telemetry.jsonl",
            [
                {"t": 105.0, "kind": "model_fitted", "unit": 1, "threshold": 4.0},
                {"t": 105.0, "kind": "model_fitted", "unit": 2, "threshold": 4.2},
                self.finding("model", 2),
                self.finding("rules", 1),
            ],
        )
        m = metrics.compute_metrics(self.out)
        self.assertEqual(m["model_thresholds"], {"1": 4.0, "2": 4.2})
        self.assertTrue(m["detectors"]["model"]["on_attacked_feeder"])
        self.assertTrue(m["detectors"]["rules"]["detected"])
        self.assertFalse(m["detectors"]["rules"]["on_attacked_feeder"])
        self.assertIn("on the attacked feeder", metrics.format_report(m))


class Ledger(unittest.TestCase):
    """What reaches the dashboard: every feeder's state, and where the run aimed."""

    def mirrored(self, frame):
        from cyberrange.planes.monitor.components import PlantMirror

        events = []
        ctx = type(
            "Ctx",
            (),
            {
                "exec_text": lambda self, node, cmd: json.dumps(frame) + "\n",
                "emit": lambda self, kind, **f: events.append({"kind": kind, **f}),
            },
        )
        PlantMirror("engine").poll(ctx())
        return events[0]

    def feeder(self, v_dg, mode, kw):
        return {
            "v_load": 1.0,
            "v_dg": v_dg,
            "abnormal": int(v_dg > 1.05),
            "actuators": {"dg_setpoint": kw, "ctrl_mode": mode, "switch_cmd": 0},
        }

    def test_every_feeder_s_state_is_mirrored(self):
        first, second = self.feeder(1.01, 0, 20.0), self.feeder(1.08, 1, 80.0)
        ev = self.mirrored(
            {"timestamp": 5.0, "step": 3, **first, "units": {"1": first, "2": second}}
        )
        self.assertEqual((ev["v_dg"], ev["ctrl_mode"]), (1.01, 0), "the top level is feeder 1")
        self.assertEqual(sorted(ev["units"]), ["1", "2"])
        self.assertEqual(
            ev["units"]["2"],
            dict(v_load=1.0, v_dg=1.08, abnormal=1, dg_setpoint=80.0, ctrl_mode=1, switch_cmd=0),
            "the attacked feeder's state never reaches the dashboard",
        )

    def test_a_plant_of_one_feeder_mirrors_as_before(self):
        ev = self.mirrored({"timestamp": 5.0, "step": 3, **self.feeder(1.01, 0, 20.0)})
        self.assertNotIn("units", ev)
        self.assertEqual((ev["v_dg"], ev["dg_setpoint"], ev["frame_t"]), (1.01, 20.0, 5.0))

    def test_the_run_says_its_feeders_and_its_target(self):
        s = TwoSubstations()
        info = s.run_info(args_for(s, attack_unit=2, attack_via="hmib"))
        self.assertEqual(
            (info["units"], info["attack_unit"], info["attack_via"]), ([1, 2], 2, "hmib")
        )
        info = s.run_info(args_for(s))
        self.assertEqual((info["units"], info["attack_unit"]), ([1, 2], None))


if __name__ == "__main__":
    unittest.main()
