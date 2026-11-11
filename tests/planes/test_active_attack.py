"""Integration test for the active attack chain, end to end on the host (no
Kathará): the deliberately-vulnerable app (cyberrange/planes/attack/agents/vuln_app.py), the
pivot Modbus writer (ot_write.py), and the exploit driver's RCE primitive
(exploit_client.rce) against the real physical engine (modbus_engine.py).

It proves: a command injection on the app server yields RCE, the pivot reaches
the OT engine's Modbus port, and the unauthorized write actually moves the
physics (the engine reports an abnormal state). This is the stimulus the DPI
sensor detects in the lab.

Run: `.venv/bin/python -m unittest tests.test_active_attack`.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from tests.helpers import guest_paths       # noqa: E402

AGENTS_T = guest_paths.TRAFFIC_AGENTS
AGENTS_A = guest_paths.ATTACK_AGENTS
sys.path.insert(0, str(guest_paths.DEFENSE))
sys.path.insert(0, str(AGENTS_A))

import ot_registers as reg          # noqa: E402
from cyberrange.planes.attack.active_attack import parse_exploit_events   # noqa: E402

try:
    from pymodbus.client import ModbusTcpClient
    import exploit_client            # noqa: E402  (imports ot_registers)
    HAVE = True
except Exception:
    HAVE = False


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _wait_port(port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@unittest.skipUnless(HAVE, "pymodbus / exploit_client unavailable")
class ActiveAttackChain(unittest.TestCase):
    def setUp(self):
        # Staging dir so the injected `python3 ot_write.py ...` finds ot_write +
        # ot_registers (mirrors them both landing flat at / in the container).
        self.stage = Path(tempfile.mkdtemp(prefix="cps-attack-"))
        for name in ("ot_write.py",):
            shutil.copy(AGENTS_A / name, self.stage / name)
        shutil.copy(guest_paths.DEFENSE / "ot_registers.py", self.stage / "ot_registers.py")
        shutil.copy(AGENTS_A / "vuln_app.py", self.stage / "vuln_app.py")

        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join([str(self.stage), env.get("PYTHONPATH", "")])

        self.app_port = _free_port()
        self.eng_port = _free_port()
        self.app = subprocess.Popen(
            [sys.executable, "vuln_app.py", "--port", str(self.app_port)],
            cwd=str(self.stage), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        eng_env = dict(os.environ)
        eng_env["PYTHONPATH"] = os.pathsep.join([str(AGENTS_T), str(guest_paths.DEFENSE)])
        self.engine = subprocess.Popen(
            [sys.executable, "-m", "modbus_engine", "--port", str(self.eng_port),
             "--interval", "0.3", "--duration", "25", "--seed", "7"],
            cwd=str(AGENTS_T), env=eng_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertTrue(_wait_port(self.app_port), "vuln_app did not start")
        self.assertTrue(_wait_port(self.eng_port), "engine did not start")
        time.sleep(0.6)

    def tearDown(self):
        for p in (self.app, self.engine):
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(self.stage, ignore_errors=True)

    def test_rce_then_pivot_write_moves_physics(self):
        url = f"http://127.0.0.1:{self.app_port}"
        # 1) ingress: RCE via command injection
        out = exploit_client.rce(url, "echo PWNED-$((6*7))")
        self.assertIn("PWNED-42", out)

        # engine normal before the attack
        c = ModbusTcpClient("127.0.0.1", port=self.eng_port); self.assertTrue(c.connect())
        try:
            rr = c.read_input_registers(0, reg.SENSOR_COUNT, slave=reg.UNIT_ID)
            self.assertEqual(rr.registers[reg.IR_ABNORMAL], 0)

            # 2+3) pivot + manipulate: app server writes the DG setpoint out of range
            raw = reg.encode(200.0, reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1])
            poke = f"python3 ot_write.py 127.0.0.1 {self.eng_port} {reg.HR_DG_SETPOINT} {raw} {reg.UNIT_ID}"
            abnormal = False
            for _ in range(10):
                resp = exploit_client.rce(url, poke)
                self.assertIn("ot_write ok", resp)
                time.sleep(0.3)
                rr = c.read_input_registers(0, reg.SENSOR_COUNT, slave=reg.UNIT_ID)
                if rr.registers[reg.IR_ABNORMAL] == 1:
                    abnormal = True
                    break
            self.assertTrue(abnormal, "pivot Modbus write did not move the physics")
        finally:
            c.close()


@unittest.skipUnless(HAVE, "pymodbus / exploit_client unavailable")
class AttackVsPLC(unittest.TestCase):
    """The same chain with the PLC in the loop (the point-2 property):
    a loud out-of-range write is rejected and the plant recovers to nominal,
    while a manual-hijack (in-range writes) makes the impact persist."""

    STEP = 0.3

    def setUp(self):
        self.stage = Path(tempfile.mkdtemp(prefix="cps-plc-"))
        for name in ("ot_write.py", "vuln_app.py", "exploit_client.py"):
            shutil.copy(AGENTS_A / name, self.stage / name)
        shutil.copy(guest_paths.DEFENSE / "ot_registers.py", self.stage / "ot_registers.py")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(self.stage)
        self.env = env
        eng_env = dict(os.environ)
        eng_env["PYTHONPATH"] = os.pathsep.join([str(AGENTS_T), str(guest_paths.DEFENSE)])
        self.app_port, self.eng_port = _free_port(), _free_port()
        self.procs = [subprocess.Popen(
            [sys.executable, "vuln_app.py", "--port", str(self.app_port)], cwd=str(self.stage),
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
        self.procs.append(subprocess.Popen(
            [sys.executable, "-m", "modbus_engine", "--port", str(self.eng_port),
             "--interval", str(self.STEP), "--duration", "40", "--seed", "7"],
            cwd=str(AGENTS_T), env=eng_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        self.assertTrue(_wait_port(self.app_port), "vuln_app did not start")
        self.assertTrue(_wait_port(self.eng_port), "engine did not start")
        self.procs.append(subprocess.Popen(
            [sys.executable, "-m", "plc_controller", "--engine-host", "127.0.0.1",
             "--port", str(self.eng_port), "--interval", str(self.STEP), "--duration", "40"],
            cwd=str(AGENTS_T), env=eng_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        self.c = ModbusTcpClient("127.0.0.1", port=self.eng_port)
        self.assertTrue(self.c.connect())
        time.sleep(1.5)   # PLC settles at nominal

    def tearDown(self):
        self.c.close()
        for p in self.procs:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        shutil.rmtree(self.stage, ignore_errors=True)

    def state(self):
        ir = self.c.read_input_registers(0, reg.SENSOR_COUNT, slave=reg.UNIT_ID).registers
        hr = self.c.read_holding_registers(0, reg.ACTUATOR_COUNT, slave=reg.UNIT_ID).registers
        return {"abnormal": ir[reg.IR_ABNORMAL],
                "mode": hr[reg.HR_CTRL_MODE],
                "setpoint": reg.decode(hr[reg.HR_DG_SETPOINT], 10.0)}

    def attack(self, mode, repeat=None):
        cmd = [sys.executable, "exploit_client.py", "--target-url",
               f"http://127.0.0.1:{self.app_port}", "--engine-ip", "127.0.0.1",
               "--engine-port", str(self.eng_port), "--attack", mode, "--interval", "0.2",
               "--ot-write-path", str(self.stage / "ot_write.py")]
        if repeat is not None:
            cmd += ["--repeat", str(repeat)]
        out = subprocess.run(cmd, cwd=str(self.stage), env=self.env, capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        return parse_exploit_events(out.stdout)

    def test_baseline_is_nominal(self):
        st = self.state()
        self.assertEqual((st["abnormal"], st["mode"], st["setpoint"]), (0, 0, 20.0))

    def test_loud_write_is_rejected_and_plant_recovers(self):
        events = self.attack("setpoint-overvoltage", repeat=3)
        self.assertEqual(len([e for e in events if e["phase"] == "modbus_write"]), 3)
        time.sleep(8 * self.STEP)
        st = self.state()
        self.assertEqual(st["abnormal"], 0, st)
        self.assertEqual(st["mode"], reg.CTRL_AUTO)
        self.assertEqual(st["setpoint"], 20.0)   # back to nominal, not curtailed

    def test_manual_hijack_persists_with_plc_running(self):
        events = self.attack("manual-hijack")
        writes = [e for e in events if e["phase"] == "modbus_write"]
        self.assertEqual([(w["register"], w["value"]) for w in writes],
                         [(reg.HR_CTRL_MODE, 1.0), (reg.HR_DG_SETPOINT, 60.0)])
        self.assertTrue(all(w["ok"] for w in writes))
        self.assertTrue(any(e["phase"] == "rce" for e in events))
        time.sleep(3 * self.STEP)
        # The attacker is gone; the PLC is polling; the impact stays.
        for _ in range(10):
            st = self.state()
            self.assertEqual(st["abnormal"], 1, st)
            self.assertEqual(st["mode"], reg.CTRL_MANUAL)
            self.assertEqual(st["setpoint"], 60.0)
            time.sleep(self.STEP)


if __name__ == "__main__":
    unittest.main()
