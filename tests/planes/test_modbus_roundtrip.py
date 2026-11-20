"""Integration test for the Modbus/TCP layer of the cyber-physical scenario:
the physical engine (modbus_engine.py) serving the pandapower twin, and a
Modbus master reading its sensors and writing its actuators.

Spawns the real engine as a subprocess on an ephemeral port (exactly as the lab
runs it) with the flat guest modules on PYTHONPATH, then uses a pymodbus client
to: (1) read the sensor input registers and confirm a normal, in-band state, and
(2) write an out-of-range DG setpoint to the actuator holding register and
confirm the physics goes abnormal on the next steps — proving an unauthorized
Modbus write reaches the twin.

Run: `.venv/bin/python -m unittest tests.test_modbus_roundtrip`.
"""

import os
import socket
import subprocess
import sys
import time
import unittest


from tests.helpers import guest_paths  # noqa: E402

sys.path.insert(0, str(guest_paths.DEFENSE))
sys.path.insert(0, str(guest_paths.TRAFFIC_AGENTS))

import ot_registers as reg  # noqa: E402

try:
    from pymodbus.client import ModbusTcpClient

    HAVE_PYMODBUS = True
except Exception:
    HAVE_PYMODBUS = False

AGENTS = guest_paths.TRAFFIC_AGENTS


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@unittest.skipUnless(HAVE_PYMODBUS, "pymodbus not installed")
class ModbusEngineRoundTrip(unittest.TestCase):
    def setUp(self):
        self.port = _free_port()
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(AGENTS), str(guest_paths.DEFENSE), env.get("PYTHONPATH", "")]
        )
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "modbus_engine",
                "--port",
                str(self.port),
                "--interval",
                "0.3",
                "--duration",
                "20",
                "--seed",
                "7",
            ],
            cwd=str(AGENTS),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.assertTrue(_wait_port(self.port), "engine did not open its Modbus port")
        time.sleep(0.6)  # let the first physics steps run

    def tearDown(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def _read(self, client):
        rr = client.read_input_registers(0, reg.SENSOR_COUNT, slave=reg.UNIT_ID)
        self.assertFalse(rr.isError(), f"sensor read failed: {rr}")
        regs = rr.registers
        return {
            "v_load": reg.decode(regs[reg.IR_V_LOAD], 1000.0),
            "v_dg": reg.decode(regs[reg.IR_V_DG], 1000.0),
            "abnormal": regs[reg.IR_ABNORMAL],
        }

    def test_read_normal_then_write_drives_abnormal(self):
        client = ModbusTcpClient("127.0.0.1", port=self.port)
        self.assertTrue(client.connect())
        try:
            s = self._read(client)
            self.assertEqual(s["abnormal"], 0, f"expected normal start, got {s}")
            self.assertGreaterEqual(s["v_load"], reg.V_BAND_LOW)

            # Unauthorized out-of-range write to the DG setpoint actuator.
            word = reg.encode(200.0, reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1])
            wr = client.write_register(reg.HR_DG_SETPOINT, word, slave=reg.UNIT_ID)
            self.assertFalse(wr.isError(), f"actuator write failed: {wr}")

            abnormal = False
            for _ in range(10):
                time.sleep(0.3)
                if self._read(client)["abnormal"] == 1:
                    abnormal = True
                    break
            self.assertTrue(abnormal, "out-of-range Modbus write did not move the physics")
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
