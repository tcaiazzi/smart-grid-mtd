"""IT-side sensor (defense_plane.agents.it_sensor): injection in the web log,
unexpected web-server children, unexpected Modbus clients — learned-normal first,
then flagged. Off-wire, synthetic observations, no /proc.

Run: `.venv/bin/python -m unittest tests.test_it_sensor`.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "defense_plane"))
sys.path.insert(0, str(REPO_ROOT / "defense_plane" / "agents"))

import it_sensor  # noqa: E402
from mtd_telemetry import Telemetry  # noqa: E402

ENGINE = "10.20.0.20"


class Helpers(unittest.TestCase):
    def test_is_injection(self):
        for ok in ("10.20.0.20", "localhost", "host-1.lab", "127.0.0.1"):
            self.assertFalse(it_sensor.is_injection(ok), ok)
        for bad in ("127.0.0.1; id", "a|b", "$(whoami)", "a`b`", "x;ls"):
            self.assertTrue(it_sensor.is_injection(bad), bad)

    def test_descendants(self):
        procs = [{"pid": 10, "ppid": 1}, {"pid": 11, "ppid": 10}, {"pid": 12, "ppid": 11},
                 {"pid": 20, "ppid": 1}]
        self.assertEqual(it_sensor.descendants(procs, {10}), {11, 12})

    def test_hex_endpoint(self):
        self.assertEqual(it_sensor._hex_endpoint("10.20.0.20", 5020), "1400140A:139C")


class Sensor(unittest.TestCase):
    def make(self, learn=10.0, t0=1000.0):
        tel = Telemetry()
        s = it_sensor.ITSensor(ENGINE, 5020, learn_seconds=learn, telemetry=tel, t0=t0)
        return s, tel

    def findings(self, tel):
        return [e for e in tel.events() if e["kind"] == "ot_finding"]

    def test_web_injection_after_learn(self):
        s, tel = self.make()
        # during learning: even an injection is not flagged (and legit never is)
        s.observe_web([{"src": "10.10.0.10", "target": "127.0.0.1; id", "path": "/diag"}], now=1001)
        self.assertEqual(self.findings(tel), [])
        # after learning
        s.observe_web([{"src": "10.10.0.10", "target": "127.0.0.1; id"},
                       {"src": "10.10.0.20", "target": "10.20.0.20"}], now=1020)
        f = self.findings(tel)
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["klass"], f[0]["maps_to"], f[0]["detector"]),
                         ("web_injection_pattern", "it_access", "it"))
        self.assertEqual(f[0]["entities"]["src"], "10.10.0.10")

    def test_web_dedup(self):
        s, tel = self.make()
        for _ in range(3):
            s.observe_web([{"src": "10.10.0.10", "target": "x; id"}], now=1020)
        self.assertEqual(len(self.findings(tel)), 1)

    def test_child_process_learns_ping_flags_shell(self):
        s, tel = self.make()
        app = {"pid": 100, "ppid": 1, "comm": "python3", "cmdline": "python3 /vuln_app.py"}
        # learning window: a legitimate diagnostic spawns sh->ping
        s.observe_procs([app, {"pid": 101, "ppid": 100, "comm": "sh", "cmdline": "sh -c ping"},
                         {"pid": 102, "ppid": 101, "comm": "ping", "cmdline": "ping -c 1 x"}], now=1001)
        self.assertEqual(self.findings(tel), [])
        # after: an injected command runs a different child
        s.observe_procs([app, {"pid": 110, "ppid": 100, "comm": "sh", "cmdline": "sh -c id"},
                         {"pid": 111, "ppid": 110, "comm": "id", "cmdline": "id"}], now=1020)
        f = self.findings(tel)
        self.assertEqual([x["maps_to"] for x in f], ["it_exec"])
        self.assertEqual(f[0]["evidence"]["comm"], "id")

    def test_unexpected_modbus_client(self):
        s, tel = self.make()
        # legit client's connection learned
        s.observe_conns([{"laddr_port": 40000, "raddr_ip": ENGINE, "raddr_port": 5020,
                          "state": "01"}], now=1001)
        self.assertEqual(self.findings(tel), [])
        # the pivot opens a new local port to the engine
        s.observe_conns([{"laddr_port": 40000, "raddr_ip": ENGINE, "raddr_port": 5020, "state": "01"},
                         {"laddr_port": 55123, "raddr_ip": ENGINE, "raddr_port": 5020, "state": "02"}],
                        now=1020)
        f = self.findings(tel)
        self.assertEqual([x["maps_to"] for x in f], ["pivot"])
        self.assertEqual(f[0]["evidence"]["laddr_port"], 55123)

    def test_connections_to_other_ports_ignored(self):
        s, tel = self.make(learn=0.0)
        s.observe_conns([{"laddr_port": 50000, "raddr_ip": ENGINE, "raddr_port": 80, "state": "01"},
                         {"laddr_port": 50001, "raddr_ip": "10.20.0.10", "raddr_port": 5020,
                          "state": "01"}], now=1020)
        self.assertEqual(self.findings(tel), [])


if __name__ == "__main__":
    unittest.main()
