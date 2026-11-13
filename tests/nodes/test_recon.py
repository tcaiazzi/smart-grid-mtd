"""The recon-driven attacker's guest logic (nodes/redteam): reconnaissance that
drives nmap and reads the OS, and the belief tree it builds from the findings —
all with fakes, no nmap, no lab.

Run: `.venv/bin/python -m pytest tests/nodes/test_recon.py`.
"""

import json
import tempfile
import unittest

from tests.helpers import guest_paths

# The recon agents are node software imported flat, as on the attacker; DEFENSE
# supplies ot_registers, ATTACK_AGENTS supplies the exploit chain red_recon_agent
# reuses for its RCE tunnel.
guest_paths.add(guest_paths.REDTEAM, guest_paths.ATTACK_AGENTS, guest_paths.DEFENSE)

import belief_tree  # noqa: E402
import recon  # noqa: E402
import red_recon_agent  # noqa: E402


# A minimal nmap -oX document: one host with an open HTTP port and a closed one.
NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <address addr="10.10.0.20" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="8080"><state state="open"/>
     <service name="http" product="SimpleHTTP"/></port>
   <port protocol="tcp" portid="22"><state state="closed"/>
     <service name="ssh"/></port>
  </ports>
 </host>
</nmaprun>"""

# /proc/net/tcp with one connection to the engine's Modbus port (5020 == 0x139C);
# the remote address is little-endian hex, so 1400140A == 10.20.0.20.
PROC_NET_TCP = (
    "  sl  local_address rem_address   st\n"
    "   0: 0100007F:0050 0100007F:8000 01\n"
    "   1: 0A14000A:C000 1400140A:139C 01\n"
)


class Recon(unittest.TestCase):
    def test_parse_nmap_keeps_only_open_ports(self):
        hosts = recon.parse_nmap_xml(NMAP_XML)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ip"], "10.10.0.20")
        self.assertEqual([p["port"] for p in hosts[0]["ports"]], [8080])
        self.assertEqual(hosts[0]["ports"][0]["service"], "http")

    def test_parse_nmap_bad_xml_is_empty(self):
        self.assertEqual(recon.parse_nmap_xml("not xml"), [])

    def test_scan_it_uses_the_injected_runner(self):
        hosts = recon.scan_it("10.10.0.0/24", [8080], run=lambda c, p: NMAP_XML)
        self.assertEqual(hosts[0]["ip"], "10.10.0.20")

    def test_remote_ips_to_port_reads_proc_net_tcp(self):
        self.assertEqual(recon.remote_ips_to_port(PROC_NET_TCP, 5020), ["10.20.0.20"])
        self.assertEqual(recon.remote_ips_to_port(PROC_NET_TCP, 9999), [])

    def test_discover_ot_finds_engine_and_registers(self):
        def run_cmd(cmd):
            if "/proc/net/tcp" in cmd:
                return PROC_NET_TCP
            if "read_holding_registers" in cmd:
                return '{"0": 200, "1": 0, "2": 1}\n'
            return ""

        ot = recon.discover_ot(run_cmd)
        self.assertEqual(ot["engine_ip"], "10.20.0.20")
        self.assertTrue(ot["modbus_ok"])
        self.assertEqual(ot["registers"], {0: 200, 1: 0, 2: 1})

    def test_discover_ot_no_engine(self):
        self.assertEqual(recon.discover_ot(lambda cmd: ""), {})


class BeliefTree(unittest.TestCase):
    def _leaves(self, tree):
        """Feasible leaf ids of a tree document."""
        out = set()

        def walk(n):
            kids = n.get("children") or []
            if not kids:
                if n.get("feasible", True):
                    out.add(n["id"])
                return
            for c in kids:
                walk(c)

        walk(tree)
        return out

    def test_full_discovery_all_feasible(self):
        findings = {
            "foothold": {"ip": "10.10.0.20", "port": 8080},
            "ot": {"engine_ip": "10.20.0.20", "modbus_ok": True, "registers": {0: 1, 1: 0, 2: 0}},
        }
        tree = belief_tree.build(findings)
        self.assertEqual(tree["id"], "via_hmi")
        self.assertEqual(
            self._leaves(tree),
            {"it_access", "it_exec", "pivot", "setpoint_oor", "breaker_open", "mode_hijack"},
        )

    def test_no_foothold_nothing_feasible(self):
        tree = belief_tree.build({"foothold": None, "ot": {}})
        self.assertEqual(self._leaves(tree), set())

    def test_foothold_but_no_ot_stops_at_exec(self):
        tree = belief_tree.build({"foothold": {"ip": "10.10.0.20", "port": 8080}, "ot": {}})
        self.assertEqual(self._leaves(tree), {"it_access", "it_exec"})

    def test_modbus_ok_without_register_map_assumes_contract(self):
        # The engine answered but the read did not enumerate: the attacker falls
        # back to the known plant contract so no impact is lost.
        findings = {
            "foothold": {"ip": "10.10.0.20", "port": 8080},
            "ot": {"engine_ip": "10.20.0.20", "modbus_ok": True, "registers": {}},
        }
        self.assertEqual(
            self._leaves(belief_tree.build(findings)),
            {"it_access", "it_exec", "pivot", "setpoint_oor", "breaker_open", "mode_hijack"},
        )


class Reconnoitre(unittest.TestCase):
    def test_records_both_stages_and_returns_target(self):
        def scan(cidr, ports):
            return recon.parse_nmap_xml(NMAP_XML)

        def rce_fn(target_url, cmd):
            if "/proc/net/tcp" in cmd:
                return PROC_NET_TCP
            if "read_holding_registers" in cmd:
                return '{"0": 1, "1": 0, "2": 0}'
            return ""

        with tempfile.NamedTemporaryFile("w+", suffix=".jsonl") as f:
            findings, target_url = red_recon_agent.reconnoitre(
                "10.10.0.0/24", [8080], f.name, scan=scan, rce_fn=rce_fn
            )
            f.seek(0)
            rows = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(target_url, "http://10.10.0.20:8080")
        self.assertEqual(findings["foothold"], {"ip": "10.10.0.20", "port": 8080})
        self.assertEqual(findings["ot"]["engine_ip"], "10.20.0.20")
        stages = [r["stage"] for r in rows if r["kind"] == "recon"]
        self.assertEqual(stages, ["it", "ot"])
        self.assertTrue(
            all(isinstance(r.get("t"), float) for r in rows),
            "a recon row with no time cannot be placed on the run's timeline",
        )


if __name__ == "__main__":
    unittest.main()
