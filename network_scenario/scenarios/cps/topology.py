"""topology.py — the CPS lab: three zones joined by an IT/OT boundary firewall.

    IT 10.10.0.0/24            firewall             OT 10.20.0.0/24
      attacker 10.10.0.10   10.10.0.1 | 10.20.0.1   plc    10.20.0.10
      hmi      10.10.0.20       (FORWARD DROP,      engine 10.20.0.20
                                  HMI->engine Modbus  sensor eth0 (passive)
                                  allowed)
                                                    DEF 10.30.0.0/24
                                                      sensor eth1 10.30.0.10

The attacker cannot reach the engine directly: it must compromise the HMI and
pivot from it, so its writes come from an allowed host. The sensor has a
passive NIC on the OT link (it sees the Modbus traffic) and a management NIC
on the defense net (unreachable from OT). Node roles are the knowledge graph's.
"""

import types

from network_scenario.core.topology import Iface, Node, Route, Topology, build_lab as _build
from network_scenario.guest_files import (
    ATTACKER_CPS_FILES, ENGINE_FILES, HMI_FILES, PLC_FILES, SENSOR_FILES,
)

LAB_NAME = "cps"
IMAGE = "kathara/cps"
# Zones (collision domains)
IT, OT, DEF = "IT", "OT", "DEF"
# Addresses
ATTACKER_IP = "10.10.0.10"
HMI_IP = "10.10.0.20"
FW_IT_IP = "10.10.0.1"
FW_OT_IP = "10.20.0.1"
PLC_IP = "10.20.0.10"
ENGINE_IP = "10.20.0.20"
SENSOR_DEF_IP = "10.30.0.10"
IT_NET, OT_NET, DEF_NET = "10.10.0.0/24", "10.20.0.0/24", "10.30.0.0/24"
MODBUS_PORT = 5020
APP_PORT = 8080
DASHBOARD_GUEST_PORT = 8080
# Primary address per machine NIC — also the "addresses" meta on each Machine.
# The sensor's OT NIC (eth0) is passive and deliberately has no address.
ADDRESSES = {
    "attacker": {"eth0": f"{ATTACKER_IP}/24"},
    "hmi":      {"eth0": f"{HMI_IP}/24"},
    "firewall": {"eth0": f"{FW_IT_IP}/24", "eth1": f"{FW_OT_IP}/24"},
    "plc":      {"eth0": f"{PLC_IP}/24"},
    "engine":   {"eth0": f"{ENGINE_IP}/24"},
    "sensor":   {"eth1": f"{SENSOR_DEF_IP}/24"},
}


def firewall_rules():
    """Standing IT/OT boundary ruleset: default-drop forwarding, keep established
    flows, and allow ONLY the sanctioned HMI -> engine Modbus flow. The firewall
    cannot tell a legitimate operator command from a hijacked one — it only sees
    "HMI, TCP to 5020" — which is what the DPI sensor and the SOAR response
    exist to compensate for."""
    return [
        "sysctl -w net.ipv4.ip_forward=1",
        "iptables -P FORWARD DROP",
        "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
        f"iptables -A FORWARD -s {HMI_IP} -d {ENGINE_IP} -p tcp --dport {MODBUS_PORT} -j ACCEPT",
    ]


def topology(args) -> Topology:
    dashboard = int(getattr(args, "dashboard_port", 0) or 0)

    def gw(via):
        return [Route("default", via, "eth0")]

    def addr(name, i):
        return ADDRESSES[name].get(f"eth{i}")

    return Topology(LAB_NAME, default_image=IMAGE, nodes=[
        Node("attacker", [Iface(IT, addr("attacker", 0))], role="it-host",
             routes=gw(FW_IT_IP), files=ATTACKER_CPS_FILES),
        Node("hmi", [Iface(IT, addr("hmi", 0))], role="hmi",
             routes=gw(FW_IT_IP), files=HMI_FILES),
        Node("firewall", [Iface(IT, addr("firewall", 0)), Iface(OT, addr("firewall", 1))],
             role="boundary", startup=firewall_rules()),
        Node("plc", [Iface(OT, addr("plc", 0))], role="plc",
             routes=gw(FW_OT_IP), files=PLC_FILES),
        Node("engine", [Iface(OT, addr("engine", 0))], role="plant",
             routes=gw(FW_OT_IP), files=ENGINE_FILES),
        Node("sensor", [Iface(OT, promisc=True), Iface(DEF, addr("sensor", 1))],
             role="sensor", files=SENSOR_FILES,
             mgmt_port=f"{dashboard}:{DASHBOARD_GUEST_PORT}/tcp" if dashboard else None),
    ])


def build_lab(args=None):
    """(lab, machines, startups) of the CPS lab, not deployed."""
    return _build(topology(args or types.SimpleNamespace(dashboard_port=0)))


def roles():
    """{machine: knowledge-graph role}, from the topology."""
    return {n.name: n.role for n in topology(types.SimpleNamespace()).nodes}


def services():
    """Exposed services per machine: (name, proto, port, app)."""
    return {
        "hmi":    [("diag-http", "tcp", APP_PORT, "http")],
        "engine": [("modbus", "tcp", MODBUS_PORT, "modbus")],
    }
