"""topology.py — the CPS lab: IT and OT joined by a boundary firewall, plus the
management network of the security tooling.

    IT 10.10.0.0/24            firewall             OT 10.20.0.0/24
      attacker 10.10.0.10   10.10.0.1 | 10.20.0.1   plc    10.20.0.10
      hmi      10.10.0.20       (FORWARD DROP,      engine 10.20.0.20
        |                         HMI->engine Modbus  sensor eth0 (passive)
        |                         allowed)              |
    MGMT 10.30.0.0/24 ---------------------------------------------------
      hmi eth1 10.30.0.30   firewall eth2 10.30.0.1   sensor eth1 10.30.0.10
      soc      10.30.0.20

The attacker cannot reach the engine directly: it must compromise the HMI and
pivot from it, so its writes come from an allowed host. The sensor has a
passive NIC on the OT link (it sees the Modbus traffic) and no address there.

MGMT is the in-band management network: the hosts that report findings or
enforce countermeasures sit on it next to the SOC. The HMI is dual-homed, which
makes it the one way in for an attacker — the firewall forwards nothing to or
from MGMT. The engine and the PLC are deliberately not on it: a host sharing a
network with the engine could write to it without crossing the boundary.

What the experiment itself reads (ledger, dashboard, artifacts) never travels
on a lab network: it goes through the container runtime, so no node can see it.
Node roles are the knowledge graph's.
"""

import types

from cyberrange.core.topology import Iface, Node, Route, Topology, build_lab as _build
from cyberrange.scenarios.cps.guest_files import (
    ATTACKER_CPS_FILES,
    ENGINE_FILES,
    FW_FILES,
    HMI_FILES,
    PLC_FILES,
    SENSOR_FILES,
    SOC_FILES,
)

LAB_NAME = "cps"
IMAGE = "kathara/cps"
SOC_IMAGE = "kathara/soc"  # the Wazuh manager; too heavy to put on every node
# Zones (collision domains)
IT, OT, MGMT = "IT", "OT", "MGMT"
# Addresses
ATTACKER_IP = "10.10.0.10"
HMI_IP = "10.10.0.20"
FW_IT_IP = "10.10.0.1"
FW_OT_IP = "10.20.0.1"
PLC_IP = "10.20.0.10"
ENGINE_IP = "10.20.0.20"
# MGMT stays numerically above IT and OT: the knowledge graph lists a host's
# addresses in string order and takes the first as its primary one.
FW_MGMT_IP = "10.30.0.1"
SENSOR_MGMT_IP = "10.30.0.10"
SOC_IP = "10.30.0.20"
HMI_MGMT_IP = "10.30.0.30"
IT_NET, OT_NET, MGMT_NET = "10.10.0.0/24", "10.20.0.0/24", "10.30.0.0/24"
MODBUS_PORT = 5020
APP_PORT = 8080
DASHBOARD_GUEST_PORT = 8080
OPERATOR_GUEST_PORT = 8090  # the SOC's operator API, when the SOC advises
# Primary address per machine NIC — also the "addresses" meta on each Machine.
# The sensor's OT NIC (eth0) is passive and deliberately has no address.
ADDRESSES = {
    "attacker": {"eth0": f"{ATTACKER_IP}/24"},
    "hmi": {"eth0": f"{HMI_IP}/24", "eth1": f"{HMI_MGMT_IP}/24"},
    "firewall": {"eth0": f"{FW_IT_IP}/24", "eth1": f"{FW_OT_IP}/24", "eth2": f"{FW_MGMT_IP}/24"},
    "plc": {"eth0": f"{PLC_IP}/24"},
    "engine": {"eth0": f"{ENGINE_IP}/24"},
    "sensor": {"eth1": f"{SENSOR_MGMT_IP}/24"},
    "soc": {"eth0": f"{SOC_IP}/24"},
}


# Hosts that run a Wazuh agent, with the id the manager knows each by. The
# engine and the PLC have none: the plant is watched from the wire and acted on
# from the boundary.
WAZUH_AGENTS = {"sensor": "001", "hmi": "002", "firewall": "003"}


def sensor_rules():
    """The sensor's live page is instrumentation, reached through the bridged
    NIC only. Its server listens on every address, so without this rule the
    page would also answer on MGMT, where the HMI — the attacker's foothold —
    could read the defense's own view of the attack."""
    return [f"iptables -A INPUT -i eth1 -p tcp --dport {DASHBOARD_GUEST_PORT} -j DROP"]


def soc_rules():
    """The SOC's operator API is for the operator's console, reached through
    the bridged NIC only. Its server listens on every address, so without this
    rule it would also answer on MGMT (eth0), where the HMI — the attacker's
    foothold — could try its token and approve or reject in the operator's
    place."""
    return [f"iptables -A INPUT -i eth0 -p tcp --dport {OPERATOR_GUEST_PORT} -j DROP"]


def firewall_rules():
    """Standing boundary ruleset: default-drop forwarding, keep established
    flows, and allow ONLY the sanctioned HMI -> engine Modbus flow — so nothing
    is forwarded to or from MGMT either. The firewall
    cannot tell a legitimate operator command from a hijacked one — it only sees
    "HMI, TCP to 5020" — which is what the DPI sensor and the SOAR response
    exist to compensate for."""
    return [
        "sysctl -w net.ipv4.ip_forward=1",
        "iptables -P FORWARD DROP",
        "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
        f"iptables -A FORWARD -s {HMI_IP} -d {ENGINE_IP} -p tcp --dport {MODBUS_PORT} -j ACCEPT",
    ]


def topology(args, name=LAB_NAME) -> Topology:
    """The lab, named ``name``: a scenario that reuses it under another name can
    run next to this one. With an ``operator_port`` in ``args`` the SOC's
    operator API is published on that host port."""
    dashboard = int(getattr(args, "dashboard_port", 0) or 0)
    operator = int(getattr(args, "operator_port", 0) or 0)

    def gw(via):
        return [Route("default", via, "eth0")]

    def addr(name, i):
        return ADDRESSES[name].get(f"eth{i}")

    return Topology(
        name,
        default_image=IMAGE,
        nodes=[
            Node(
                "attacker",
                [Iface(IT, addr("attacker", 0))],
                role="it-host",
                routes=gw(FW_IT_IP),
                files=ATTACKER_CPS_FILES,
            ),
            Node(
                "hmi",
                # IT first: the response isolates the HMI by taking eth0 down,
                # and must still reach it afterwards on eth1.
                [Iface(IT, addr("hmi", 0)), Iface(MGMT, addr("hmi", 1))],
                role="hmi",
                routes=gw(FW_IT_IP),
                files=HMI_FILES,
            ),
            Node(
                "firewall",
                [
                    Iface(IT, addr("firewall", 0)),
                    Iface(OT, addr("firewall", 1)),
                    Iface(MGMT, addr("firewall", 2)),
                ],
                role="boundary",
                startup=firewall_rules(),
                files=FW_FILES,
            ),
            Node(
                "plc", [Iface(OT, addr("plc", 0))], role="plc", routes=gw(FW_OT_IP), files=PLC_FILES
            ),
            Node(
                "engine",
                [Iface(OT, addr("engine", 0))],
                role="plant",
                routes=gw(FW_OT_IP),
                files=ENGINE_FILES,
            ),
            Node(
                "sensor",
                [Iface(OT, promisc=True), Iface(MGMT, addr("sensor", 1))],
                role="sensor",
                startup=sensor_rules(),
                files=SENSOR_FILES,
                mgmt_port=f"{dashboard}:{DASHBOARD_GUEST_PORT}/tcp" if dashboard else None,
            ),
            Node(
                "soc",
                [Iface(MGMT, addr("soc", 0))],
                image=SOC_IMAGE,
                role="soc",
                startup=soc_rules() if operator else [],
                files=SOC_FILES,
                mgmt_port=f"{operator}:{OPERATOR_GUEST_PORT}/tcp" if operator else None,
            ),
        ],
    )


def default_args():
    """The arguments the topology reads, at their defaults."""
    return types.SimpleNamespace(dashboard_port=0)


def build_lab(args=None):
    """(lab, machines, startups) of the CPS lab, not deployed."""
    return _build(topology(args or default_args()))


def roles():
    """{machine: knowledge-graph role}, from the topology."""
    return {n.name: n.role for n in topology(default_args()).nodes}


def services():
    """Exposed services per machine: (name, proto, port, app)."""
    return {
        "hmi": [("diag-http", "tcp", APP_PORT, "http")],
        "engine": [("modbus", "tcp", MODBUS_PORT, "modbus")],
    }
