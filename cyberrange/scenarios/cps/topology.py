"""topology.py — the CPS lab: IT and OT joined by a boundary firewall, plus the
management network of the security tooling.

    IT 10.10.0.0/24            firewall             OT 10.20.0.0/24
      attacker 10.10.0.10   10.10.0.1 | 10.20.0.1   plc    10.20.0.10
      hmi      10.10.0.20       (FORWARD DROP,      engine 10.20.0.20
        |                         HMI->engine Modbus  sensor eth0 (passive)
        |                         allowed)              |
      ews      10.10.0.30 ......................... ews    10.20.0.30
    MGMT 10.30.0.0/24 ---------------------------------------------------
      hmi eth1 10.30.0.30   firewall eth2 10.30.0.1   sensor eth1 10.30.0.10
      soc      10.30.0.20   ews eth2 10.30.0.50

The attacker cannot reach the engine directly: it must compromise the HMI and
pivot from it, so its writes come from an allowed host. The sensor has a
passive NIC on the OT link (it sees the Modbus traffic) and no address there.

The engineering workstation (ews) stands on both IT and OT, as the machine that
programs a PLC does. It forwards nothing and speaks no Modbus of its own, so the
boundary holds and the plant's traffic is the same with it; but whoever takes it
is on the OT link, next to the PLC and the engine, without crossing the firewall.

MGMT is the in-band management network: the hosts that report findings or
enforce countermeasures sit on it next to the SOC. The HMI and the workstation
are on it as well as on IT, which makes them the ways in for an attacker — the
firewall forwards nothing to or from MGMT. The engine and the PLC are
deliberately not on it: a host sharing a network with the engine could write to
it without crossing the boundary — which is what the workstation, on OT, can do.

What the experiment itself reads (ledger, dashboard, artifacts) never travels
on a lab network: it goes through the container runtime, so no node can see it.

The lab is data (lab.py); this module turns a LabSpec into the platform's
Topology, adding what each host runs. The module constants below are the
default lab's, for the code and the tests that speak of that lab in particular.
"""

import types
from dataclasses import dataclass, field

from cyberrange.core.topology import Iface, Node, Route, Topology, build_lab as _build
from cyberrange.scenarios.cps import lab as L
from cyberrange.scenarios.cps.guest_files import (
    ATTACKER_CPS_FILES,
    ENGINE_FILES,
    EWS_FILES,
    FW_FILES,
    HMI_FILES,
    PLC_FILES,
    SENSOR_FILES,
    SOC_FILES,
)

LAB_NAME = "cps"
IMAGE, SOC_IMAGE = L.IMAGE, L.SOC_IMAGE
IT, OT, MGMT = L.IT, L.OT, L.MGMT
MODBUS_PORT, APP_PORT, MAINT_PORT = L.MODBUS_PORT, L.APP_PORT, L.MAINT_PORT
DASHBOARD_GUEST_PORT = 8080
# What a team's node serves to the people of the team, when a scenario puts
# people in the lab: its console and its web terminal.
CONSOLE_GUEST_PORT = 8090
TERMINAL_GUEST_PORT = 8091

# What each host runs, by its profile.
PROFILE_FILES = {
    "attacker": ATTACKER_CPS_FILES,
    "hmi": HMI_FILES,
    "ews": EWS_FILES,
    "firewall": FW_FILES,
    "plc": PLC_FILES,
    "engine": ENGINE_FILES,
    "sensor": SENSOR_FILES,
    "soc": SOC_FILES,
}

# ── the default lab, by name ─────────────────────────────────────────────────
DEFAULT = L.default_spec()
IT_NET, OT_NET, MGMT_NET = (DEFAULT.zone(z).cidr for z in (IT, OT, MGMT))
ATTACKER_IP = DEFAULT.ip("attacker")
HMI_IP = DEFAULT.ip("hmi", IT)
EWS_IP = DEFAULT.ip("ews", IT)
FW_IT_IP = DEFAULT.ip("firewall", IT)
FW_OT_IP = DEFAULT.ip("firewall", OT)
PLC_IP = DEFAULT.ip("plc")
ENGINE_IP = DEFAULT.ip("engine")
EWS_OT_IP = DEFAULT.ip("ews", OT)
FW_MGMT_IP = DEFAULT.ip("firewall", MGMT)
SENSOR_MGMT_IP = DEFAULT.ip("sensor", MGMT)
SOC_IP = DEFAULT.ip("soc")
HMI_MGMT_IP = DEFAULT.ip("hmi", MGMT)
EWS_MGMT_IP = DEFAULT.ip("ews", MGMT)
# Primary address per machine NIC — also the "addresses" meta on each Machine.
ADDRESSES = {h.name: DEFAULT.addresses(h.name) for h in DEFAULT.hosts}


def wazuh_agents(spec=None):
    """{host: agent id} of the hosts that run a Wazuh agent: those on the SOC's
    network. The engine and the PLC have none: the plant is watched from the
    wire and acted on from the boundary."""
    spec = spec or DEFAULT
    return {h.name: f"{i:03d}" for i, h in enumerate(spec.managed(), 1)}


WAZUH_AGENTS = wazuh_agents()


def firewall_rules(spec=None):
    """The boundary's standing ruleset (LabSpec.boundary_rules)."""
    return (spec or DEFAULT).boundary_rules()


def sensor_rules(ifaces):
    """The sensor's live page is instrumentation, reached through the bridged
    NIC only. Its server listens on every address, so without this rule the
    page would also answer on MGMT, where the HMI — the attacker's foothold —
    could read the defense's own view of the attack."""
    return [
        f"iptables -A INPUT -i {i} -p tcp --dport {DASHBOARD_GUEST_PORT} -j DROP" for i in ifaces
    ]


def closed_on(iface, *ports):
    """A team's console and terminal are for its people, reached through the
    node's bridged NIC only. Their servers listen on every address, so without
    these rules they would also answer on the lab network behind ``iface``,
    where the other side is: the HMI on MGMT could try the SOC's token and
    approve in the operator's place, a host on IT could drive the attacker's
    console."""
    return [f"iptables -A INPUT -i {iface} -p tcp --dport {p} -j DROP" for p in ports]


@dataclass
class Extra:
    """What a scenario built on this lab adds to one node: files to stage,
    host ports to publish ("HOST:GUEST/tcp"), startup commands, optionally a
    different node image (e.g. the attacker on its own red-team image), and
    interfaces on links of the scenario's own, after the lab's."""

    files: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    startup: list = field(default_factory=list)
    image: str = None
    ifaces: list = field(default_factory=list)

    def merged(self, other):
        """This and ``other`` on the same node: files, ports and startup in
        order; two different images cannot both be the node's."""
        if self.image and other.image and self.image != other.image:
            raise ValueError(f"one node, two images: {self.image} and {other.image}")
        return Extra(
            self.files + other.files,
            self.ports + other.ports,
            self.startup + other.startup,
            other.image or self.image,
            self.ifaces + other.ifaces,
        )


def topology(args, name=LAB_NAME, extras=None, spec=None) -> Topology:
    """The lab ``spec`` (default: the default lab), named ``name``: a scenario
    that reuses it under another name can run next to this one. ``extras``
    ({node: Extra}) is what such a scenario adds to the nodes; the lab is the
    same without it."""
    spec = spec or DEFAULT
    dashboard = int(getattr(args, "dashboard_port", 0) or 0)
    extras = extras or {}
    unknown = set(extras) - {h.name for h in spec.hosts}
    if unknown:
        raise ValueError(f"extras for hosts the lab does not have: {sorted(unknown)}")
    sensors = spec.with_role("sensor")
    nodes = []
    for h in spec.hosts:
        extra = extras.get(h.name) or Extra()
        node = _node(spec, h, published=bool(extra.ports))
        if dashboard and sensors and h is sensors[0]:
            node.mgmt_port = f"{dashboard}:{DASHBOARD_GUEST_PORT}/tcp"
        node.files = list(node.files) + list(extra.files)
        node.ifaces = list(node.ifaces) + list(extra.ifaces)
        node.startup = list(node.startup) + list(extra.startup)
        if extra.ports:
            node.mgmt_port = node.published_ports() + list(extra.ports)
        if extra.image:
            node.image = extra.image
        nodes.append(node)
    return Topology(name, default_image=IMAGE, nodes=nodes)


def _node(spec, h, published):
    ifaces = [
        Iface(n.zone, promisc=True) if n.passive else Iface(n.zone, spec.cidr_of(n)) for n in h.nics
    ]
    routes = []
    gw = spec.gateway(h.name)
    if gw:
        # A published port brings a bridged NIC with a default route of its
        # own: the lab's must replace it, not fail next to it.
        routes = [Route("default", gw[0], gw[1], replace=published)]
    startup = []
    if h.name == spec.boundary:
        startup += spec.boundary_rules()
    if spec.forwards(h.name):
        # The host is no router. Every container forwards by default, and with
        # feet on two zones it would carry one straight onto the other, around
        # the boundary.
        startup.append("iptables -P FORWARD DROP")
    if h.role == "sensor":
        startup += sensor_rules(spec.addresses(h.name))
    return Node(
        h.name,
        ifaces,
        image=h.image,
        role=h.role,
        routes=routes,
        startup=startup,
        files=PROFILE_FILES.get(h.profile, []),
    )


def default_args():
    """The arguments the topology reads, at their defaults."""
    return types.SimpleNamespace(dashboard_port=0)


def build_lab(args=None):
    """(lab, machines, startups) of the CPS lab, not deployed."""
    return _build(topology(args or default_args()))


def services(spec=None):
    """Exposed services per machine: (name, proto, port, app)."""
    spec = spec or DEFAULT
    return {h.name: [tuple(vars(s).values()) for s in h.services] for h in spec.hosts if h.services}
