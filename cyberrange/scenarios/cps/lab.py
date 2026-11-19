"""lab.py — the CPS lab as data: zones, hosts and the flows the boundary lets through.

A lab of this family is a handful of facts: which networks exist, which hosts
stand on which of them with which role, what each host serves, and which flows
the boundary firewall forwards. Everything else — addresses, routes, the
firewall's ruleset, which hosts carry a Wazuh agent, the SOC's inventory — is
derived from those facts (topology.py, inventory.py). A larger lab is another
LabSpec, not new code; ``default_spec()`` is the lab every CPS scenario runs.

The spec checks the constraints the rest of the system relies on when it is
built, so that a lab breaking one fails here rather than half-way into a run.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Optional

# Roles, as the knowledge graph reads them (nodes/soc/soar_kg.py).
BOUNDARY_ROLE = "boundary"
SOC_ROLE = "soc"


@dataclass(frozen=True)
class Zone:
    """A network. ``routed`` zones are the ones the boundary forwards between;
    an unrouted one (the management network) is reached only by the hosts
    standing on it."""

    name: str
    cidr: str
    routed: bool = True


@dataclass(frozen=True)
class Nic:
    """A host's interface on ``zone``: its address is the zone's network plus
    ``host``. ``host=None`` is a passive NIC — it sees the zone's traffic and
    has no address there."""

    zone: str
    host: Optional[int] = None

    @property
    def passive(self):
        return self.host is None


@dataclass(frozen=True)
class Service:
    name: str
    proto: str
    port: int
    app: str


@dataclass
class Host:
    """A machine of the lab. ``nics`` are in interface order (eth0 first).
    ``profile`` names the software it runs (its guest files); by default it is
    the host's name, which is what the lab's own hosts are called."""

    name: str
    role: str
    nics: tuple
    services: tuple = ()
    image: Optional[str] = None
    profile: Optional[str] = None

    def __post_init__(self):
        self.nics = tuple(self.nics)
        self.services = tuple(self.services)
        self.profile = self.profile or self.name


@dataclass(frozen=True)
class Flow:
    """A flow the boundary forwards: ``src`` to ``dst``'s ``service``."""

    src: str
    dst: str
    service: str


@dataclass
class LabSpec:
    name: str
    zones: tuple
    hosts: tuple
    boundary: str
    flows: tuple = ()
    _zones: dict = field(init=False, repr=False)
    _hosts: dict = field(init=False, repr=False)

    def __post_init__(self):
        self.zones, self.hosts, self.flows = tuple(self.zones), tuple(self.hosts), tuple(self.flows)
        self._zones = {z.name: z for z in self.zones}
        self._hosts = {h.name: h for h in self.hosts}
        self.check()

    # ── lookups ──────────────────────────────────────────────────────────────
    def zone(self, name) -> Zone:
        return self._zones[name]

    def host(self, name) -> Host:
        try:
            return self._hosts[name]
        except KeyError:
            raise KeyError(f"no host {name!r} in the {self.name} lab") from None

    def with_role(self, role):
        """The hosts of ``role``, in declaration order."""
        return [h for h in self.hosts if h.role == role]

    def one(self, role) -> Host:
        """The only host of ``role``: for what a lab of this family has once."""
        found = self.with_role(role)
        if len(found) != 1:
            raise ValueError(
                f"the {self.name} lab has {len(found)} hosts of role {role!r}, this needs one"
            )
        return found[0]

    def address(self, nic: Nic) -> str:
        net = ipaddress.ip_network(self.zone(nic.zone).cidr)
        return str(net.network_address + nic.host)

    def cidr_of(self, nic: Nic) -> str:
        """``addr/prefix`` of an addressed NIC, as the startup commands write it."""
        prefix = ipaddress.ip_network(self.zone(nic.zone).cidr).prefixlen
        return f"{self.address(nic)}/{prefix}"

    def ip(self, host, zone=None) -> str:
        """``host``'s address on ``zone``; without a zone, its primary address
        (the first addressed NIC)."""
        h = self.host(host)
        for nic in h.nics:
            if not nic.passive and (zone is None or nic.zone == zone):
                return self.address(nic)
        raise KeyError(f"{host} has no address" + (f" on {zone}" if zone else ""))

    def iface(self, host, zone) -> str:
        """The name of ``host``'s interface on ``zone`` (eth<i>)."""
        for i, nic in enumerate(self.host(host).nics):
            if nic.zone == zone:
                return f"eth{i}"
        raise KeyError(f"{host} is not on {zone}")

    def zone_of(self, host) -> str:
        """The zone of ``host``'s primary address."""
        return next(n.zone for n in self.host(host).nics if not n.passive)

    def service(self, host, name) -> Service:
        for s in self.host(host).services:
            if s.name == name:
                return s
        raise KeyError(f"{host} serves no {name}")

    def addresses(self, host):
        """{eth<i>: addr/prefix} of the addressed NICs of ``host``."""
        return {
            f"eth{i}": self.cidr_of(n) for i, n in enumerate(self.host(host).nics) if not n.passive
        }

    def gateway(self, host):
        """(via, dev) of ``host``'s default route: the boundary's address on the
        zone of its first NIC, when that zone is routed. None for the boundary
        itself and for hosts that stand only where nothing is forwarded."""
        h = self.host(host)
        if h.name == self.boundary or not h.nics:
            return None
        first = h.nics[0]
        if first.passive or not self.zone(first.zone).routed:
            return None
        return self.ip(self.boundary, first.zone), "eth0"

    def forwards(self, host) -> bool:
        """Whether ``host`` would carry traffic between two routed zones. Every
        container forwards by default: only the boundary may."""
        routed = {n.zone for n in self.host(host).nics if self.zone(n.zone).routed}
        return host != self.boundary and len(routed) > 1

    def managed(self):
        """The hosts on the SOC's network, the SOC aside: those that report to it
        and on which it may act. The plant is never among them — it is watched
        from the wire and acted on from the boundary."""
        soc = self.one(SOC_ROLE)
        zone = self.zone_of(soc.name)
        return [
            h
            for h in self.hosts
            if h is not soc and any(n.zone == zone and not n.passive for n in h.nics)
        ]

    # ── the boundary ─────────────────────────────────────────────────────────
    def boundary_rules(self):
        """The boundary's standing ruleset: forward nothing but the declared
        flows (and the replies to them). The firewall cannot tell a legitimate
        command from a hijacked one on an allowed flow — that is what the DPI
        sensor and the SOAR response are for."""
        rules = [
            "sysctl -w net.ipv4.ip_forward=1",
            "iptables -P FORWARD DROP",
            "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
        ]
        for f in self.flows:
            svc = self.service(f.dst, f.service)
            rules.append(
                f"iptables -A FORWARD -s {self.ip(f.src)} -d {self.ip(f.dst)} "
                f"-p {svc.proto} --dport {svc.port} -j ACCEPT"
            )
        return rules

    # ── what the rest of the system relies on ────────────────────────────────
    def check(self):
        def fail(why):
            raise ValueError(f"lab {self.name}: {why}")

        if len(self._hosts) != len(self.hosts):
            fail("two hosts share a name")
        if "-" in "".join(self._hosts):
            fail("Kathará refuses a machine name with '-'")
        if self.boundary not in self._hosts:
            fail(f"no boundary host {self.boundary!r}")
        taken = {}
        for h in self.hosts:
            for nic in h.nics:
                if nic.zone not in self._zones:
                    fail(f"{h.name} is on an undeclared zone {nic.zone!r}")
                if nic.passive:
                    continue
                net = ipaddress.ip_network(self.zone(nic.zone).cidr)
                if not 0 < nic.host < net.num_addresses - 1:
                    fail(f"{h.name}: host number {nic.host} is outside {net}")
                key = (nic.zone, nic.host)
                if key in taken:
                    fail(f"{h.name} and {taken[key]} share {self.address(nic)}")
                taken[key] = h.name
            # The knowledge graph lists a host's addresses in string order and
            # takes the first as the host's own: the primary address must sort
            # first, or the SOC reasons about the wrong one.
            addrs = [self.address(n) for n in h.nics if not n.passive]
            if addrs and min(addrs) != addrs[0]:
                fail(f"{h.name}'s primary address {addrs[0]} does not sort first in {addrs}")
        for f in self.flows:
            self.service(f.dst, f.service)
            self.ip(f.src)


# ── the lab every CPS scenario runs ──────────────────────────────────────────
IT, OT, MGMT = "IT", "OT", "MGMT"
IMAGE = "kathara/cps"
SOC_IMAGE = "kathara/soc"  # the Wazuh manager; too heavy to put on every node
MODBUS_PORT = 5020
APP_PORT = 8080
MAINT_PORT = 8081  # the workstation's remote-maintenance service


def default_spec() -> LabSpec:
    """IT and OT joined by a boundary firewall, plus the management network
    of the security tooling (the diagram is in topology.py)."""
    return LabSpec(
        name="cps",
        zones=(
            Zone(IT, "10.10.0.0/24"),
            Zone(OT, "10.20.0.0/24"),
            # MGMT stays numerically above IT and OT, so that a host's IT or OT
            # address sorts first and stays its primary one.
            Zone(MGMT, "10.30.0.0/24", routed=False),
        ),
        hosts=(
            Host("attacker", "it-host", [Nic(IT, 10)]),
            # IT first: the response isolates the HMI by taking eth0 down, and
            # must still reach it afterwards on its MGMT NIC.
            Host(
                "hmi",
                "hmi",
                [Nic(IT, 20), Nic(MGMT, 30)],
                [Service("diag-http", "tcp", APP_PORT, "http")],
            ),
            # .21-.40 of MGMT belong to the SOC's tooling (cps-soc).
            Host(
                "ews",
                "engineering",
                [Nic(IT, 30), Nic(OT, 30), Nic(MGMT, 50)],
                [Service("maint-http", "tcp", MAINT_PORT, "http")],
            ),
            Host("firewall", BOUNDARY_ROLE, [Nic(IT, 1), Nic(OT, 1), Nic(MGMT, 1)]),
            Host("plc", "plc", [Nic(OT, 10)]),
            Host(
                "engine", "plant", [Nic(OT, 20)], [Service("modbus", "tcp", MODBUS_PORT, "modbus")]
            ),
            # A passive NIC on the OT link: it sees the Modbus traffic, and
            # nothing there can reach it.
            Host("sensor", "sensor", [Nic(OT), Nic(MGMT, 10)]),
            Host("soc", SOC_ROLE, [Nic(MGMT, 20)], image=SOC_IMAGE),
        ),
        boundary="firewall",
        flows=(Flow("hmi", "engine", "modbus"),),
    )
