"""trees.py — attack tree of the CPS chain and the countermeasures that
annotate it (an attack-defense tree), instantiated on the knowledge graph.

The attack tree is a template whose steps reference knowledge-graph nodes and
whose preconditions are checked against the graph (``feasible``): change the
graph — e.g. drop the boundary allow rule — and the branch that needs it
becomes infeasible. Automatic generation from the graph is a later step (WP2
T2.2); v0 is hand-written but graph-grounded.

Gates: AND children are ordered steps that must all succeed; OR children are
alternatives. ATT&CK ids are a first mapping and carry ``review`` notes where
they still need validation.

Countermeasures split their effect in two, because a response has two jobs:
    prevents   nodes the action stops from (re)occurring  (e.g. block a flow)
    restores   impact nodes the action undoes             (e.g. back to AUTO)
Commands are shell strings run on ``machine`` (a lab host name).
"""

from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

from defense_plane import ot_registers as reg
from defense_plane.soar import kg as kgmod

AND, OR, LEAF = "AND", "OR", "LEAF"
DG_SCALE = reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1]


@dataclass
class Node:
    id: str
    label: str
    gate: str = LEAF
    children: list = field(default_factory=list)
    attck: Optional[str] = None          # ATT&CK (Enterprise or ICS) technique id
    attck_name: Optional[str] = None
    targets: list = field(default_factory=list)   # knowledge-graph node ids
    impact: float = 0.0                  # loss weight if this node is achieved
    observable: bool = True              # can the OT sensor see this step at all?
    review: Optional[str] = None         # open question on the mapping
    precondition: Optional[Callable] = field(default=None, repr=False)

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def to_dict(self):
        d = {k: v for k, v in asdict(self).items() if k not in ("children", "precondition")}
        d["children"] = [c.to_dict() for c in self.children]
        return d


@dataclass
class Countermeasure:
    id: str
    label: str
    d3fend: Optional[str]                # D3FEND technique name (id to be checked)
    machine: Optional[str]               # lab host the commands run on
    apply: list
    revert: list
    prevents: list = field(default_factory=list)
    restores: list = field(default_factory=list)
    time_to_effect_s: float = 1.0        # nominal; replaced by measured values later
    op_cost: float = 0.0                 # operational disruption, 0..1
    energy_cost: float = 0.0             # relative energy cost, 0..1
    requires_approval: bool = False
    order: int = 50                      # execution order: preventive first

    def to_dict(self):
        return asdict(self)


# ── Tree helpers ─────────────────────────────────────────────────────────────

def index(root):
    return {n.id: n for n in root.walk()}


def parents(root):
    out = {}
    for n in root.walk():
        for c in n.children:
            out[c.id] = n
    return out


def leaves(root):
    return [n for n in root.walk() if n.gate == LEAF]


def feasible(node, g):
    """Node achievable on graph ``g``: a leaf by its precondition, AND when all
    children are, OR when any child is."""
    if node.gate == LEAF:
        return node.precondition(g) if node.precondition else True
    results = [feasible(c, g) for c in node.children]
    return all(results) if node.gate == AND else any(results)


def prerequisites(root, node_id):
    """Steps that must already have succeeded for ``node_id`` to be reached:
    the earlier siblings in every AND ancestor (with their whole subtrees)."""
    par, idx = parents(root), index(root)
    out, cur = [], idx[node_id]
    while cur.id in par:
        p = par[cur.id]
        if p.gate == AND:
            for sib in p.children[:p.children.index(cur)]:
                out.extend(n.id for n in sib.walk())
        cur = p
    return out


def ancestors(root, node_id):
    par, out, cur = parents(root), [], node_id
    while cur in par:
        cur = par[cur].id
        out.append(cur)
    return out


def to_json(root, countermeasures):
    """Attack-defense tree: the attack tree plus, per node, the countermeasures
    that prevent or restore it (what WP4 consumes for explanations)."""
    defense = {}
    for cm in countermeasures:
        for nid in cm.prevents:
            defense.setdefault(nid, {"prevented_by": [], "restored_by": []})["prevented_by"].append(cm.id)
        for nid in cm.restores:
            defense.setdefault(nid, {"prevented_by": [], "restored_by": []})["restored_by"].append(cm.id)
    return {"attack_tree": root.to_dict(), "defense": defense,
            "countermeasures": [c.to_dict() for c in countermeasures]}


# ── The CPS lab ──────────────────────────────────────────────────────────────

# Roles that may legitimately talk Modbus to the plant (the plant contract).
_MODBUS_ROLES = set(reg.ROLE_POLICY)


def _hosts_by_role(g, role):
    return [g.nodes[h]["name"] for h in kgmod.hosts(g) if g.nodes[h]["role"] == role]


def cps_context(g):
    """Addresses and ports the CPS tree and countermeasures need, read off the
    knowledge graph (not hard-coded)."""
    hmi = _hosts_by_role(g, "hmi")[0]
    engine = _hosts_by_role(g, "plant")[0]
    fw = _hosts_by_role(g, kgmod.BOUNDARY_ROLE)[0]
    modbus = g.nodes[f"svc:{engine}/modbus"]
    http = kgmod.services_of(g, hmi)[0]
    hmi_ip = kgmod.addresses(g, hmi)[0][0]
    fw_on_hmi_zone = [a for a, z in kgmod.addresses(g, fw)
                      if z == kgmod.addresses(g, hmi)[0][1]][0]
    return {"hmi": hmi, "engine": engine, "firewall": fw,
            "hmi_ip": hmi_ip, "engine_ip": kgmod.addresses(g, engine)[0][0],
            "gateway_hmi": fw_on_hmi_zone, "modbus_port": modbus["port"],
            "modbus_svc": f"svc:{engine}/modbus", "hmi_svc": http,
            "hmi_port": g.nodes[http]["port"]}


def cps_attack_tree(g):
    """Attack tree of the CPS chain, grounded on knowledge graph ``g``."""
    c = cps_context(g)
    hr = lambda a: f"reg:hr:{a}"  # noqa: E731

    def via_trusted_flow(gg):
        return kgmod.reachable(gg, c["hmi"], c["engine"], c["modbus_port"])

    def unknown_ot_writer(gg):
        # Any host outside the Modbus roles (and not the boundary device) that
        # can reach the plant: none in the lab as built.
        for h in kgmod.hosts(gg):
            d = gg.nodes[h]
            if d["role"] in _MODBUS_ROLES | {kgmod.BOUNDARY_ROLE, "plant"}:
                continue
            if kgmod.reachable(gg, d["name"], c["engine"], c["modbus_port"]):
                return True
        return False

    ot_actions = Node(
        "ot_action", "Manipulate the plant over Modbus", OR, children=[
            Node("setpoint_oor", "DG setpoint written outside its envelope",
                 attck="T0855", attck_name="Unauthorized Command Message",
                 targets=[hr(reg.HR_DG_SETPOINT)], impact=0.6),
            Node("breaker_open", "Feeder breaker opened remotely",
                 attck="T0855", attck_name="Unauthorized Command Message",
                 targets=[hr(reg.HR_SWITCH_CMD)], impact=1.0,
                 review="T0813 (Denial of Control) / T0831 also plausible"),
            Node("mode_hijack", "MANUAL authority taken, in-range unsafe dispatch",
                 attck="T0831", attck_name="Manipulation of Control",
                 targets=[hr(reg.HR_CTRL_MODE), hr(reg.HR_DG_SETPOINT)], impact=0.9),
        ])

    via_hmi = Node(
        "via_hmi", "Through the HMI (the only host allowed across the boundary)", AND,
        children=[
            Node("it_access", "Initial access to the HMI's web application",
                 attck="T1190", attck_name="Exploit Public-Facing Application",
                 targets=[c["hmi_svc"]], observable=False),
            Node("it_exec", "Command execution on the HMI host",
                 attck="T1059", attck_name="Command and Scripting Interpreter",
                 targets=[f"host:{c['hmi']}"], observable=False),
            Node("pivot", "Use the sanctioned HMI -> plant Modbus flow",
                 targets=[c["modbus_svc"]] + [r["id"] for r in kgmod.flow_rules(g, c["firewall"])],
                 observable=False, precondition=via_trusted_flow,
                 review="ATT&CK id to be chosen (lateral movement over a trusted flow)"),
            ot_actions,
        ])

    direct = Node(
        "direct_ot", "From a host without a Modbus role", AND, children=[
            Node("ot_foothold", "Foothold on a host that reaches the plant",
                 observable=False, precondition=unknown_ot_writer,
                 review="no such host in the lab as built; kept for unauthorized_* findings"),
            Node("ot_write_unknown", "Unauthorized Modbus access from that host",
                 attck="T0855", attck_name="Unauthorized Command Message",
                 targets=[c["modbus_svc"]], impact=0.6),
        ])

    return Node("impact", "Physical impact on the feeder", OR,
                children=[via_hmi, direct])


def cps_countermeasures(g):
    """Countermeasures executable in the lab, with their commands."""
    c = cps_context(g)
    flow = f"-s {c['hmi_ip']} -d {c['engine_ip']} -p tcp --dport {c['modbus_port']}"
    port = c["modbus_port"]
    ot_leaves = ["setpoint_oor", "breaker_open", "mode_hijack"]
    return [
        Countermeasure(
            "notify", "Alert the operator, no automatic action", None, None, [], [],
            time_to_effect_s=0.0, op_cost=0.0, energy_cost=0.0, order=90),
        Countermeasure(
            "block_flow", "Block the HMI -> plant Modbus flow at the boundary",
            "Network Traffic Filtering", c["firewall"],
            # Inserted at the top: the ESTABLISHED,RELATED accept comes first in
            # the standing ruleset and would keep an open session alive.
            apply=[f"iptables -I FORWARD 1 {flow} -j DROP",
                   f"conntrack -D {flow} 2>/dev/null || true"],
            revert=[f"iptables -D FORWARD {flow} -j DROP"],
            # Costly: it also cuts the operator's legitimate HMI control.
            prevents=["pivot"] + ot_leaves, time_to_effect_s=0.5,
            op_cost=0.5, energy_cost=0.01, order=10),
        Countermeasure(
            "isolate_hmi", "Disconnect the HMI host from the network",
            "Network Isolation", c["hmi"],
            apply=["ip link set eth0 down"],
            revert=["ip link set eth0 up",
                    f"ip route add default via {c['gateway_hmi']} dev eth0"],
            prevents=["it_access", "it_exec", "pivot"] + ot_leaves,
            time_to_effect_s=0.5, op_cost=0.8, energy_cost=0.01,
            requires_approval=True, order=20),
        Countermeasure(
            "force_auto", "Return control authority to the PLC and restore the nominal "
            "DG setpoint (local override)",
            "Restore Configuration", c["engine"],
            # Mode first, then the setpoint, over one connection: without the
            # setpoint the PLC walks down from the hijacked value 2 kW per cycle.
            apply=[f"python3 ot_write.py 127.0.0.1 {port} "
                   f"{reg.HR_CTRL_MODE}={reg.CTRL_AUTO} "
                   f"{reg.HR_DG_SETPOINT}={reg.encode(reg.DG_NOMINAL_KW, DG_SCALE)}"],
            revert=[], restores=["mode_hijack", "setpoint_oor"],
            time_to_effect_s=1.0, op_cost=0.1, energy_cost=0.02, order=30),
        Countermeasure(
            "restore_breaker", "Re-close the feeder breaker (local override)",
            "Restore Configuration", c["engine"],
            apply=[f"python3 ot_write.py 127.0.0.1 {port} {reg.HR_SWITCH_CMD}=0"],
            revert=[], restores=["breaker_open"],
            time_to_effect_s=1.0, op_cost=0.1, energy_cost=0.02, order=40),
    ]
