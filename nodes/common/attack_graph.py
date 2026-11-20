#!/usr/bin/env python3
"""attack_graph.py — the attack tree of a CPS lab and the responses to it,
generated from the knowledge graph.

Nobody writes a lab's tree. The steps are data (techniques.py) and the graph
says where they apply:

    a way in through every host whose role may command the plant and that
        serves an application (the HMI): access, execution, its sanctioned flow;
    a direct way from the hosts without a Modbus role that stand on the plant's
        link (the engineering workstation): a foothold, then a write or a
        position between the PLC and the plant;
    on every way, the actions on every feeder whose registers they write.

A step recurring in several places keeps its kind (``Node.kind``) and takes
an id qualified by where it is (``breaker_open@hmia:u2``); a lab where it occurs
once keeps the bare kind as id, so the tree of the lab every scenario runs is
the one its consumers know. Preconditions are reachability on the graph; so is
what each step ``uses``, which is how a response's effect on the graph tells
which steps it prevents.

Copied flat onto the SOC node and onto the attacker (see the scenarios'
guest_files.py); stdlib + networkx (through soar_kg).
"""

import ot_registers as reg
import soar_kg as kgmod
import techniques as tech
from soar_trees import AND, DISPATCH_S, LEAF, OR, Countermeasure, Node
from soar_trees import charged, index, prerequisites

# Roles that may legitimately talk Modbus to the plant (the plant contract).
MODBUS_ROLES = set(reg.ROLE_POLICY)
DG_SCALE = reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1]


# ── the graph, as the tree needs it ──────────────────────────────────────────
def _names(g, role):
    return [g.nodes[h]["name"] for h in kgmod.hosts(g) if g.nodes[h]["role"] == role]


def _primary(g, host):
    """(address, zone) of ``host``'s primary address, or (None, None)."""
    found = kgmod.addresses(g, host)
    return found[0] if found else (None, None)


def _on_zone(g, host, zone):
    return next((a for a, z in kgmod.addresses(g, host) if z == zone), None)


class Plant:
    """The plant's Modbus service and where it stands, or nothing known."""

    def __init__(self, g):
        svc = kgmod.plant_service(g)
        self.known = svc is not None
        self.host = svc["host"] if svc else None
        self.svc = f"svc:{svc['host']}/{svc['name']}" if svc else None
        self.port = svc["port"] if svc else None
        self.ip, self.zone = _primary(g, self.host) if svc else (None, None)

    def reached_by(self, host):
        """graph -> whether ``host`` can open a Modbus session to the plant."""
        return lambda gg: self.known and kgmod.reachable(gg, host, self.host, self.port)


def _qualify(kind, *where):
    """The id of a step: its kind, with the places it recurs in."""
    where = [w for w in where if w]
    return f"{kind}@{':'.join(where)}" if where else kind


def _node(t, id_, who=None, **kw):
    fields = {k: v for k, v in t.items() if k not in ("kind", "label", "writes", "reads")}
    label = t["label"].format(who=who) if who else t["label"]
    return Node(id_, label, kind=t["kind"], **{**fields, **kw})


def _who(g, host):
    return tech.ROLE_LABEL.get(g.nodes[f"host:{host}"]["role"], host)


# ── the tree ─────────────────────────────────────────────────────────────────
def ways_in(g):
    """The hosts a way in goes through: a Modbus role, and a service to get in by."""
    return [
        g.nodes[h]["name"]
        for h in kgmod.hosts(g)
        if g.nodes[h]["role"] in MODBUS_ROLES and kgmod.services_of(g, g.nodes[h]["name"])
    ]


def _impacts(g, plant, uses, where):
    """The actions on the plant, for every feeder whose registers they write."""
    feeders = kgmod.feeders(g)
    by_name = {}
    for n, d in g.nodes(data=True):
        if d.get("type") == "register" and d["kind"] == "holding":
            by_name[(d["feeder"], d["name"])] = n
    out = []
    for feeder in feeders:
        for t in tech.IMPACTS:
            targets = [by_name.get((feeder, name)) for name in t["writes"]]
            if None in targets:
                continue
            qual = f"u{feeder}" if len(feeders) > 1 else None
            out.append(_node(t, _qualify(t["kind"], where, qual), targets=targets, uses=uses))
    return out


def _attackers(g):
    return _names(g, "it-host")


def attack_tree(g):
    """The attack tree of the lab ``g`` describes."""
    plant = Plant(g)
    boundary = (_names(g, kgmod.BOUNDARY_ROLE) or [None])[0]
    hosts_in = ways_in(g)
    attackers = _attackers(g)
    children = []
    for host in hosts_in:
        where = host if len(hosts_in) > 1 else None
        who = _who(g, host)
        svc = kgmod.services_of(g, host)[0]
        port = g.nodes[svc]["port"]
        reaches_plant = plant.reached_by(host)

        def got_in(gg, host=host, port=port):
            # Where the attacker stands: a host the lab does not trust.
            return not attackers or any(kgmod.reachable(gg, a, host, port) for a in attackers)

        ip = _primary(g, host)[0]
        allowing = [
            r["id"]
            for r in (kgmod.flow_rules(g, boundary) if boundary else [])
            if r["action"] == "ACCEPT"
            and plant.known
            and kgmod._rule_matches(r, ip, plant.ip, plant.port, "tcp")
        ]
        steps = tech.ACCESS_STEPS
        access, execute, pivot = (
            _node(steps[0], _qualify("it_access", where), who, targets=[svc], uses=got_in),
            _node(steps[1], _qualify("it_exec", where), who, targets=[f"host:{host}"], uses=got_in),
            _node(
                steps[2],
                _qualify("pivot", where),
                who,
                targets=([plant.svc] if plant.known else []) + allowing,
                precondition=reaches_plant,
                uses=reaches_plant,
            ),
        )
        action = _node(
            tech.OT_ACTION,
            _qualify("ot_action", where),
            gate=OR,
            children=_impacts(g, plant, reaches_plant, where),
        )
        label = tech.VIA["label"].format(who=who) if len(hosts_in) == 1 else f"Through {host}"
        children.append(
            Node(
                f"via_{host}",
                label,
                AND,
                kind=tech.VIA["kind"],
                children=[access, execute, pivot, action],
            )
        )

    def unknown_writer(gg):
        # Any host outside the Modbus roles (and not the boundary device) that
        # can reach the plant: one that stands on the plant's own link.
        if not plant.known:
            return False
        for h in kgmod.hosts(gg):
            d = gg.nodes[h]
            if d["role"] in MODBUS_ROLES | {kgmod.BOUNDARY_ROLE, "plant"}:
                continue
            if kgmod.reachable(gg, d["name"], plant.host, plant.port):
                return True
        return False

    feeder = (kgmod.feeders(g) or [None])[0]
    reads = [kgmod.reg_id(feeder, "ir", a) for a, spec in reg.SENSOR_REGISTERS.items()
             if spec[0] in tech.FDI["reads"]] if feeder is not None else []  # fmt: skip
    plant_svc = [plant.svc] if plant.known else []
    direct = Node(
        "direct_ot",
        tech.DIRECT["label"],
        AND,
        kind=tech.DIRECT["kind"],
        children=[
            _node(tech.FOOTHOLD, "ot_foothold", precondition=unknown_writer),
            _node(
                tech.DIRECT_ACTION,
                "ot_direct_action",
                gate=OR,
                children=[
                    _node(
                        tech.WRITE_UNKNOWN,
                        "ot_write_unknown",
                        targets=plant_svc,
                        uses=unknown_writer,
                    ),
                    _node(
                        tech.VIA_AITM,
                        "via_aitm",
                        gate=AND,
                        children=[
                            _node(tech.AITM, "ot_aitm", targets=plant_svc, uses=unknown_writer),
                            _node(tech.FDI, "meas_fdi", targets=reads, uses=unknown_writer),
                        ],
                    ),
                ],
            ),
        ],
    )
    return Node(
        "impact", tech.ROOT["label"], OR, kind=tech.ROOT["kind"], children=[*children, direct]
    )


# ── the responses ────────────────────────────────────────────────────────────
def prevented(root, g, effect):
    """The leaves a response with ``effect`` on the graph stops: those that, or
    whose prerequisites, use something of ``g`` the effect takes away."""
    after = kgmod.with_effects(g, effect)
    idx = index(root)

    def cut(n):
        return n.uses is not None and n.uses(g) and not n.uses(after)

    return [
        n.id
        for n in root.walk()
        if n.gate == LEAF and (cut(n) or any(cut(idx[p]) for p in prerequisites(root, n.id)))
    ]


def _of_kind(root, kinds, under=None):
    """Ids of the nodes of ``kinds`` (in that order), within ``under``'s subtree."""
    top = index(root)[under] if under else root
    nodes = list(top.walk())
    return [n.id for k in kinds for n in nodes if n.kind == k]


def _from_step(root, path, first_kind):
    """The leaves of ``path`` from the step of ``first_kind`` on, in order."""
    leaves = [n for n in index(root)[path].walk() if n.gate == LEAF]
    kinds = [n.kind for n in leaves]
    return [n.id for n in leaves[kinds.index(first_kind) :]] if first_kind in kinds else []


def countermeasures(g, it=False):
    """The responses the lab can carry out, with their commands. The IT-side
    ones (kill_proc_tree, block_web_src) only with ``it``, i.e. when the IT
    sensor runs — otherwise the early steps they answer are not observed and the
    response has no justification to use them.

    ``time_to_effect_s`` is DISPATCH_S plus what the countermeasure itself
    takes, where that was measured to be more than the dispatch hides: the
    plant coming back in band after a write to it, the seconds repair_arp
    spends resolving and sending."""
    root = attack_tree(g)
    plant = Plant(g)
    boundary = (_names(g, kgmod.BOUNDARY_ROLE) or [None])[0]
    hosts_in = ways_in(g)
    feeders = kgmod.feeders(g)
    cms = [
        Countermeasure(
            "notify",
            "Alert the operator, no automatic action",
            None,
            None,
            [],
            [],
            time_to_effect_s=0.0,
            op_cost=0.0,
            energy_cost=0.0,
            order=90,
            kind="notify",
        )
    ]
    if not plant.known or boundary is None:
        return charged(g, cms)
    port = plant.port
    for host in hosts_in:
        where = host if len(hosts_in) > 1 else None
        who = _who(g, host)
        ip, zone = _primary(g, host)
        nic = g.nodes[f"ip:{ip}"]["iface"]
        gateway = _on_zone(g, boundary, zone)
        flow = f"-s {ip} -d {plant.ip} -p tcp --dport {port}"
        drop = [[kgmod.DROP, boundary, ip, plant.ip, port]]
        detach = [[kgmod.DETACH, host, nic]]
        cms += [
            Countermeasure(
                _qualify("block_flow", where),
                f"Block the {who} -> plant Modbus flow at the boundary",
                "Network Traffic Filtering",
                boundary,
                # Inserted at the top: the ESTABLISHED,RELATED accept comes first
                # in the standing ruleset and would keep an open session alive.
                apply=[
                    f"iptables -I FORWARD 1 {flow} -j DROP",
                    f"conntrack -D {flow} 2>/dev/null || true",
                ],
                revert=[f"iptables -D FORWARD {flow} -j DROP"],
                # Costly: it also cuts the operator's legitimate control.
                effect=drop,
                prevents=prevented(root, g, drop),
                time_to_effect_s=DISPATCH_S,
                energy_cost=0.01,
                order=10,
                kind="block_flow",
            ),
            Countermeasure(
                f"isolate_{host}",
                f"Disconnect the {who} host from the network",
                "Network Isolation",
                host,
                apply=[f"ip link set {nic} down"],
                revert=[f"ip link set {nic} up", f"ip route add default via {gateway} dev {nic}"],
                effect=detach,
                prevents=prevented(root, g, detach),
                time_to_effect_s=DISPATCH_S,
                energy_cost=0.01,
                requires_approval=g.nodes[f"host:{host}"]["role"] in tech.OPERATOR_ROLES,
                order=20,
                kind="isolate_way",
            ),
        ]
    responder = _on_zone(g, boundary, plant.zone)
    plant_cfg = g.graph.get("plant") or reg.plant()
    for feeder in feeders:
        qual = f"u{feeder}" if len(feeders) > 1 else None
        unit = f" --unit={feeder}" if feeder != reg.UNIT_ID else ""
        nominal = reg.feeder(plant_cfg, feeder)["dg_kw"]
        write = f"python3 ot_write.py {plant.ip} {port}{unit}"
        cms += [
            Countermeasure(
                _qualify("force_auto", qual),
                "Return control authority to the PLC and restore the nominal "
                "DG setpoint (written by the boundary device)",
                "Restore Configuration",
                boundary,
                # From the boundary device, which already stands on the OT link:
                # the plant needs no agent and no new path is opened towards it.
                # The sensor knows this writer as the responder role. Mode first,
                # then the setpoint, over one connection: without the setpoint
                # the PLC walks down from the hijacked value 2 kW per cycle.
                apply=[
                    f"{write} {reg.HR_CTRL_MODE}={reg.CTRL_AUTO} "
                    f"{reg.HR_DG_SETPOINT}={reg.encode(nominal, DG_SCALE)}"
                ],
                revert=[],
                restores=_restored(root, "force_auto", feeder, len(feeders) > 1),
                time_to_effect_s=DISPATCH_S + 0.35,
                op_cost=0.1,
                energy_cost=0.02,
                order=30,
                kind="force_auto",
            ),
            Countermeasure(
                _qualify("restore_breaker", qual),
                "Re-close the feeder breaker (written by the boundary device)",
                "Restore Configuration",
                boundary,
                apply=[f"{write} {reg.HR_SWITCH_CMD}=0"],
                revert=[],
                restores=_restored(root, "restore_breaker", feeder, len(feeders) > 1),
                time_to_effect_s=DISPATCH_S + 0.2,
                op_cost=0.1,
                energy_cost=0.02,
                order=40,
                kind="restore_breaker",
            ),
        ]
    # The hosts of the direct way: off the plant's link, and the addresses the
    # PLC and the plant were lied to about told again.
    direct = [
        g.nodes[h]["name"]
        for h in kgmod.hosts(g)
        if g.nodes[h]["role"] not in MODBUS_ROLES | {kgmod.BOUNDARY_ROLE, "plant"}
        and _on_zone(g, g.nodes[h]["name"], plant.zone)
    ]
    for host in direct:
        nic = g.nodes[f"ip:{_on_zone(g, host, plant.zone)}"]["iface"]
        detach = [[kgmod.DETACH, host, nic]]
        cms.append(
            Countermeasure(
                f"isolate_{host}",
                f"Take the {_who(g, host)} off the OT link",
                "Network Isolation",
                host,
                apply=[f"ip link set {nic} down"],
                revert=[f"ip link set {nic} up"],
                effect=detach,
                prevents=prevented(root, g, detach),
                restores=[],
                time_to_effect_s=DISPATCH_S,
                energy_cost=0.01,
                order=15,
                kind="isolate_ot_host",
            )
        )
    plcs = [p for p in _names(g, "plc") if _on_zone(g, p, plant.zone)]
    if direct and plcs:
        for plc in plcs:
            cms.append(_repair_arp(g, plc, plant, boundary, responder, len(plcs) > 1, root))
    if not it:
        return charged(g, cms)
    # IT-side countermeasures (need the IT sensor to observe the early steps).
    attackers = _attackers(g)
    attacker_ip = _primary(g, attackers[0])[0] if attackers else None
    for host in hosts_in:
        where = host if len(hosts_in) > 1 else None
        path = f"via_{host}"
        svc_port = g.nodes[kgmod.services_of(g, host)[0]]["port"]
        block = f"-s {attacker_ip} -p tcp --dport {svc_port} -j DROP"
        cms += [
            Countermeasure(
                _qualify("kill_proc_tree", where),
                "Terminate the processes the web app spawned (the RCE)",
                "Process Termination",
                host,
                # Depth-first over the descendants: the injected command is
                # usually a shell whose own child is the payload, which
                # `pkill -P` alone misses.
                apply=[
                    "kt() { for c in $(pgrep -P $1); do kt $c; kill -9 $c 2>/dev/null; done; }; "
                    f"for p in $(pgrep -f {tech.ACCESS_PROCESS}); do kt $p; done; true"
                ],
                revert=[],  # killing the foothold changes no persistent state
                # The graph has no processes: what it stops is declared, from
                # the execution on.
                prevents=_from_step(root, path, "it_exec"),
                time_to_effect_s=DISPATCH_S,
                op_cost=0.15,
                energy_cost=0.01,
                order=5,
                kind="kill_proc_tree",
            ),
            Countermeasure(
                _qualify("block_web_src", where),
                "Block the attacking source at the diagnostics app",
                "Inbound Traffic Filtering",
                host,
                apply=[f"iptables -I INPUT 1 {block}"] if attacker_ip else [],
                revert=[f"iptables -D INPUT {block}"] if attacker_ip else [],
                # Nor host firewalls: from the access on.
                prevents=_from_step(root, path, "it_access"),
                time_to_effect_s=DISPATCH_S,
                op_cost=0.2,
                energy_cost=0.01,
                order=6,
                kind="block_web_src",
            ),
        ]
    return charged(g, cms)


def _restored(root, response, feeder, qualified):
    """The impact nodes ``response`` undoes on ``feeder``, every way in."""

    def on_feeder(n):
        # The feeder is the last qualifier of a recurring step's id.
        return not qualified or n.id.partition("@")[2].split(":")[-1] == f"u{feeder}"

    return [
        n.id for k in tech.RESTORES[response] for n in root.walk() if n.kind == k and on_feeder(n)
    ]


def _repair_arp(g, plc, plant, boundary, responder_ip, qualified, root):
    plc_ip = _primary(g, plc)[0]
    iface = g.nodes[f"ip:{responder_ip}"]["iface"]
    # scapy comes with the node image. The boundary device was never lied to,
    # so the addresses it resolves are the true ones.
    heal = (
        "from scapy.all import ARP, Ether, conf, getmacbyip, sendp; conf.verb = 0; "
        f"a, b = '{plc_ip}', '{plant.ip}'; ma, mb = getmacbyip(a), getmacbyip(b); "
        "p = [Ether(dst=ma) / ARP(op=2, psrc=b, hwsrc=mb, pdst=a, hwdst=ma), "
        "Ether(dst=mb) / ARP(op=2, psrc=a, hwsrc=ma, pdst=b, hwdst=mb)]; "
        f"sendp(p, iface='{iface}', count=3, inter=0.2)"
    )
    return Countermeasure(
        _qualify("repair_arp", plc if qualified else None),
        "Tell the PLC and the plant each other's true address again (sent by the boundary device)",
        "Restore Configuration",
        boundary,
        # After the isolation (order): while the host in the middle is on the
        # link it renews its claim every second. Without this the two keep
        # sending to a host that is gone until their caches expire, and the PLC
        # regulates nothing for most of a minute.
        apply=[f'python3 -c "{heal}"'],
        revert=[],
        restores=_of_kind(root, tech.RESTORES["repair_arp"]),
        time_to_effect_s=DISPATCH_S + 2.3,
        op_cost=0.05,
        energy_cost=0.01,
        order=16,
        kind="repair_arp",
    )
