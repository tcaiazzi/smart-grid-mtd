#!/usr/bin/env python3
"""soar_kg.py — knowledge graph of the lab the SOC watches.

Built from the SOC's inventory (the hosts with their roles, interfaces and
addresses, the services, the boundary firewall's ruleset) and the OT plant
contract (ot_registers.py). The inventory is what a SOC is configured with; the
graph is what it reasons on.

Copied flat onto the SOC node next to soc_analytics.py (see the scenario's
guest_files.py). Stdlib + networkx.

Inventory:
    {"name": lab name,
     "hosts": [{"name", "role", "image", "ifaces": [{"name", "zone", "cidr"|null}]}],
     "services": {host: [[name, proto, port, app], ...]},
     "boundary": {"host": name, "rules": [iptables command, ...]},
     "plant_service": [host, service name]}

Node ids are typed by prefix:
    zone:<name>             collision domain (IT / OT / MGMT)
    host:<name>             machine; attrs image, role
    ip:<addr>               interface address; attrs prefix, iface, host
    svc:<host>/<name>       network service; attrs proto, port, app
    reg:<hr|ir>:<addr>      Modbus register; attrs name, kind, sensitive, lo, hi
    rule:<host>:<n>         forwarding rule; attrs action, src, dst, proto, dport

Edges carry a ``rel`` attribute (and the MultiDiGraph key is the same string):
    host -in_zone-> zone    (iface)       host -has_ip-> ip
    ip -in_zone-> zone                    host -runs-> svc
    svc -exposes-> reg                    host -may_write-> reg   (ROLE_POLICY)
    host -enforces-> rule                 rule -src-> host, rule -dst-> svc

``reachable()`` answers the only question v0 needs: can host A open a
connection to a port on host B, given zones, addresses and the boundary rules.
"""

import ipaddress
import json
import shlex

import networkx as nx

import ot_registers as reg

# Role of the boundary device: the only host allowed to forward between zones.
BOUNDARY_ROLE = "boundary"


# ── Construction ─────────────────────────────────────────────────────────────


def build_kg(inventory):
    """Knowledge graph of the lab described by ``inventory`` (see the module
    docstring). Role names matching ROLE_POLICY get may_write edges to the
    registers that role may write; the plant service exposes the registers."""
    services = inventory.get("services") or {}
    roles = {h["name"]: h.get("role") or "unknown" for h in inventory["hosts"]}
    g = nx.MultiDiGraph(name=inventory.get("name", "lab"))

    for host in sorted(inventory["hosts"], key=lambda h: h["name"]):
        name = host["name"]
        hid = f"host:{name}"
        g.add_node(hid, type="host", name=name, image=host.get("image"), role=roles[name])
        ifaces = sorted(host.get("ifaces") or [], key=lambda i: i["name"])
        for itf in ifaces:
            zid = f"zone:{itf['zone']}"
            if zid not in g:
                g.add_node(zid, type="zone", name=itf["zone"])
            _edge(g, hid, zid, "in_zone", iface=itf["name"])
        # A passive interface has a zone and no address: in the zone, not reachable in it.
        for itf in ifaces:
            if not itf.get("cidr"):
                continue
            addr = ipaddress.ip_interface(itf["cidr"])
            iid = f"ip:{addr.ip}"
            g.add_node(
                iid,
                type="ip",
                addr=str(addr.ip),
                prefix=addr.network.prefixlen,
                network=str(addr.network),
                iface=itf["name"],
                host=name,
            )
            _edge(g, hid, iid, "has_ip")
            _edge(g, iid, f"zone:{itf['zone']}", "in_zone")
        for sname, proto, port, app in services.get(name, []):
            sid = f"svc:{name}/{sname}"
            g.add_node(
                sid, type="service", name=sname, host=name, proto=proto, port=int(port), app=app
            )
            _edge(g, hid, sid, "runs")

    boundary = inventory.get("boundary") or {}
    _add_registers(g, inventory.get("plant_service"))
    _add_role_permissions(g, roles)
    _add_rules(g, boundary.get("host"), boundary.get("rules") or [])
    return g


def _edge(g, u, v, rel, **attrs):
    g.add_edge(u, v, key=rel, rel=rel, **attrs)


def _add_registers(g, plant_service):
    for addr, (name, scale, lo, hi) in reg.ACTUATOR_REGISTERS.items():
        g.add_node(
            f"reg:hr:{addr}",
            type="register",
            kind="holding",
            addr=addr,
            name=name,
            scale=scale,
            lo=lo,
            hi=hi,
            sensitive=addr in reg.SENSITIVE_ACTUATORS,
        )
    for addr, (name, scale, unit) in reg.SENSOR_REGISTERS.items():
        g.add_node(
            f"reg:ir:{addr}",
            type="register",
            kind="input",
            addr=addr,
            name=name,
            scale=scale,
            unit=unit,
            sensitive=False,
        )
    if plant_service:
        sid = f"svc:{plant_service[0]}/{plant_service[1]}"
        if sid in g:
            for n in registers(g):
                _edge(g, sid, n, "exposes")


def _add_role_permissions(g, roles):
    for host, role in roles.items():
        pol = reg.ROLE_POLICY.get(role)
        if not pol or f"host:{host}" not in g:
            continue
        for addr in pol["writes"]:
            _edge(g, f"host:{host}", f"reg:hr:{addr}", "may_write")


def parse_forward_rules(rules):
    """iptables strings -> (default_policy, [rule dict]). Only the FORWARD chain
    matters for crossing the boundary; the stateful ESTABLISHED/RELATED accept
    is a return-path rule, not a new flow, so it is skipped."""
    default, parsed = "ACCEPT", []
    for line in rules:
        tok = shlex.split(line)
        if not tok or tok[0] != "iptables":
            continue
        if "-P" in tok and tok[tok.index("-P") + 1] == "FORWARD":
            default = tok[tok.index("-P") + 2]
            continue
        if "FORWARD" not in tok or "--state" in tok or "-j" not in tok:
            continue

        def opt(flag):
            return tok[tok.index(flag) + 1] if flag in tok else None

        dport = opt("--dport")
        parsed.append(
            {
                "action": opt("-j"),
                "src": opt("-s"),
                "dst": opt("-d"),
                "proto": opt("-p"),
                "dport": int(dport) if dport else None,
            }
        )
    return default, parsed


def _add_rules(g, firewall, fw_rules):
    fid = f"host:{firewall}"
    if not firewall or fid not in g:
        return
    default, rules = parse_forward_rules(fw_rules)
    g.nodes[fid]["role"] = BOUNDARY_ROLE
    g.nodes[fid]["forward_default"] = default
    for n, r in enumerate(rules):
        rid = f"rule:{firewall}:{n}"
        g.add_node(rid, type="flow_rule", order=n, **r)
        _edge(g, fid, rid, "enforces")
        src = host_of_ip(g, r["src"]) if r["src"] else None
        if src:
            _edge(g, rid, f"host:{src}", "src")
        dst = host_of_ip(g, r["dst"]) if r["dst"] else None
        for sid in services_of(g, dst) if dst else []:
            s = g.nodes[sid]
            if (r["dport"] in (None, s["port"])) and (r["proto"] in (None, s["proto"])):
                _edge(g, rid, sid, "dst")


# ── Queries ──────────────────────────────────────────────────────────────────


def _out(g, node, rel):
    return [v for _, v, k in g.out_edges(node, keys=True) if k == rel]


def hosts(g):
    return sorted(n for n, d in g.nodes(data=True) if d["type"] == "host")


def registers(g):
    return sorted(n for n, d in g.nodes(data=True) if d["type"] == "register")


def addresses(g, host):
    """[(addr, zone)] of a host — only zones where it actually has an address."""
    out = []
    for iid in _out(g, f"host:{host}", "has_ip"):
        zones = _out(g, iid, "in_zone")
        out.append((g.nodes[iid]["addr"], g.nodes[zones[0]]["name"] if zones else None))
    return sorted(out)


def host_of_ip(g, addr):
    """Host owning an address (accepts a bare ip or ip/prefix), or None."""
    if addr is None:
        return None
    ip = str(ipaddress.ip_interface(addr).ip)
    node = g.nodes.get(f"ip:{ip}")
    return node["host"] if node else None


def services_of(g, host):
    return sorted(_out(g, f"host:{host}", "runs"))


def service(g, host, port, proto="tcp"):
    for sid in services_of(g, host):
        s = g.nodes[sid]
        if s["port"] == port and s["proto"] == proto:
            return sid
    return None


def flow_rules(g, firewall="firewall"):
    rules = [g.nodes[r] | {"id": r} for r in _out(g, f"host:{firewall}", "enforces")]
    return sorted(rules, key=lambda r: r["order"])


def _rule_matches(r, src_ip, dst_ip, port, proto):
    def ip_ok(spec, ip):
        return spec is None or ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False)

    return (
        ip_ok(r["src"], src_ip)
        and ip_ok(r["dst"], dst_ip)
        and r["dport"] in (None, port)
        and r["proto"] in (None, proto)
    )


def reachable(g, src, dst, port, proto="tcp"):
    """Can host ``src`` open a ``proto`` connection to ``port`` on host ``dst``?

    True when the two hosts have addresses in a common zone (no host firewalls
    are modelled), or when a boundary host with addresses in both zones
    forwards the flow: the first matching FORWARD rule decides, else the
    chain's default policy. The service must exist on ``dst``.
    """
    if service(g, dst, port, proto) is None:
        return False
    s_addrs, d_addrs = addresses(g, src), addresses(g, dst)
    if {z for _, z in s_addrs} & {z for _, z in d_addrs}:
        return True
    for b in hosts(g):
        bd = g.nodes[b]
        if bd.get("role") != BOUNDARY_ROLE:
            continue
        bz = {z for _, z in addresses(g, bd["name"])}
        for s_ip, s_zone in s_addrs:
            for d_ip, d_zone in d_addrs:
                if s_zone not in bz or d_zone not in bz:
                    continue
                verdict = bd.get("forward_default", "ACCEPT")
                for r in flow_rules(g, bd["name"]):
                    if _rule_matches(r, s_ip, d_ip, port, proto):
                        verdict = r["action"]
                        break
                if verdict == "ACCEPT":
                    return True
    return False


# ── Serialization ────────────────────────────────────────────────────────────


def to_json(g):
    return nx.node_link_data(g, edges="links")


def from_json(data):
    return nx.node_link_graph(data, directed=True, multigraph=True, edges="links")


def save(g, path):
    with open(path, "w") as f:
        json.dump(to_json(g), f, indent=1, sort_keys=True)
