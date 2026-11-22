#!/usr/bin/env python3
"""belief_tree.py — turn what recon found into an attack tree the planner reads.

The attacker does not receive the defender's tree; it builds its own *belief*
from reconnaissance. Recon's findings become an inventory of the lab as the
attacker knows it — the HMI it got a foothold on, the engine it found behind
it, the registers it read, and a boundary it infers from the HMI talking to the
engine — and the tree is derived from that inventory by the same generator the
SOC runs on its full one (attack_graph.py). What the attacker never saw is not
in its tree, or not feasible: tree fidelity scores the difference.

Copied flat onto the attacker node with recon.py and red_recon_agent.py (see the
scenario's guest_files.py). Stdlib + networkx (through soar_kg).
"""

import ipaddress

import attack_graph
import ot_registers as reg
import soar_kg as kgmod

GATEWAY = "gateway"  # the boundary the attacker infers, not one it saw
WORKSTATION = "ews"  # a host found next to the engine that is not one of the plant's


def _net(ip):
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _iface(name, ip, host=None):
    """An interface on ``ip``'s /24 (the zone is named by its network); with
    ``host``, at that host number of it rather than at ``ip``."""
    net = ipaddress.ip_network(_net(ip))
    addr = ip if host is None else str(net.network_address + host)
    return {"name": name, "zone": _net(ip), "cidr": f"{addr}/{net.prefixlen}"}


def inventory_of(findings):
    """The lab as recon ``findings`` describe it:

        {"foothold": {"ip","port"} | None,   # an HTTP host found on the IT scan
         "ot": {"engine_ip","modbus_ok","modbus_port","registers": {addr: raw},
                "workstation_ip"} | {}}

    A register is believed to exist when it was read, or — the engine answering
    Modbus without an enumeration — from the known plant contract. A
    workstation is a host found on the engine's own network that is none of
    the plant's devices: one that could write to the engine unasked."""
    foothold = findings.get("foothold")
    ot = findings.get("ot") or {}
    hosts, services, rules, plant_service, known = [], {}, [], None, None
    if foothold:
        hosts.append({"name": "hmi", "role": "hmi", "ifaces": [_iface("eth0", foothold["ip"])]})
        services["hmi"] = [["web", "tcp", int(foothold["port"]), "http"]]
    engine = ot.get("engine_ip")
    if engine:
        port = int(ot.get("modbus_port") or reg.MODBUS_PORT)
        hosts.append({"name": "engine", "role": "plant", "ifaces": [_iface("eth0", engine)]})
        services["engine"] = [["modbus", "tcp", port, "modbus"]]
        plant_service = ["engine", "modbus"]
        known = sorted(int(a) for a in (ot.get("registers") or {}))
        if ot.get("modbus_ok") and not known:
            known = sorted(reg.ACTUATOR_REGISTERS)
        if ot.get("workstation_ip"):
            station = _iface("eth0", ot["workstation_ip"])
            hosts.append({"name": WORKSTATION, "role": "engineering", "ifaces": [station]})
        if foothold:
            # The HMI talks to the engine on another network: something forwards
            # that flow, and — as far as the attacker knows — that flow only.
            hosts.append(
                {
                    "name": GATEWAY,
                    "role": kgmod.BOUNDARY_ROLE,
                    "ifaces": [_iface("eth0", foothold["ip"], 1), _iface("eth1", engine, 1)],
                }
            )
            flow = f"-s {foothold['ip']} -d {engine} -p tcp --dport {port}"
            rules = ["iptables -P FORWARD DROP", f"iptables -A FORWARD {flow} -j ACCEPT"]
    return {
        "name": "belief",
        "hosts": hosts,
        "services": services,
        "boundary": {"host": GATEWAY if rules else None, "rules": rules},
        "plant_service": plant_service,
        "known_registers": known,
    }


def build(findings):
    """The belief attack tree (a tree document, as tree_doc reads it) from recon
    ``findings``: every node says whether it is feasible on what was found."""
    g = kgmod.build_kg(inventory_of(findings))
    return attack_graph.attack_tree(g).to_dict(g)
