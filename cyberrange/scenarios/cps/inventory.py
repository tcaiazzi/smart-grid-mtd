"""inventory.py — what the SOC is told about the lab it watches.

The SOC node builds its knowledge graph itself (nodes/soc/soar_kg.py); the one
thing it cannot discover is the network it is responsible for. This is that
description, derived from the scenario's topology: hosts with their roles,
interfaces and addresses, the services, the boundary firewall's ruleset. It is
configuration handed to a node — the platform decides nothing with it.
"""

from cyberrange.scenarios.cps import topology as T

BOUNDARY = "firewall"
PLANT_SERVICE = ("engine", "modbus")


def inventory(args=None, rules=None) -> dict:
    """The lab as the SOC's inventory (JSON-serialisable). ``rules`` replaces the
    boundary ruleset, for asking what the graph would be without one of them."""
    topo = T.topology(args if args is not None else T.default_args())
    return {
        "name": topo.name,
        "hosts": [
            {
                "name": n.name,
                "role": n.role,
                "image": topo.image_of(n),
                "ifaces": [
                    {"name": f"eth{i}", "zone": f.link, "cidr": f.cidr}
                    for i, f in enumerate(n.ifaces)
                ],
            }
            for n in topo.nodes
        ],
        "services": {host: [list(s) for s in svcs] for host, svcs in T.services().items()},
        "boundary": {
            "host": BOUNDARY,
            "rules": list(T.firewall_rules() if rules is None else rules),
        },
        "plant_service": list(PLANT_SERVICE),
    }
