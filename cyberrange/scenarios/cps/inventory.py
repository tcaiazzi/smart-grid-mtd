"""inventory.py — what the SOC is told about the lab it watches.

The SOC node builds its knowledge graph itself (nodes/soc/soar_kg.py); the one
thing it cannot discover is the network it is responsible for. This is that
description, derived from the run's LabSpec: hosts with their roles,
interfaces and addresses, the services, the boundary firewall's ruleset. It is
configuration handed to a node — the platform decides nothing with it.

The nodes a scenario adds next to the lab (the SOC's own tooling in cps-soc)
are not in the spec, so they are not in the inventory: the SOC protects the
plant and the hosts around it, not itself.
"""

from cyberrange.planes.defense import ot_registers as reg
from cyberrange.scenarios.cps import topology as T


def inventory(spec=None, rules=None, plant=None) -> dict:
    """The lab ``spec`` (default: the default lab) and its ``plant`` (default:
    the default plant) as the SOC's inventory (JSON-serialisable). ``rules``
    replaces the boundary ruleset, for asking what the graph would be without
    one of them."""
    spec = spec or T.DEFAULT
    # One engine serves the whole plant, a Modbus unit per feeder: a lab with
    # several engine hosts gives the graph the first one's service.
    engine = spec.with_role("plant")[0]
    return {
        "name": spec.name,
        "hosts": [
            {
                "name": h.name,
                "role": h.role,
                "image": h.image or T.IMAGE,
                "ifaces": [
                    {
                        "name": f"eth{i}",
                        "zone": n.zone,
                        "cidr": None if n.passive else spec.cidr_of(n),
                    }
                    for i, n in enumerate(h.nics)
                ],
                **({"unit": h.unit} if h.unit is not None else {}),
            }
            for h in spec.hosts
        ],
        "services": {host: [list(s) for s in svcs] for host, svcs in T.services(spec).items()},
        "boundary": {
            "host": spec.boundary,
            "rules": list(spec.boundary_rules() if rules is None else rules),
        },
        "plant_service": [engine.name, engine.services[0].name],
        "plant": reg.plant(plant),
    }
