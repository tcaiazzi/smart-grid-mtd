"""The CPS lab as a SOAR knowledge graph.

``planes/defense/soar/kg.py`` knows how to turn *any* declared lab into a graph
(``build_kg(lab, firewall_rules, services, roles, plant_service)``); what it
must not know is which lab. That binding — this scenario's topology, services,
roles and boundary rules — belongs here, on the scenario side of the layering:
a plane that imports a scenario stops being reusable by the next one.
"""

from cyberrange.planes.defense.soar import kg as kgmod
from cyberrange.scenarios.cps import topology as cps


def catalog():
    """Services and roles of the CPS lab."""
    return cps.services(), cps.roles()


def build(lab=None):
    """Knowledge graph of the CPS lab: the deployed ``lab`` when given, else
    the Lab model built from the scenario's topology."""
    if lab is None:
        lab, _m, _s = cps.build_lab()
    services, roles = catalog()
    return kgmod.build_kg(lab, cps.firewall_rules(), services=services, roles=roles,
                          plant_service=("engine", "modbus"))
