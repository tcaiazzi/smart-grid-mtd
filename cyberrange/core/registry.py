"""registry.py — every scenario the platform knows, by name.

Scenario modules are imported lazily so that listing or dry-running one
scenario never imports another's dependencies (torch, pandapower, ...).
"""

import importlib

SCENARIOS = {
    "mqtt-mtd": "cyberrange.scenarios.mqtt_mtd.scenario:MqttMtdScenario",
    "cps": "cyberrange.scenarios.cps.scenario:CpsScenario",
}


def get(name):
    """A fresh Scenario instance for ``name``."""
    try:
        target = SCENARIOS[name]
    except KeyError:
        raise KeyError(f"unknown scenario {name!r}; known: {sorted(SCENARIOS)}") from None
    module, cls = target.split(":")
    return getattr(importlib.import_module(module), cls)()


def names():
    return sorted(SCENARIOS)
