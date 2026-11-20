"""The deploy manifests of every registered scenario, in one place.

Several guardrails need the same answer — "which files does this repo stage
into containers, and under what names?" — and each scenario now declares that
next to its topology. Resolving it through the registry means these checks keep
working when a scenario is added, renamed, or moved, instead of silently
falling back to an empty list (a guardrail that checks nothing).
"""

import importlib
from pathlib import Path

from cyberrange.core import registry


def manifest_modules():
    """{scenario: module} for every registered scenario's guest_files."""
    modules = {}
    for name in registry.names():
        pkg = registry.SCENARIOS[name].split(":")[0].rsplit(".", 1)[0]
        modules[name] = importlib.import_module(f"{pkg}.guest_files")
    return modules


def manifest_entries():
    """[(host_path, guest_path, "<scenario>.<MANIFEST>")] across every scenario.

    Includes the conditional manifests (SEMP_RL_FILES ships only with
    --rl-policy), which rendering a scenario with default arguments never
    reaches.
    """
    entries = []
    for scenario, module in manifest_modules().items():
        for attr in dir(module):
            value = getattr(module, attr)
            if (
                attr.isupper()
                and isinstance(value, list)
                and value
                and all(isinstance(e, tuple) and len(e) == 2 for e in value)
            ):
                entries += [(host, guest, f"{scenario}.{attr}") for host, guest in value]
    return entries


def guest_module_names():
    """Flat module names as they land in a container ("modbus_engine", ...)."""
    return {Path(guest).stem for _host, guest, _m in manifest_entries() if guest.endswith(".py")}
