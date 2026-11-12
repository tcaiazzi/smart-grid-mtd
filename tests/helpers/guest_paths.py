"""Where guest modules live on the host, for the tests that emulate a container.

Guest agents are flat modules: inside a container they sit together at "/" and
import each other bare (``from ot_registers import ...``). A test that exercises
one has to reproduce that, by putting the directories that hold them on
``sys.path`` — or on a subprocess's ``PYTHONPATH``.

The directories are named here once, and the ten test modules that need them
import them from here: moving a plane is a change to this file, not ten edits
with ten chances to miss one.
"""

from tests.helpers import REPO_ROOT

PLANES = REPO_ROOT / "cyberrange" / "planes"

#: Plane roots — the "dual" modules (rl_policy, delivery_detector,
#: ot_registers) live here and are imported both flat (guest) and as a package.
DEFENSE = PLANES / "defense"
ATTACK = PLANES / "attack"
TRAFFIC = PLANES / "traffic"

#: Guest-only agents.
DEFENSE_AGENTS = DEFENSE / "agents"
ATTACK_AGENTS = ATTACK / "agents"
TRAFFIC_AGENTS = TRAFFIC / "agents"

#: Node tooling: software of the lab's nodes, outside the platform package.
NODES = REPO_ROOT / "nodes"
WAZUH_AGENT = NODES / "wazuh" / "agent"
#: SOC node: the analytics (soc_analytics) and the SOAR modules it imports.
#: ot_registers rides along in DEFENSE (a flat dual-use module).
SOC = NODES / "soc"


def add(*directories):
    """Put ``directories`` at the front of sys.path, as a container's root is."""
    import sys

    for directory in directories:
        entry = str(directory)
        if entry in sys.path:
            sys.path.remove(entry)
        sys.path.insert(0, entry)


def pythonpath(*directories, base=None):
    """``PYTHONPATH`` value for a subprocess that runs a guest module."""
    import os

    parts = [str(d) for d in directories]
    if base:
        parts.append(base)
    return os.pathsep.join(p for p in parts if p)
