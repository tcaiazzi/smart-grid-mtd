"""Where guest modules live on the host, for the tests that emulate a container.

Guest agents are flat modules: inside a container they sit together at "/" and
import each other bare (``from ot_registers import ...``). A test that exercises
one has to reproduce that, by putting the directories that hold them on
``sys.path`` — or on a subprocess's ``PYTHONPATH``.

Ten test modules used to spell those directories out themselves, which meant a
plane could not move without ten edits and ten chances to miss one. They are
named here once instead; moving a plane is a change to this file.
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
