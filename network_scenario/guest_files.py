"""Declarative host -> guest file manifest for the network scenario.

Every entry here is copied into a Kathara machine via
``Machine.create_file_from_path(host_path, guest_path)`` at lab-build time (see
run_experiment.py). Kathara stages each file into the machine's virtual
filesystem, which is later unpacked at the container's filesystem root "/" —
so every guest path below is written with a leading "/" for clarity, but that
leading slash is a display convention, not a functional requirement: a path
without one (e.g. "mtd_executor.py") lands in exactly the same place, since
the container's default working directory *is* "/".

This is why the files below can be plain, flat modules: the container's CWD is
also the first entry on sys.path for a script run as ``python3 <name>.py``, so
an agent can do a bare ``from mtd_crypto import ...`` as long as mtd_crypto.py
was copied to the same machine. Agent modules cannot use package-relative
imports (there is no package on the guest side), and the module name each file
is copied under is a deployment contract other agents rely on — e.g.
mtd_rl_coordinator.py does ``from rl_policy import ...``, so rl_policy.py must
keep landing as "/rl_policy.py" regardless of where it lives on the host.

tests/test_guest_imports.py replays this manifest into a scratch directory
that mirrors each machine's guest filesystem and imports every module from
there, to catch a missing shared-module copy without a live lab deploy.
"""

# Copied onto every semp machine, all variants (baseline and MTD alike): the CA
# always runs to bootstrap the mutual-TLS certs, and the coordinator script is
# staged even when --no-mtd never starts it, since the RL layout below reuses it.
# mtd_crypto.py / mtd_wire.py back both cert_authority.py (QKD bootstrap) and
# mtd_coordinator.py (MTD control channel), so both ship here unconditionally.
SEMP_FILES = [
    ("defense_plane/qkd/cert_authority.py", "/cert_authority.py"),
    ("defense_plane/agents/mtd_coordinator.py", "/mtd_coordinator.py"),
    ("defense_plane/agents/mtd_crypto.py", "/mtd_crypto.py"),
    ("defense_plane/agents/mtd_wire.py", "/mtd_wire.py"),
]

# Copied onto semp only when an RL policy is selected (`--rl-policy`, MTD variant
# only). mtd_rl_coordinator.py subclasses SEMPCoordinator from mtd_coordinator.py
# above, and both it and the coordinator's decision loop import rl_policy.py.
SEMP_RL_FILES = [
    ("defense_plane/agents/mtd_rl_coordinator.py", "/mtd_rl_coordinator.py"),
    ("defense_plane/rl_policy.py", "/rl_policy.py"),
]

# Copied onto every scmc machine, all variants: the QKD cert client always runs,
# and both publishers are staged so the CLI can pick either at exec time.
# mtd_crypto.py / mtd_wire.py back both cert_client.py (QKD bootstrap) and
# mtd_executor.py (MTD control channel), so both ship here unconditionally.
# microgrid_sim.py backs the pymgrid physics shared by both publishers.
SCMC_FILES = [
    ("defense_plane/agents/mtd_executor.py", "/mtd_executor.py"),
    ("traffic_generator/agents/simple_client.py", "/simple_client.py"),
    ("defense_plane/qkd/cert_client.py", "/cert_client.py"),
    ("defense_plane/agents/mtd_crypto.py", "/mtd_crypto.py"),
    ("defense_plane/agents/mtd_wire.py", "/mtd_wire.py"),
    ("traffic_generator/agents/microgrid_sim.py", "/microgrid_sim.py"),
]

# Copied onto every router machine.
ROUTER_FILES = [
    ("traffic_generator/replay_background.sh", "/replay_background.sh"),
]
