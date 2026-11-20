"""Host -> guest file manifest of the MQTT smart-grid scenario.

One entry per file a node receives: ``(host_path, guest_path)``, host paths
relative to the repo root. The staging mechanism and the rule that guest paths
are a contract (while host paths are free to move) are documented once, in
``cyberrange/core/topology.py``.
"""

# Copied onto every semp machine, all variants (baseline and MTD alike): the CA
# always runs to bootstrap the mutual-TLS certs, and the coordinator script is
# staged even when --no-mtd never starts it, since the RL layout below reuses it.
# mtd_crypto.py / mtd_wire.py back both cert_authority.py (QKD bootstrap) and
# mtd_coordinator.py (MTD control channel), so both ship here unconditionally.
# Every coordinator records telemetry (mtd_telemetry.py) priced with
# rl_policy.KNOB_COST, and can serve it live (mtd_dashboard.py + its page) and
# score it with the blackhole detector (delivery_detector.py, numpy-only).
SEMP_FILES = [
    ("cyberrange/planes/defense/qkd/cert_authority.py", "/cert_authority.py"),
    ("cyberrange/planes/defense/agents/mtd_coordinator.py", "/mtd_coordinator.py"),
    ("cyberrange/planes/defense/agents/mtd_crypto.py", "/mtd_crypto.py"),
    ("cyberrange/planes/defense/agents/mtd_wire.py", "/mtd_wire.py"),
    ("cyberrange/planes/defense/agents/mtd_telemetry.py", "/mtd_telemetry.py"),
    ("cyberrange/planes/defense/agents/mtd_dashboard.py", "/mtd_dashboard.py"),
    ("cyberrange/planes/defense/agents/mtd_dashboard.html", "/mtd_dashboard.html"),
    ("cyberrange/planes/defense/rl_policy.py", "/rl_policy.py"),
    ("cyberrange/planes/defense/delivery_detector.py", "/delivery_detector.py"),
]

# Copied onto semp only when an RL policy is selected (`--rl-policy`, MTD variant
# only). mtd_rl_coordinator.py subclasses SEMPCoordinator from mtd_coordinator.py
# above; rl_policy.py, which its decision loop imports, already ships above.
SEMP_RL_FILES = [
    ("cyberrange/planes/defense/agents/mtd_rl_coordinator.py", "/mtd_rl_coordinator.py")
]

# Copied onto every scmc machine, all variants: the QKD cert client always runs,
# and both publishers are staged so the CLI can pick either at exec time.
# mtd_crypto.py / mtd_wire.py back both cert_client.py (QKD bootstrap) and
# mtd_executor.py (MTD control channel), so both ship here unconditionally.
# microgrid_sim.py backs the pymgrid physics shared by both publishers.
SCMC_FILES = [
    ("cyberrange/planes/defense/agents/mtd_executor.py", "/mtd_executor.py"),
    ("cyberrange/planes/traffic/agents/simple_client.py", "/simple_client.py"),
    ("cyberrange/planes/defense/qkd/cert_client.py", "/cert_client.py"),
    ("cyberrange/planes/defense/agents/mtd_crypto.py", "/mtd_crypto.py"),
    ("cyberrange/planes/defense/agents/mtd_wire.py", "/mtd_wire.py"),
    ("cyberrange/planes/traffic/agents/microgrid_sim.py", "/microgrid_sim.py"),
]

# Copied onto every router machine.
ROUTER_FILES = [("cyberrange/planes/traffic/replay_background.sh", "/replay_background.sh")]
