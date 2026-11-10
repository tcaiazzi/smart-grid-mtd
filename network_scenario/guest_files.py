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
# Every coordinator records telemetry (mtd_telemetry.py) priced with
# rl_policy.KNOB_COST, and can serve it live (mtd_dashboard.py + its page) and
# score it with the blackhole detector (delivery_detector.py, numpy-only).
SEMP_FILES = [
    ("defense_plane/qkd/cert_authority.py", "/cert_authority.py"),
    ("defense_plane/agents/mtd_coordinator.py", "/mtd_coordinator.py"),
    ("defense_plane/agents/mtd_crypto.py", "/mtd_crypto.py"),
    ("defense_plane/agents/mtd_wire.py", "/mtd_wire.py"),
    ("defense_plane/agents/mtd_telemetry.py", "/mtd_telemetry.py"),
    ("defense_plane/agents/mtd_dashboard.py", "/mtd_dashboard.py"),
    ("defense_plane/agents/mtd_dashboard.html", "/mtd_dashboard.html"),
    ("defense_plane/rl_policy.py", "/rl_policy.py"),
    ("defense_plane/delivery_detector.py", "/delivery_detector.py"),
]

# Copied onto semp only when an RL policy is selected (`--rl-policy`, MTD variant
# only). mtd_rl_coordinator.py subclasses SEMPCoordinator from mtd_coordinator.py
# above; rl_policy.py, which its decision loop imports, already ships above.
SEMP_RL_FILES = [
    ("defense_plane/agents/mtd_rl_coordinator.py", "/mtd_rl_coordinator.py"),
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


# ─────────────────────────────────────────────────────────────────────────────
# Cyber-physical (OT/Modbus) scenario manifests — doc steps 1–4. These ride on
# the kathara/cps image (docker/cps/Dockerfile), separate from the MQTT lab.
# ot_registers.py is the shared "plant contract" copied onto every node that
# speaks or inspects Modbus; the DPI sensor stays stdlib/numpy-only.

# Physical engine node: pandapower twin behind a Modbus/TCP server.
ENGINE_FILES = [
    ("traffic_generator/agents/modbus_engine.py", "/modbus_engine.py"),
    ("traffic_generator/agents/grid_sim.py", "/grid_sim.py"),
    ("defense_plane/ot_registers.py", "/ot_registers.py"),
    # Stdlib Modbus writer, reused defensively: the SOAR prototype's local
    # override (back to AUTO, re-close the breaker) writes on 127.0.0.1 here.
    ("attack_plane/agents/ot_write.py", "/ot_write.py"),
]

# PLC node: Modbus master / controller (the legitimate industrial traffic).
PLC_FILES = [
    ("traffic_generator/agents/plc_controller.py", "/plc_controller.py"),
    ("defense_plane/ot_registers.py", "/ot_registers.py"),
]

# Defense sensor node: passive Modbus-DPI -> findings, served on the mgmt NIC.
SENSOR_FILES = [
    ("defense_plane/agents/ot_sensor.py", "/ot_sensor.py"),
    ("defense_plane/agents/ot_model.py", "/ot_model.py"),
    ("defense_plane/ot_registers.py", "/ot_registers.py"),
    ("defense_plane/agents/mtd_telemetry.py", "/mtd_telemetry.py"),
    ("defense_plane/agents/mtd_dashboard.py", "/mtd_dashboard.py"),
    ("defense_plane/agents/mtd_dashboard.html", "/mtd_dashboard.html"),
]

# IT HMI / SCADA host: the ONE IT client the boundary firewall lets reach the
# engine (legitimate polling + operator dispatches), which also runs the
# deliberately-vulnerable diagnostics web app — the attacker's foothold — and the
# raw-stdlib Modbus writer the pivot uses after RCE.
HMI_FILES = [
    ("traffic_generator/agents/hmi_client.py", "/hmi_client.py"),
    ("attack_plane/agents/vuln_app.py", "/vuln_app.py"),
    ("attack_plane/agents/ot_write.py", "/ot_write.py"),
    ("defense_plane/ot_registers.py", "/ot_registers.py"),
]

# Attacker node: drives the exploit over HTTP against the HMI host.
ATTACKER_CPS_FILES = [
    ("attack_plane/agents/exploit_client.py", "/exploit_client.py"),
    ("defense_plane/ot_registers.py", "/ot_registers.py"),
]
