"""Host -> guest file manifest of the cyber-physical (OT/Modbus) scenario.

One entry per file a node receives: ``(host_path, guest_path)``, host paths
relative to the repo root. The staging mechanism and the rule that guest paths
are a contract (while host paths are free to move) are documented once, in
``cyberrange/core/topology.py``.

These nodes ride on the kathara/cps image (docker/cps/Dockerfile), separate
from the MQTT lab. ot_registers.py is the shared "plant contract" copied onto
every node that speaks or inspects Modbus; the DPI sensor stays
stdlib/numpy-only.
"""

# Physical engine node: pandapower twin behind a Modbus/TCP server.
ENGINE_FILES = [
    ("cyberrange/planes/traffic/agents/modbus_engine.py", "/modbus_engine.py"),
    ("cyberrange/planes/traffic/agents/grid_sim.py", "/grid_sim.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
    # Stdlib Modbus writer, reused defensively: the SOAR prototype's local
    # override (back to AUTO, re-close the breaker) writes on 127.0.0.1 here.
    ("cyberrange/planes/attack/agents/ot_write.py", "/ot_write.py"),
]

# PLC node: Modbus master / controller (the legitimate industrial traffic).
PLC_FILES = [
    ("cyberrange/planes/traffic/agents/plc_controller.py", "/plc_controller.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
]

# Defense sensor node: passive Modbus-DPI -> findings, served on the mgmt NIC.
SENSOR_FILES = [
    ("cyberrange/planes/defense/agents/ot_sensor.py", "/ot_sensor.py"),
    ("cyberrange/planes/defense/agents/ot_model.py", "/ot_model.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
    ("cyberrange/planes/defense/agents/mtd_telemetry.py", "/mtd_telemetry.py"),
    ("cyberrange/planes/defense/agents/mtd_dashboard.py", "/mtd_dashboard.py"),
    ("cyberrange/planes/defense/agents/mtd_dashboard.html", "/mtd_dashboard.html"),
]

# IT HMI / SCADA host: the ONE IT client the boundary firewall lets reach the
# engine (legitimate polling + operator dispatches), which also runs the
# deliberately-vulnerable diagnostics web app — the attacker's foothold — and the
# raw-stdlib Modbus writer the pivot uses after RCE.
HMI_FILES = [
    ("cyberrange/planes/traffic/agents/hmi_client.py", "/hmi_client.py"),
    ("cyberrange/planes/attack/agents/vuln_app.py", "/vuln_app.py"),
    ("cyberrange/planes/attack/agents/ot_write.py", "/ot_write.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
    # IT-side sensor (--it-telemetry): watches this host so the attacker's early
    # steps are observed, not just inferred. Stdlib + the shared telemetry bus.
    ("cyberrange/planes/defense/agents/it_sensor.py", "/it_sensor.py"),
    ("cyberrange/planes/defense/agents/mtd_telemetry.py", "/mtd_telemetry.py"),
]

# Attacker node: drives the exploit over HTTP against the HMI host.
ATTACKER_CPS_FILES = [
    ("cyberrange/planes/attack/agents/exploit_client.py", "/exploit_client.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
]
