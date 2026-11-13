"""Host -> guest file manifest of the cyber-physical (OT/Modbus) scenario.

One entry per file a node receives: ``(host_path, guest_path)``, host paths
relative to the repo root. The staging mechanism and the rule that guest paths
are a contract (while host paths are free to move) are documented once, in
``cyberrange/core/topology.py``.

These nodes ride on the kathara/cps image (docker/cps/Dockerfile), separate
from the MQTT lab. ot_registers.py is the shared "plant contract" copied onto
every node that speaks or inspects Modbus; the DPI sensor stays
stdlib/numpy-only.

What comes from ``nodes/`` is the tooling of the management network (Wazuh
configuration, set-up scripts, the active response): software of the nodes, not
of the platform, which only stages it.
"""

# Hosts on the management network that report to the SOC and run its responses.
WAZUH_AGENT_FILES = [
    ("nodes/wazuh/agent/wazuh-agent-setup.sh", "/wazuh-agent-setup.sh"),
    ("nodes/wazuh/agent/wazuh-agent.conf", "/wazuh-agent.conf"),
    ("nodes/wazuh/agent/cps_response.py", "/cps_response.py"),
]

# SOC node (kathara/soc image): the Wazuh manager with its rules for this lab,
# and the analytics that read its alerts and ask it for the responses.
SOC_FILES = [
    ("nodes/wazuh/manager/wazuh-manager-setup.sh", "/wazuh-manager-setup.sh"),
    ("nodes/wazuh/manager/cps_rules.xml", "/cps_rules.xml"),
    ("nodes/soc/soc_analytics.py", "/soc_analytics.py"),
    ("nodes/soc/soc_operator.py", "/soc_operator.py"),
    ("nodes/soc/soar_kg.py", "/soar_kg.py"),
    ("nodes/soc/soar_trees.py", "/soar_trees.py"),
    ("nodes/soc/soar_mapping.py", "/soar_mapping.py"),
    ("nodes/soc/soar_policy.py", "/soar_policy.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
]

# Physical engine node: pandapower twin behind a Modbus/TCP server.
ENGINE_FILES = [
    ("cyberrange/planes/traffic/agents/modbus_engine.py", "/modbus_engine.py"),
    ("cyberrange/planes/traffic/agents/grid_sim.py", "/grid_sim.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
]

# Boundary firewall: the stdlib Modbus writer, reused defensively. The response
# returns the plant to a safe state (back to AUTO, re-close the breaker) from
# here, over the OT link the firewall already stands on.
FW_FILES = [
    ("cyberrange/planes/attack/agents/ot_write.py", "/ot_write.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
] + WAZUH_AGENT_FILES

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
] + WAZUH_AGENT_FILES

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
] + WAZUH_AGENT_FILES

# Attacker node: drives the exploit over HTTP against the HMI host. The
# autonomous attacker's brain runs here too (red_agent.py with the planner):
# the exploit primitives it drives are already on this node, and the oracle
# stays off the lab — the host reconstructs the ground truth from its record.
ATTACKER_CPS_FILES = [
    ("cyberrange/planes/attack/agents/exploit_client.py", "/exploit_client.py"),
    ("cyberrange/planes/defense/ot_registers.py", "/ot_registers.py"),
    ("nodes/redteam/red_agent.py", "/red_agent.py"),
    ("nodes/redteam/planner.py", "/planner.py"),
    ("nodes/redteam/steps.py", "/steps.py"),
    ("nodes/redteam/tree_doc.py", "/tree_doc.py"),
]
