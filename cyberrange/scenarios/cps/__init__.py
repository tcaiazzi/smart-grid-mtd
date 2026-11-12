"""Cyber-physical (OT/Modbus) scenario: IT and OT zones behind a boundary
firewall plus a management network, a pandapower digital twin behind
Modbus/TCP, a PLC, a dual-homed HMI with a vulnerable web app, an active
attacker, OT/IT sensors and an optional SOAR responder."""

# What this scenario is made of, by category, for the platform's code-size
# accounting (python -m cyberrange.core loc). Guest agents come from the
# deploy manifests (the scenario's guest_files.py) of the nodes listed here.
#
# The categories must stay disjoint — loc sums each one, so a file matched
# twice is counted twice — which is why they follow directories rather than
# enumerating files: everything the scenario owns now lives under its own
# package, and what is left outside is only the host-side logic the planes own
# (a plane component imports it, so it cannot move in here).
SOURCES = {
    "scenario (topology, episode, CLI, campaign, metrics, manifest)": [
        "cyberrange/scenarios/cps/*.py"
    ],
    "dashboard panel": ["cyberrange/scenarios/cps/panel.js"],
    "host-side domain logic (SOAR, attack drivers, planner)": [
        "cyberrange/planes/defense/soar/*.py",
        "cyberrange/planes/attack/active_attack.py",
        "cyberrange/planes/attack/planner/*.py",
    ],
}
GUEST_MANIFESTS = ("ENGINE_FILES", "PLC_FILES", "SENSOR_FILES", "HMI_FILES", "ATTACKER_CPS_FILES")
