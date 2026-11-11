"""Cyber-physical (OT/Modbus) scenario: three zones (IT / OT / defense), a
pandapower digital twin behind Modbus/TCP, a PLC, an HMI with a vulnerable web
app, an active attacker, OT/IT sensors and an optional SOAR responder."""

# What this scenario is made of, by category, for the platform's code-size
# accounting (python -m network_scenario.core loc). Guest agents come from the
# deploy manifests (network_scenario/guest_files.py) of the nodes listed here.
SOURCES = {
    "scenario (topology, episode, CLI, campaign)": [
        "network_scenario/scenarios/cps/*.py", "network_scenario/cps_experiment.py",
        "network_scenario/cps_campaign.py"],
    "metrics": ["monitor/cps_metrics.py"],
    "dashboard panel": ["monitor/cps_graph.js"],
    "host-side domain logic (SOAR, attack drivers, planner)": [
        "defense_plane/soar/*.py", "network_scenario/cps_responder.py",
        "attack_plane/active_attack.py", "attack_plane/planner/*.py"],
}
GUEST_MANIFESTS = ("ENGINE_FILES", "PLC_FILES", "SENSOR_FILES", "HMI_FILES",
                   "ATTACKER_CPS_FILES")
