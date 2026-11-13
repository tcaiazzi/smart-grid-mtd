"""Cyber-physical scenario whose blue team works on a real SOC's tools.

The cps-advisor lab and episode — a SOC that advises, an operator who decides,
optionally a red team against a blue team — with the defender's two consoles
replaced by the open-source tools of a real SOC, each deployed as its project
deploys it: the Wazuh indexer and dashboard as the SIEM (alerts, agents, rules),
and DFIR-IRIS as case management, where the SOC files each countermeasure it
proposes as a task an analyst closes or cancels.
"""

# What this scenario ADDS, for the platform's code-size accounting
# (python -m cyberrange.core loc). The lab, its nodes' software and the metrics
# are the cps scenario's, the people's consoles cps-advisor's: counted there, once.
SOURCES = {
    "scenario (topology, episode options, CLI)": ["cyberrange/scenarios/cps_soc/*.py"],
    "dashboard panel": ["cyberrange/scenarios/cps_soc/panel.js"],
}
GUEST_MANIFESTS = (
    "SOC_SIEM_FILES",
    "INDEXER_FILES",
    "DASHBOARD_FILES",
    "IRIS_FILES",
    "IRIS_MODULE_FILES",
)
