"""Cyber-physical scenario with a human in the loop: the lab of the cps
scenario, with a SOC that advises instead of acting. Every countermeasure it
would run is put to an operator with the reasons for it, and runs only if the
operator approves it at the SOC's own console. With --teams the attack is a
person's too: a red team works from a console on the attacker node, a blue team
from the SOC's, and the platform's dashboard only watches."""

# What this scenario is made of, for the platform's code-size accounting
# (python -m cyberrange.core loc). Only what it adds: the lab, its nodes'
# software and the metrics are the cps scenario's and are counted there, once.
SOURCES = {
    "scenario (episode options, CLI)": ["cyberrange/scenarios/cps_advisor/*.py"],
    "dashboard panel": ["cyberrange/scenarios/cps_advisor/panel.js"],
}
GUEST_MANIFESTS = ("TEAM_FILES", "SOC_CONSOLE_FILES", "RED_FILES")
