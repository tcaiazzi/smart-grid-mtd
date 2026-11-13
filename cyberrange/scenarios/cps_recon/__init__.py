"""Cyber-physical scenario where the attacker derives the attack tree itself.

The same lab and episode as cyberrange/scenarios/cps, with one difference: the
attacker is not handed the defender's attack tree. It reconnoitres the network
(nmap on its own box for the IT side, living off the land on the compromised HMI
for the OT side), builds a *belief* tree from what it finds, and plans on that.
A run then also measures how close the derived tree is to the true one.
"""

# What this scenario ADDS, for the platform's code-size accounting
# (python -m cyberrange.core loc). The lab, its nodes' software and the metrics
# are the cps scenario's and are counted there, once.
SOURCES = {
    "scenario (episode options, CLI)": ["cyberrange/scenarios/cps_recon/*.py"],
    "dashboard panel": ["cyberrange/scenarios/cps_recon/panel.js"],
}
GUEST_MANIFESTS = ("RECON_FILES",)
