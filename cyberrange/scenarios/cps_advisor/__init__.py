"""Cyber-physical scenario with a human in the loop: the lab of the cps
scenario, with a SOC that advises instead of acting. Every countermeasure it
would run is put to an operator with the reasons for it, and runs only if the
operator approves it from a console of the SOC's operator API."""

# What this scenario is made of, for the platform's code-size accounting
# (python -m cyberrange.core loc). Only what it adds: the lab, the nodes'
# software and the metrics are the cps scenario's and are counted there, once.
SOURCES = {
    "scenario (episode options, CLI)": ["cyberrange/scenarios/cps_advisor/*.py"],
    "dashboard panel": ["cyberrange/scenarios/cps_advisor/panel.js"],
}
# It stages no file of its own (see guest_files.py).
GUEST_MANIFESTS = ()
