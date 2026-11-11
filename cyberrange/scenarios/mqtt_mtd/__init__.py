"""MQTT smart-grid scenario (the workshop paper's): a nanogrid's SCMC publishes
to the SEMP broker over mutual TLS, a passive attacker fingerprints the traffic
with a CNN and blackholes the nanogrid, and a moving-target defense (fixed
timers or an RL policy) morphs the traffic to defeat the fingerprinting."""

# What this scenario is made of, by category, for the platform's code-size
# accounting (python -m cyberrange.core loc). Guest agents come from the
# deploy manifests (the scenario's guest_files.py) of the nodes listed here.
#
# The categories must stay disjoint — loc sums each one, so a file matched
# twice is counted twice — which is why they follow directories. What is left
# outside the scenario package is only the host-side logic the attack plane
# owns: cyberrange/planes/attack/components.py imports it, so it cannot move in here
# without inverting the plane -> scenario dependency.
SOURCES = {
    "scenario (topology, episode, CLI, campaign, metrics, manifest)": [
        "cyberrange/scenarios/mqtt_mtd/*.py",
        "main.py",
    ],
    "analysis & paper figures": ["cyberrange/scenarios/mqtt_mtd/analysis/*.py"],
    "offline training (RL coordinator, delivery detector)": [
        "cyberrange/scenarios/mqtt_mtd/training/*.py"
    ],
    "dataset tooling": ["cyberrange/scenarios/mqtt_mtd/tools/*.py"],
    "host-side domain logic owned by the attack plane (CNN fingerprinter)": [
        "cyberrange/planes/attack/classify.py",
        "cyberrange/planes/attack/thresholds.py",
    ],
}
GUEST_MANIFESTS = ("SEMP_FILES", "SEMP_RL_FILES", "SCMC_FILES", "ROUTER_FILES")
