"""scenario.py — the cps-advisor scenario with a real SOC's tools.

The same lab, episode and people as cyberrange/scenarios/cps_advisor: a SOC that
advises, an operator who decides, and with --teams a red team against a blue
team. What changes is what the blue team works on: instead of the SOC's own
console, Wazuh as SIEM and DFIR-IRIS as case management (the SocTools feature,
feature.py), started before the people's own services.

Why a scenario of its own: its lab adds seven nodes and some 3 GB of memory,
which no cps or cps-advisor run should pay for.
"""

import os

from cyberrange.scenarios.cps_advisor.feature import People
from cyberrange.scenarios.cps_advisor.scenario import CpsAdvisorScenario
from cyberrange.scenarios.cps_soc.feature import (  # noqa: F401  (the scenario's names)
    ATTACK_TREE_VIEW,
    IDLE,
    IMAGES,
    SocTools,
)

LAB_NAME = "cps-soc"


class CpsSocScenario(CpsAdvisorScenario):
    name = "cps-soc"
    lab_name = LAB_NAME
    # The tools first: their files come first on the SOC, and they start before
    # the people's services.
    features = (SocTools(), People(console=False))

    def panel_js(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")
