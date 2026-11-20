"""scenario.py — the cps scenario with people in the loop.

The same lab and the same episode as cyberrange/scenarios/cps, with a
difference in who decides: the SOC advises an operator, who approves or rejects
each countermeasure at the SOC's console; with --teams a red team attacks and a
blue team defends. All of it is the People feature (feature.py).

Why a scenario of its own and not an option of cps: a run here needs people,
so it is not a unit of a campaign, and its lab publishes ports the cps lab
does not. Under its own lab name the two can also be up side by side.
"""

import os

from cyberrange.scenarios.cps.scenario import CpsScenario
from cyberrange.scenarios.cps_advisor.feature import People

LAB_NAME = "cps-advisor"


class CpsAdvisorScenario(CpsScenario):
    name = "cps-advisor"
    lab_name = LAB_NAME
    features = (People(),)
    DEFAULT_RESPOND = "solver"  # the policy that says what a choice costs and what else it weighed
    DEFAULT_APPROVAL = "operator:120"
    APPROVAL_HELP = (
        "operator:<seconds> — every countermeasure waits this long for the "
        "operator's verdict, then expires unapplied"
    )

    def panel_js(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")
