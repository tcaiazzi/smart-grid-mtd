"""scenario.py — the cps scenario with people in the loop.

The same lab and the same episode as cyberrange/scenarios/cps, with a
difference in who decides: the SOC advises an operator, who approves or rejects
each countermeasure at the SOC's console; with --teams a red team attacks and a
blue team defends. All of it is the People feature (feature.py).

Why a scenario of its own and not an option of cps: its lab publishes ports the
cps lab does not, and a run with a person at a seat waits for that person — it
is not a unit of a campaign. With a harness at both seats it is: campaign.py
benchmarks harnesses that way. Under its own lab name this scenario and cps can
also be up side by side.
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
