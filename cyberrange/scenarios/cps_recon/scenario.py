"""scenario.py — the cps scenario with a recon-driven attacker.

The same lab and the same episode as cyberrange/scenarios/cps, with a difference
in what the attacker knows: it derives the attack tree by reconnaissance instead
of being handed it (the Recon feature, feature.py).

Why a scenario of its own and not an option of cps: the attacker runs on a
different node image, and under its own lab name it can run side by side with
cps.
"""

import os

from cyberrange.scenarios.cps.scenario import CpsScenario
from cyberrange.scenarios.cps_recon.feature import REDTEAM_IMAGE, Recon  # noqa: F401

LAB_NAME = "cps-recon"


class CpsReconScenario(CpsScenario):
    name = "cps-recon"
    lab_name = LAB_NAME
    features = (Recon(),)
    REDTEAM_IMAGE = REDTEAM_IMAGE
    DEFAULT_OUT_DIR = "output/cps-recon/run-1"

    def panel_js(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")
