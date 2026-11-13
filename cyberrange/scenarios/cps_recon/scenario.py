"""scenario.py — the cps scenario with a recon-driven attacker.

The same lab and the same episode as cyberrange/scenarios/cps, with a difference
in what the attacker knows. The planner driver of cps is *handed* the attack tree
the SOC built from the inventory — perfect knowledge of the target. Here the
attacker is given only a scan scope (its own IT subnet and a port list) and must
**derive** the tree itself: nmap discovers the IT side from the attacker's own
box (the kathara/redteam image), then, through the foothold on the HMI, it reads
the OS and the HMI's own pymodbus to find the engine and its registers. From that
it builds a belief tree and plans on it, reusing the whole cps chain.

Why a scenario of its own and not an option of cps: the attacker runs on a
different node image (its tools must not sit on the victim HMI), and under its own
lab name it can run side by side with cps.
"""

import logging
import os

from cyberrange.planes.attack import components as attack
from cyberrange.scenarios.cps import topology as T
from cyberrange.scenarios.cps.scenario import CpsScenario
from cyberrange.scenarios.cps_recon.guest_files import RECON_FILES

log = logging.getLogger("scenarios.cps_recon")

LAB_NAME = "cps-recon"
# The attacker's own IT subnet — what any attacker knows of its own box, not the
# target's structure (which it has to discover).
DEFAULT_IT_CIDR = "10.10.0.0/24"


class CpsReconScenario(CpsScenario):
    name = "cps-recon"
    lab_name = LAB_NAME
    REDTEAM_IMAGE = "kathara/redteam"
    DEFAULT_OUT_DIR = "output/cps-recon/run-1"

    def add_arguments(self, ap):
        super().add_arguments(ap)
        g = ap.add_argument_group("cps-recon reconnaissance")
        g.add_argument(
            "--it-cidr",
            default=DEFAULT_IT_CIDR,
            help="the IT subnet the attacker scans (its own; not the target's map)",
        )
        g.add_argument(
            "--scan-ports",
            default="22,80,502,5020,8080",
            help="comma-separated ports nmap probes on the IT scan",
        )

    def topology(self, args):
        # The attacker rides on the red-team image (nmap) and gets the recon
        # agents; the victim nodes stay on the cps image, unchanged.
        extras = {"attacker": T.Extra(files=RECON_FILES, image=self.REDTEAM_IMAGE)}
        return T.topology(args, name=self.lab_name, extras=extras)

    def attacker(self, args):
        return attack.ReconAttacker(
            args.attacker_profile,
            args.it_cidr,
            scan_ports=args.scan_ports,
            goal=args.attack_goal,
            dwell=args.dwell,
            max_steps=args.max_steps,
            interval=args.attack_interval,
        )

    def panel_js(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")
