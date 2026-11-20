"""feature.py — an attacker that derives its own attack tree by reconnaissance.

The planner driver of cps is *handed* the attack tree the SOC built from the
inventory — perfect knowledge of the target. With this feature the attacker is
given only a scan scope (its own IT subnet and a port list) and must derive the
tree itself: nmap discovers the IT side from the attacker's own box (the
kathara/redteam image), then, through the foothold on the HMI, it reads the OS
and the HMI's own pymodbus to find the engine and its registers. From that it
builds a belief tree and plans on it, reusing the whole cps chain.

The attacker's tools must not sit on the victim HMI, so the attacker runs on its
own image.
"""

from cyberrange.planes.attack import components as attack
from cyberrange.scenarios.cps import topology as T
from cyberrange.scenarios.cps.feature import Feature
from cyberrange.scenarios.cps_recon.guest_files import RECON_FILES

REDTEAM_IMAGE = "kathara/redteam"


class Recon(Feature):
    def add_arguments(self, ap):
        g = ap.add_argument_group("reconnaissance")
        g.add_argument(
            "--it-cidr",
            # The attacker's own subnet — what any attacker knows of its own
            # box, not the target's structure (which it has to discover).
            default=T.IT_NET,
            help="the IT subnet the attacker scans (its own; not the target's map)",
        )
        g.add_argument(
            "--scan-ports",
            default="22,80,502,5020,8080",
            help="comma-separated ports nmap probes on the IT scan",
        )

    def extras(self, spec, args):
        # The victim nodes stay on the cps image, unchanged.
        return {spec.one("it-host").name: T.Extra(files=RECON_FILES, image=REDTEAM_IMAGE)}

    def attacker(self, scenario, args):
        return attack.ReconAttacker(
            args.attacker_profile,
            args.it_cidr,
            scan_ports=args.scan_ports,
            goal=args.attack_goal,
            dwell=args.dwell,
            max_steps=args.max_steps,
            interval=args.attack_interval,
            node=scenario.lab_spec(args).one("it-host").name,
        )
