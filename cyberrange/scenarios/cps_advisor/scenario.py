"""scenario.py — the cps scenario with a human in the loop.

The same lab and the same episode as cyberrange/scenarios/cps, with one
difference in who decides: the SOC's analytics does not run its
countermeasures, it puts each one to an operator with the reasons for it
(--approval operator:<seconds>). The operator answers on the SOC's own
operator API, which this scenario publishes on a host port; a suggestion left
unanswered expires and is not applied.

Why a scenario of its own and not an option of cps: a run here needs a person,
so it is not a unit of a campaign, and its lab exposes one more port than the
cps lab does. Under its own lab name the two can also be up side by side.
"""

import re
import secrets

from cyberrange.scenarios.cps import topology as T
from cyberrange.scenarios.cps.scenario import CpsScenario

LAB_NAME = "cps-advisor"
OPERATOR_APPROVAL = re.compile(r"^operator:\d+(\.\d+)?$")
# Where the platform's dashboard is served by default (make dashboard): the one
# browser console this scenario lets call the operator API unless told otherwise.
DEFAULT_CONSOLES = ("http://127.0.0.1:8765", "http://localhost:8765")


class CpsAdvisorScenario(CpsScenario):
    name = "cps-advisor"
    lab_name = LAB_NAME
    DEFAULT_OUT_DIR = "output/cps-advisor/run-1"
    DEFAULT_RESPOND = (
        "solver"  # the policy that says what each choice costs and what else it weighed
    )
    DEFAULT_APPROVAL = "operator:120"
    APPROVAL_HELP = (
        "operator:<seconds> — every countermeasure waits this long for the "
        "operator's verdict, then expires unapplied"
    )

    def add_arguments(self, ap):
        super().add_arguments(ap)
        o = ap.add_argument_group("cps-advisor operator")
        o.add_argument(
            "--operator-port",
            type=int,
            default=8766,
            help="host port the SOC's operator API is published on",
        )
        o.add_argument(
            "--operator-token",
            default=None,
            help="bearer token of the operator API (default: a fresh one per run)",
        )
        o.add_argument(
            "--operator-origin",
            action="append",
            default=None,
            help="origin of a browser console allowed to call the operator API "
            f"(repeatable; default: {', '.join(DEFAULT_CONSOLES)})",
        )

    def validate(self, args):
        super().validate(args)
        if (args.respond or "off") == "off":
            raise SystemExit(
                "--respond off: an advisor with no policy has nothing to suggest; "
                "use rules or solver (or the cps scenario, to only watch)"
            )
        if not 0 < int(args.operator_port or 0) < 65536:
            raise SystemExit(
                f"--operator-port {args.operator_port}: the operator needs a host port to answer on"
            )

    def check_approval(self, spec):
        if not OPERATOR_APPROVAL.match(spec) or float(spec.split(":", 1)[1]) <= 0:
            raise SystemExit(
                f"--approval must be operator:<seconds> in this scenario, got {spec!r}; "
                "auto, deny and delay belong to the cps scenario"
            )

    def prepare(self, args):
        super().prepare(args)
        # Before run_start, which tells the console where and how to answer.
        if not getattr(args, "operator_token", None):
            args.operator_token = secrets.token_urlsafe(24)

    def consoles(self, args):
        return list(getattr(args, "operator_origin", None) or DEFAULT_CONSOLES)

    def run_info(self, args):
        return super().run_info(args) | {
            "approval": args.approval,
            "operator_url": f"http://127.0.0.1:{args.operator_port}",
            "operator_token": getattr(args, "operator_token", None),
        }

    def operator_api(self, args):
        return dict(
            operator_port=T.OPERATOR_GUEST_PORT,
            operator_token=args.operator_token,
            operator_origins=self.consoles(args),
        )

    def panel_js(self):
        import os

        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")
