"""scenario.py — the cps scenario with people in the loop.

The same lab and the same episode as cyberrange/scenarios/cps, with a
difference in who decides. The SOC's analytics does not run its
countermeasures: it puts each one to an operator with the reasons for it
(--approval operator:<seconds>), at its own console, published on a host port.
A suggestion left unanswered expires and is not applied. The blue team also
gets a shell on the SOC, and from there SSH to the hosts it manages.

With --teams the attack is a person's as well: no driver runs it, a red team
does, from a console and a shell on the attacker node. Three views then exist,
served from three places, so that each side sees only what its side knows:

    control   the platform's dashboard, on the host   everything, read-only
    blue      the SOC's console, on the soc node      the defence, and its levers
    red       the red console, on the attacker node   the attack's steps

Why a scenario of its own and not an option of cps: a run here needs people,
so it is not a unit of a campaign, and its lab publishes ports the cps lab
does not. Under its own lab name the two can also be up side by side.
"""

import json
import logging
import os
import re
import secrets
import sys

from cyberrange.planes.attack import components as attack
from cyberrange.planes.defense import components as defense
from cyberrange.planes.monitor import components as monitor
from cyberrange.scenarios.cps import topology as T
from cyberrange.scenarios.cps.scenario import CpsScenario
from cyberrange.scenarios.cps_advisor.guest_files import RED_FILES, SOC_CONSOLE_FILES, TEAM_FILES

log = logging.getLogger("scenarios.cps_advisor")

LAB_NAME = "cps-advisor"
OPERATOR_APPROVAL = re.compile(r"^operator:\d+(\.\d+)?$")
BLUE, RED = "blue", "red"
# The hosts the blue team manages from the SOC, by the address their SSH listens on.
MANAGED = {"firewall": T.FW_MGMT_IP, "sensor": T.SENSOR_MGMT_IP, "hmi": T.HMI_MGMT_IP}
# The service an attacker gets a shell through, on the hosts that run one.
ENTRY = {"hmi": attack.VulnApp.SCRIPT}
TEAMS_FILE = "teams.json"  # where the teams' links are written; host only


class CpsAdvisorScenario(CpsScenario):
    name = "cps-advisor"
    lab_name = LAB_NAME
    DEFAULT_OUT_DIR = "output/cps-advisor/run-1"
    DEFAULT_RESPOND = "solver"  # the policy that says what a choice costs and what else it weighed
    DEFAULT_APPROVAL = "operator:120"
    APPROVAL_HELP = (
        "operator:<seconds> — every countermeasure waits this long for the "
        "operator's verdict, then expires unapplied"
    )

    def add_arguments(self, ap):
        super().add_arguments(ap)
        t = ap.add_argument_group("cps-advisor teams")
        t.add_argument(
            "--teams",
            action="store_true",
            help="red team against blue team: nobody drives the attack, a person does from "
            "the red console (needs --playground)",
        )
        t.add_argument("--blue-port", type=int, default=8766, help="host port of the SOC console")
        t.add_argument(
            "--blue-shell-port", type=int, default=8767, help="host port of the blue team's shell"
        )
        t.add_argument("--red-port", type=int, default=8768, help="host port of the red console")
        t.add_argument(
            "--red-shell-port", type=int, default=8769, help="host port of the red team's shell"
        )
        t.add_argument("--blue-token", default=None, help="default: a fresh one per run")
        t.add_argument("--red-token", default=None, help="default: a fresh one per run")

    def validate(self, args):
        super().validate(args)
        if (args.respond or "off") == "off":
            raise SystemExit(
                "--respond off: an advisor with no policy has nothing to suggest; "
                "use rules or solver (or the cps scenario, to only watch)"
            )
        ports = [args.blue_port, args.blue_shell_port]
        if args.teams:
            ports += [args.red_port, args.red_shell_port]
            if not getattr(args, "playground", False):
                raise SystemExit(
                    "--teams needs --playground: the lab has to stay up for the people in it"
                )
            if args.attack:
                raise SystemExit(
                    "--teams and --attack: with teams the attack is the red team's, nothing "
                    "drives it"
                )
        if len(set(ports)) != len(ports) or not all(0 < int(p or 0) < 65536 for p in ports):
            raise SystemExit(f"the teams' host ports must be distinct and valid, got {ports}")

    def check_approval(self, spec):
        if not OPERATOR_APPROVAL.match(spec) or float(spec.split(":", 1)[1]) <= 0:
            raise SystemExit(
                f"--approval must be operator:<seconds> in this scenario, got {spec!r}; "
                "auto, deny and delay belong to the cps scenario"
            )

    def prepare(self, args):
        super().prepare(args)
        # One secret per team and per run: it is all that keeps a team out of
        # the other's console, so it never reaches the ledger.
        for team in (BLUE, RED):
            if not getattr(args, f"{team}_token", None):
                setattr(args, f"{team}_token", secrets.token_urlsafe(24))

    def run_info(self, args):
        return super().run_info(args) | {"approval": args.approval, "teams": bool(args.teams)}

    # ── the lab: the cps one, plus what people need ──────────────────────────
    def topology(self, args):
        def published(*pairs):
            return [f"{host}:{guest}/tcp" for host, guest in pairs]

        served = (T.CONSOLE_GUEST_PORT, T.TERMINAL_GUEST_PORT)
        extras = {name: T.Extra(files=TEAM_FILES) for name in MANAGED}
        extras["soc"] = T.Extra(
            files=SOC_CONSOLE_FILES + TEAM_FILES,
            ports=published(
                (args.blue_port, T.CONSOLE_GUEST_PORT),
                (args.blue_shell_port, T.TERMINAL_GUEST_PORT),
            ),
            startup=T.closed_on("eth0", *served),  # MGMT, where the HMI is
        )
        if getattr(args, "teams", False):
            extras["attacker"] = T.Extra(
                files=RED_FILES + TEAM_FILES,
                ports=published(
                    (args.red_port, T.CONSOLE_GUEST_PORT),
                    (args.red_shell_port, T.TERMINAL_GUEST_PORT),
                ),
                startup=T.closed_on("eth0", *served),  # IT, where the defended hosts are
            )
        return T.topology(args, name=self.lab_name, extras=extras)

    # ── where each team goes ─────────────────────────────────────────────────
    def links(self, args):
        """{team: {"console", "terminal"}}: the URLs handed to each team."""

        def of(team, port, shell_port):
            token = getattr(args, f"{team}_token")
            return {
                "console": f"http://127.0.0.1:{port}/#token={token}",
                "terminal": f"http://{team}:{token}@127.0.0.1:{shell_port}/",
            }

        out = {BLUE: of(BLUE, args.blue_port, args.blue_shell_port)}
        if args.teams:
            out[RED] = of(RED, args.red_port, args.red_shell_port)
        return out

    def operator_api(self, args):
        return dict(
            operator_port=T.CONSOLE_GUEST_PORT,
            operator_token=args.blue_token,
            operator_terminal=self.links(args)[BLUE]["terminal"],
        )

    # ── the episode: the cps one, plus the people ────────────────────────────
    def extra_services(self, ctx):
        a = ctx.args
        ctx.start(monitor.WebTerminal("soc", T.TERMINAL_GUEST_PORT, BLUE, a.blue_token))
        ctx.start(monitor.RecordedShell("soc", BLUE))
        ctx.start(defense.JumpHost("soc", MANAGED))
        for name in MANAGED:
            # The defenders come in over SSH from the SOC. The attacker's shell
            # is told by where it came from — the service it got in through, or
            # SSH from a host it took — so the referee's own is not scored as
            # an attack.
            ctx.start(
                monitor.RecordedShell(
                    name, BLUE, intruder=RED, jump=T.SOC_IP, entry=ENTRY.get(name)
                )
            )
        links = self.links(a)
        path = os.path.join(ctx.out_dir, TEAMS_FILE)
        if os.path.exists(path):
            os.remove(path)  # a file left by another run keeps the mode it had
        # Private from its first byte: created open and closed afterwards, the
        # tokens would be readable in between.
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            json.dump(links, f, indent=1)
        log.info("The teams' links are in %s", path)
        self.hand_over(BLUE, links[BLUE])

    @staticmethod
    def hand_over(team, links):
        """Show a team's links on the terminal the run was started from, and
        nowhere else: the run's log is kept with its artifacts, and a token in
        it would outlive the secrecy of teams.json."""
        for what, url in links.items():
            print(f"{team} team {what}: {url}", file=sys.__stdout__, flush=True)

    def engage(self, ctx):
        """The red team is let in only now: the sensor's model has finished
        calibrating on normal operation, and the ground truth is open to
        record what the team does."""
        a = ctx.args
        if not a.teams:
            return
        links = self.links(a)[RED]
        ctx.start(monitor.WebTerminal("attacker", T.TERMINAL_GUEST_PORT, RED, a.red_token))
        ctx.start(monitor.RecordedShell("attacker", RED, witnessed=True))
        ctx.start(
            attack.RedConsole(
                "attacker",
                T.CONSOLE_GUEST_PORT,
                a.red_token,
                self._attack_tree(ctx),
                f"http://{T.HMI_IP}:{T.APP_PORT}",
                T.ENGINE_IP,
                T.MODBUS_PORT,
                interval=a.attack_interval,
                terminal=links["terminal"],
            )
        )
        self.hand_over(RED, links)

    def panel_js(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")
