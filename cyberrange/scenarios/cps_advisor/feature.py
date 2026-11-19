"""feature.py — people in the loop of the CPS scenario: an operator, and teams.

The SOC's analytics does not run its countermeasures: it puts each one to an
operator with the reasons for it (--approval operator:<seconds>). A suggestion
left unanswered expires and is not applied. The blue team gets a shell on the
SOC, and from there SSH to the hosts it manages; with ``console`` it also gets
the SOC's own console, published on a host port.

With --teams the attack is a person's as well: no driver runs it, a red team
does, from a console and a shell on the attacker node. Three views then exist,
served from three places, so that each side sees only what its side knows:

    control   the platform's dashboard, on the host   everything, read-only
    blue      the SOC's console, on the soc node      the defence, and its levers
    red       the red console, on the attacker node   the attack's steps
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
from cyberrange.scenarios.cps.feature import Feature
from cyberrange.scenarios.cps.scenario import plant_of
from cyberrange.scenarios.cps_advisor.guest_files import RED_FILES, SOC_CONSOLE_FILES, TEAM_FILES

log = logging.getLogger("scenarios.cps_advisor")

OPERATOR_APPROVAL = re.compile(r"^operator:\d+(\.\d+)?$")
BLUE, RED = "blue", "red"
# The roles of the hosts the blue team manages from the SOC, over SSH.
MANAGED_ROLES = ("boundary", "sensor", "hmi")
# The service an attacker gets a shell through, on the hosts that run one.
ENTRY = {"hmi": attack.VulnApp.SCRIPT}
TEAMS_FILE = "teams.json"  # where the teams' links are written; host only


def managed(spec):
    """{host: the address its SSH listens on}: the hosts the blue team manages,
    by their address on the SOC's network."""
    zone = spec.zone_of(spec.one("soc").name)
    return {h.name: spec.ip(h.name, zone) for h in spec.hosts if h.role in MANAGED_ROLES}


def hand_over(team, links):
    """Show a team's links on the terminal the run was started from, and
    nowhere else: the run's log is kept with its artifacts, and a token in it
    would outlive the secrecy of teams.json."""
    for what, url in links.items():
        print(f"{team} team {what}: {url}", file=sys.__stdout__, flush=True)


class People(Feature):
    """An operator who decides, and with --teams a red and a blue team.
    ``console=False`` leaves the blue team without the SOC's console, for a
    scenario that gives it other tools to decide from."""

    def __init__(self, console=True):
        self.console = console

    # ── options ──────────────────────────────────────────────────────────────
    def add_arguments(self, ap):
        t = ap.add_argument_group("teams")
        t.add_argument(
            "--teams",
            action="store_true",
            help="red team against blue team: nobody drives the attack, a person does from "
            "the red console (needs --playground)",
        )
        if self.console:
            t.add_argument(
                "--blue-port", type=int, default=8766, help="host port of the SOC console"
            )
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
        if (args.respond or "off") == "off":
            raise SystemExit(
                "--respond off: an advisor with no policy has nothing to suggest; "
                "use rules or solver (or the cps scenario, to only watch)"
            )
        if args.teams:
            if not getattr(args, "playground", False):
                raise SystemExit(
                    "--teams needs --playground: the lab has to stay up for the people in it"
                )
            if args.attack:
                raise SystemExit(
                    "--teams and --attack: with teams the attack is the red team's, nothing "
                    "drives it"
                )

    def check_approval(self, spec):
        if not OPERATOR_APPROVAL.match(spec) or float(spec.split(":", 1)[1]) <= 0:
            raise SystemExit(
                f"--approval must be operator:<seconds> in this scenario, got {spec!r}; "
                "auto, deny and delay belong to the cps scenario"
            )
        return True

    def host_ports(self, args):
        ports = [args.blue_shell_port]
        if self.console:
            ports.append(args.blue_port)
        if args.teams:
            ports += [args.red_port, args.red_shell_port]
        return ports

    def prepare(self, args):
        # One secret per team and per run: it is all that keeps a team out of
        # the other's console, so it never reaches the ledger.
        for team in (BLUE, RED):
            if not getattr(args, f"{team}_token", None):
                setattr(args, f"{team}_token", secrets.token_urlsafe(24))

    def run_info(self, args):
        return {"approval": args.approval, "teams": bool(args.teams)}

    # ── the lab ──────────────────────────────────────────────────────────────
    def extras(self, spec, args):
        def published(*pairs):
            return [f"{host}:{guest}/tcp" for host, guest in pairs]

        soc = spec.one("soc").name
        served = [(args.blue_shell_port, T.TERMINAL_GUEST_PORT)]
        files = list(TEAM_FILES)
        if self.console:
            served.insert(0, (args.blue_port, T.CONSOLE_GUEST_PORT))
            files = SOC_CONSOLE_FILES + files
        out = {name: T.Extra(files=TEAM_FILES) for name in managed(spec)}
        # Closed on the SOC's lab network, where the HMI is.
        out[soc] = T.Extra(
            files=files,
            ports=published(*served),
            startup=T.closed_on(
                spec.iface(soc, spec.zone_of(soc)), *(guest for _host, guest in served)
            ),
        )
        if args.teams:
            attacker = spec.one("it-host").name
            out[attacker] = T.Extra(
                files=RED_FILES + TEAM_FILES,
                ports=published(
                    (args.red_port, T.CONSOLE_GUEST_PORT),
                    (args.red_shell_port, T.TERMINAL_GUEST_PORT),
                ),
                # Closed on IT, where the defended hosts are.
                startup=T.closed_on(
                    spec.iface(attacker, spec.zone_of(attacker)),
                    T.CONSOLE_GUEST_PORT,
                    T.TERMINAL_GUEST_PORT,
                ),
            )
        return out

    # ── where each team goes ─────────────────────────────────────────────────
    def links(self, args):
        """{team: {"console", "terminal"}}: the URLs handed to each team."""

        def of(team, port, shell_port):
            token = getattr(args, f"{team}_token")
            out = {"console": f"http://127.0.0.1:{port}/#token={token}"} if port else {}
            return out | {"terminal": f"http://{team}:{token}@127.0.0.1:{shell_port}/"}

        out = {BLUE: of(BLUE, args.blue_port if self.console else None, args.blue_shell_port)}
        if args.teams:
            out[RED] = of(RED, args.red_port, args.red_shell_port)
        return out

    def operator_api(self, scenario, args):
        if not self.console:
            return {}
        return dict(
            operator_port=T.CONSOLE_GUEST_PORT,
            operator_token=args.blue_token,
            operator_terminal=self.links(args)[BLUE]["terminal"],
        )

    # ── the episode ──────────────────────────────────────────────────────────
    def services(self, ctx):
        a = ctx.args
        spec = ctx.scenario.lab_spec(a)
        soc = spec.one("soc").name
        hosts = managed(spec)
        ctx.start(monitor.WebTerminal(soc, T.TERMINAL_GUEST_PORT, BLUE, a.blue_token))
        ctx.start(monitor.RecordedShell(soc, BLUE))
        ctx.start(defense.JumpHost(soc, hosts))
        for name in hosts:
            # The defenders come in over SSH from the SOC. The attacker's shell
            # is told by where it came from — the service it got in through, or
            # SSH from a host it took — so the referee's own is not scored as
            # an attack.
            ctx.start(
                monitor.RecordedShell(
                    name, BLUE, intruder=RED, jump=spec.ip(soc), entry=ENTRY.get(name)
                )
            )
        links = ctx.scenario.links(a)
        path = os.path.join(ctx.out_dir, TEAMS_FILE)
        if os.path.exists(path):
            os.remove(path)  # a file left by another run keeps the mode it had
        # Private from its first byte: created open and closed afterwards, the
        # tokens would be readable in between.
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            json.dump(links, f, indent=1)
        log.info("The teams' links are in %s", path)
        hand_over(BLUE, links[BLUE])

    def engage(self, ctx):
        """The red team is let in only now: the sensor's model has finished
        calibrating on normal operation, and the ground truth is open to
        record what the team does."""
        a = ctx.args
        if not a.teams:
            return
        spec = ctx.scenario.lab_spec(a)
        p = plant_of(spec)
        attacker = spec.one("it-host").name
        links = ctx.scenario.links(a)[RED]
        ctx.start(monitor.WebTerminal(attacker, T.TERMINAL_GUEST_PORT, RED, a.red_token))
        ctx.start(monitor.RecordedShell(attacker, RED, witnessed=True))
        ctx.start(
            attack.RedConsole(
                attacker,
                T.CONSOLE_GUEST_PORT,
                a.red_token,
                ctx.scenario._attack_tree(ctx),
                f"http://{p.hmi_ip}:{p.app_port}",
                p.engine_ip,
                p.modbus_port,
                interval=a.attack_interval,
                terminal=links["terminal"],
            )
        )
        hand_over(RED, links)
