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

A seat need not be a person's. Given a harness (--red-harness, --blue-harness),
a team is played by a program: on a node of its own, with one link to its
team's console and a way out to its model's API, and nothing else of the lab or
of the host within reach. It sits at the same console as a person would, behind
the same token. With a harness at both seats nobody has to be there: the
episode gives them an engagement of fixed length and ends by itself.

What the red team knows of the attack is an option (--red-knowledge). By
default it is given the attack tree, as the steps of its console. With
``recon`` it is given nothing of the lab but its own network: it finds its way
with the tools of its node, reports what it finds to its console, and is listed
the steps its reports make possible — the tree it derives is then scored
against the true one.
"""

import json
import logging
import os
import re
import secrets
import sys
import time

from cyberrange.core import paths, runcard
from cyberrange.core.component import SeatPlayer
from cyberrange.core.scenario import PhaseSpec
from cyberrange.core.topology import Iface, Node
from cyberrange.planes.attack import components as attack
from cyberrange.planes.defense import components as defense
from cyberrange.planes.defense import ot_registers as reg
from cyberrange.planes.monitor import components as monitor
from cyberrange.scenarios.cps import topology as T
from cyberrange.scenarios.cps.feature import Feature
from cyberrange.scenarios.cps.scenario import plant_of
from cyberrange.scenarios.cps_advisor.briefing import briefing
from cyberrange.scenarios.cps_advisor.guest_files import (
    PLAYER_FILES,
    RED_FILES,
    SEAT_FILES,
    SOC_CONSOLE_FILES,
    TEAM_FILES,
)
from cyberrange.scenarios.cps_advisor.harnesses import HARNESSES
from cyberrange.scenarios.cps_recon.feature import REDTEAM_IMAGE
from cyberrange.scenarios.cps_recon.guest_files import RECON_FILES

log = logging.getLogger("scenarios.cps_advisor")

OPERATOR_APPROVAL = re.compile(r"^operator:\d+(\.\d+)?$")
BLUE, RED = "blue", "red"
# The roles of the hosts the blue team manages from the SOC, over SSH.
MANAGED_ROLES = ("boundary", "sensor", "hmi")
# The service an attacker gets a shell through, on the hosts that run one.
ENTRY = {"hmi": attack.VulnApp.SCRIPT}
TEAMS_FILE = "teams.json"  # where the teams' links are written; host only
ENGAGEMENT = "engagement"  # the phase two harnesses play each other in
# What every harness plays through and is first told, whichever it is: the
# run's card keeps their fingerprints.
ADAPTER, PLAYER_KIT = "nodes/players/seat_mcp.py", "nodes/players/harness_kit.py"
# The link between a team's console and its player's node: a network of two
# addresses, of a range no lab uses (RFC 2544's, never routed).
SEAT_NETS = {BLUE: "198.18.0.0", RED: "198.18.0.4"}
PLANE_OF = {BLUE: defense.PLANE, RED: attack.PLANE}
TREE, RECON = "tree", "recon"  # what the red team knows of the attack: given it, or found
RECON_PLAYER = "scripted-recon"  # the scripted policy for a red seat that finds its tree


def fresh_token():
    """A team's secret for one run. It is passed to the consoles as the value
    of an option, and one that began with a dash would be read as an option
    itself: the console would not start, and the run would go on without it."""
    while True:
        token = secrets.token_urlsafe(24)
        if token[0].isalnum():
            return token


def seat_link(team):
    """(link, console's address, player's address) of ``team``'s seat."""
    a, b, c, d = (int(x) for x in SEAT_NETS[team].split("."))
    return f"seat{team}", f"{a}.{b}.{c}.{d + 1}", f"{a}.{b}.{c}.{d + 2}"


def player_node(team):
    return f"{team}player"  # Kathará takes no '-' in a machine's name


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
        t.add_argument(
            "--red-knowledge",
            choices=(TREE, RECON),
            default=TREE,
            help="what the red team knows of the attack: the tree, as its console's steps, "
            "or only what it finds by reconnaissance and reports to its console",
        )
        t.add_argument("--blue-token", default=None, help="default: a fresh one per run")
        t.add_argument("--red-token", default=None, help="default: a fresh one per run")
        if not self.console:
            return  # the harnesses sit at the SOC's console, which this lab does not serve
        p = ap.add_argument_group(
            "players", "a harness at a team's seat instead of a person (with --teams)"
        )
        for team in (RED, BLUE):
            p.add_argument(
                f"--{team}-harness",
                default=None,
                choices=sorted(HARNESSES),
                help=f"what plays the {team} team; default: a person",
            )
            p.add_argument(f"--{team}-model", default=None, help="the model that harness runs")
        p.add_argument(
            "--engagement-s",
            type=float,
            default=900.0,
            help="with a harness at both seats: how long they play, at most",
        )
        p.add_argument(
            "--max-calls", type=int, default=None, help="each harness's budget of tool calls"
        )
        p.add_argument(
            "--player-dns",
            default="1.1.1.1,8.8.8.8",
            help="name servers of the players' nodes, comma-separated: a lab node has none, "
            "and a harness must find its model's API",
        )

    def players(self, args):
        """{team: Harness} for the seats a harness plays."""
        named = {team: getattr(args, f"{team}_harness", None) for team in (BLUE, RED)}
        return {team: HARNESSES[name] for team, name in named.items() if name}

    def engaged(self, args):
        """Whether both seats are a harness's: then nobody has to be there."""
        return len(self.players(args)) == 2

    def validate(self, args):
        if (args.respond or "off") == "off":
            raise SystemExit(
                "--respond off: an advisor with no policy has nothing to suggest; "
                "use rules or solver (or the cps scenario, to only watch)"
            )
        players = self.players(args)
        if players and not args.teams:
            raise SystemExit(
                f"--{next(iter(players))}-harness: a harness plays a team, and there are "
                "teams only with --teams"
            )
        for team, harness in players.items():
            if harness.seats and team not in harness.seats:
                raise SystemExit(
                    f"--{team}-harness {harness.name}: it plays the "
                    f"{' or '.join(harness.seats)} team only"
                )
            missing = harness.missing()
            if missing:
                raise SystemExit(
                    f"--{team}-harness {harness.name} needs {' or '.join(missing)} in the "
                    "environment: its node is given nothing else of this host"
                )
        if args.red_knowledge == RECON and not args.teams:
            raise SystemExit("--red-knowledge recon: there is a red team only with --teams")
        if RED in players and (players[RED].name == RECON_PLAYER) != (args.red_knowledge == RECON):
            scripted = players[RED].name.startswith("scripted")
            if scripted:
                raise SystemExit(
                    f"--red-harness {players[RED].name} with --red-knowledge "
                    f"{args.red_knowledge}: {RECON_PLAYER} plays a seat that finds its tree, "
                    "the other scripted policies one that is given it"
                )
        if args.teams:
            if not self.engaged(args) and not getattr(args, "playground", False):
                raise SystemExit(
                    "--teams needs --playground: the lab has to stay up for the people in it "
                    "(or a harness at both seats: --red-harness and --blue-harness)"
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
                setattr(args, f"{team}_token", fresh_token())

    def run_info(self, args):
        info = {"approval": args.approval, "teams": bool(args.teams)}
        if args.teams and args.red_knowledge != TREE:
            info["red_knowledge"] = args.red_knowledge
        if args.teams:
            # Who plays each seat: what a comparison of harnesses is grouped by.
            played = self.players(args)
            info["players"] = {
                team: {
                    "kind": "agent",
                    "harness": played[team].name,
                    "model": self.model(args, team),
                }
                if team in played
                else {"kind": "human"}
                for team in (BLUE, RED)
            }
        return info

    def secret_options(self, args):
        return ("blue_token", "red_token")

    def run_card(self, scenario, args):
        """What the players were given, as fingerprints: the seat's adapter and
        the first message (nodes/players, the same for every harness), and
        each team's briefing. Two games are comparable when these match."""
        if not args.teams:
            return {}
        card = {
            "red_knowledge": args.red_knowledge,
            "seat_adapter": runcard.file_fingerprint(paths.resolve(ADAPTER)),
            "player_kit": runcard.file_fingerprint(paths.resolve(PLAYER_KIT)),
        }
        for team in (BLUE, RED):
            card[f"briefing_{team}"] = runcard.fingerprint(self.briefing(scenario, args, team))
        return card

    def model(self, args, team):
        return getattr(args, f"{team}_model", None) or self.players(args)[team].default_model

    # ── the lab ──────────────────────────────────────────────────────────────
    def extras(self, spec, args):
        def published(*pairs):
            return [f"{host}:{guest}/tcp" for host, guest in pairs]

        def seated(host, team):
            """What a team's node gains when a harness plays the team: a foot
            on the link to the player's node, open to that node for the console
            and to nothing else. Without the last two rules the node would also
            carry the player's packets on into the lab."""
            link, here, there = seat_link(team)
            iface = f"eth{len(spec.host(host).nics)}"  # after the lab's own
            return T.Extra(
                ifaces=[Iface(link, f"{here}/30")],
                startup=[
                    f"iptables -A INPUT -i {iface} -p tcp -s {there} "
                    f"--dport {T.CONSOLE_GUEST_PORT} -j ACCEPT",
                    f"iptables -A INPUT -i {iface} -j DROP",
                    f"iptables -A FORWARD -i {iface} -j DROP",
                    f"iptables -A FORWARD -o {iface} -j DROP",
                ],
            )

        players = self.players(args)
        soc = spec.one("soc").name
        served = [(args.blue_shell_port, T.TERMINAL_GUEST_PORT)]
        files = list(TEAM_FILES)
        if self.console:
            served.insert(0, (args.blue_port, T.CONSOLE_GUEST_PORT))
            files = SOC_CONSOLE_FILES + files
            if args.teams:
                files = SEAT_FILES + files
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
                files=RED_FILES + SEAT_FILES + TEAM_FILES,
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
            if args.red_knowledge == RECON:
                # The scanner and the tree generator, on the red team's own
                # image: none of it belongs on a host of the plant's.
                out[attacker] = out[attacker].merged(
                    T.Extra(files=RECON_FILES, image=REDTEAM_IMAGE)
                )
            if RED in players:
                out[attacker] = out[attacker].merged(seated(attacker, RED))
        if BLUE in players:
            out[soc] = out[soc].merged(seated(soc, BLUE))
        return out

    def nodes(self, spec, args):
        """A node per harness: one foot on the link to its team's console, a
        way out for its model's API, and none of the lab's networks."""
        return [
            Node(
                player_node(team),
                [Iface(seat_link(team)[0], f"{seat_link(team)[2]}/30")],
                image=harness.image,
                role="player",
                files=PLAYER_FILES + list(harness.files),
                bridged=True,
            )
            for team, harness in self.players(args).items()
        ]

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
            # With teams the console is a team's seat, served to a player of
            # any kind; a lone operator's console stays the page it was.
            seat_team=BLUE if args.teams else None,
            briefing=self.briefing(scenario, args, BLUE) if args.teams else None,
        )

    def briefing(self, scenario, args, team):
        spec = scenario.lab_spec(args)
        return briefing(team, spec, args, managed=managed(spec), engaged=self.engaged(args))

    def phases(self, args):
        if args.teams and self.engaged(args):
            return [PhaseSpec(ENGAGEMENT, float(args.engagement_s), timed=True)]
        return []

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
                ways=p.ways,
                plant_b64=reg.plant_b64(ctx.scenario.plant_spec(a)),
                briefing=self.briefing(ctx.scenario, a, RED),
                knowledge=a.red_knowledge,
            )
        )
        hand_over(RED, links)
        self.play(ctx)

    def play(self, ctx):
        """Start the harnesses, both at once so that neither side has a head
        start; with one at each seat, give them their engagement and end it
        when the time is up or both have stopped playing."""
        a = ctx.args
        played = self.players(a)
        if not played:
            return
        spec = ctx.scenario.lab_spec(a)
        engaged = self.engaged(a)
        deadline = time.time() + float(a.engagement_s) if engaged else None
        seats = {BLUE: spec.one("soc").name, RED: spec.one("it-host").name}
        started = []
        for team, harness in played.items():
            _link, console, _player = seat_link(team)
            model = self.model(a, team)
            started.append(
                ctx.start(
                    SeatPlayer(
                        player_node(team),
                        team,
                        harness,
                        # The console's address on the link, as the player's node sees it.
                        (console, T.CONSOLE_GUEST_PORT, "eth0"),
                        getattr(a, f"{team}_token"),
                        terms={
                            "CR_OPERATOR": f"agent:{harness.name}" + (f":{model}" if model else ""),
                            "CR_MODEL": model,
                            "CR_DEADLINE": deadline,
                            "CR_MAX_CALLS": a.max_calls,
                        },
                        secrets=harness.secrets(),
                        resolvers=[ns for ns in a.player_dns.split(",") if ns.strip()],
                        plane=PLANE_OF[team],
                    )
                )
            )
            log.info("The %s team is played by %s, at %s", team, harness.name, seats[team])
        if not engaged:
            return
        log.info("Engagement: %.0fs at most, until both players have stopped", a.engagement_s)
        with ctx.phase(ENGAGEMENT):
            while time.time() < deadline and not all(p.exited for p in started):
                ctx.observe(min(2.0, max(0.0, deadline - time.time())))
                # The players' transcripts are read here: without this pull a
                # run that polls nothing would never see a player stop.
                ctx.poll()
