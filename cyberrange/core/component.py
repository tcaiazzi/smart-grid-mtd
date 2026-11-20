"""component.py — the unit a scenario is composed of.

Each plane (cyberrange.planes.{traffic,attack,defense,monitor}) exposes its
building blocks as Components in ``cyberrange/planes/<plane>/components.py``. A scenario
picks the ones it needs, configures them and starts them from its episode;
the core then stops them and collects their artifacts; the monitor plane's
TelemetryMirror puts their telemetry on the progress ledger.

    start(ctx)      launch the component (guest processes via ctx.exec, or a
                    host thread); ctx.start(c) calls it and registers c
    stop(ctx)       stop host-side work (threads); the core calls it for every
                    started component when the episode ends, in reverse order
    artifacts()     [Artifact] the files to download after the episode
    telemetry()     [TelemetrySource] the guest telemetry files it writes
    poll(ctx)       pull live state into the ledger while the run observes;
                    must never raise (the core swallows and logs anyway)
    mirror(ev)      optional: (event, fields) the ledger keeps of one row of
                    its telemetry, or None; TelemetryMirror calls it
"""

import json
import logging
import shlex
from dataclasses import dataclass

log = logging.getLogger("core.component")


@dataclass(frozen=True)
class Artifact:
    node: str
    guest_path: str
    local_name: str  # file name inside the run's output directory
    required: bool = False  # a missing required artifact fails the run


@dataclass(frozen=True)
class TelemetrySource:
    """A guest JSONL telemetry file written by a defense component."""

    node: str
    path: str  # guest path, e.g. "/telemetry.jsonl"
    name: str = ""  # label ("ot", "it", "mtd") for consumers that care


class Component:
    plane = "core"
    name = "component"

    def start(self, ctx):
        pass

    def stop(self, ctx):
        pass

    def artifacts(self):
        return []

    def telemetry(self):
        return []

    def poll(self, ctx):
        pass

    def __repr__(self):
        return f"<{type(self).__name__} {self.name}>"


class GuestAgent(Component):
    """A process launched in one container, its output captured to a console log."""

    def __init__(
        self,
        node,
        command,
        console_log,
        plane="core",
        name=None,
        artifacts=(),
        wait=False,
        watch=None,
    ):
        self.node, self.command, self.console_log = node, command, console_log
        self.plane, self.name = plane, name or console_log.rsplit(".", 1)[0]
        self._artifacts = list(artifacts)
        self.wait = wait
        # A fragment of the process's command line (its script's name), for an
        # agent the run cannot do without: the run fails if it is found dead.
        # None for one that may end by itself.
        self.watch = watch

    def alive(self, ctx):
        """Whether the agent's process is running; always true for an agent
        nobody asked to watch."""
        if not self.watch:
            return True
        # The first letter in brackets: the pattern then does not match the
        # command line of the search itself.
        pattern = f"[{self.watch[0]}]{self.watch[1:]}"
        _out, _err, rc = ctx.run(self.node, f"pgrep -f {pattern}")
        # 1 is pgrep's "nothing matched". Any other failure (a node without
        # pgrep) says nothing about the agent, and must not fail the run.
        return rc != 1

    def start(self, ctx):
        ctx.exec(self.node, self.command, console_log=self.console_log, wait=self.wait)

    def artifacts(self):
        return [
            Artifact(self.node, f"/{self.console_log}", f"{self.node}.{self.console_log}")
        ] + self._artifacts


class SeatPlayer(GuestAgent):
    """A player that is not a person, on a node of its own: a harness
    (core/harness.py) started at a team's seat and left to play.

    The node is a sandbox. Before the harness starts, the node's firewall is
    closed around ``seat`` — (address, port, interface) of the team's console
    — and the model's API; the harness then runs as an unprivileged user, with
    its terms in the environment (``terms``: the CR_* variables its launcher
    reads). The team's ``token`` and the harness's ``secrets`` reach the node
    as files, never on a command line. ``resolvers`` are the name servers the
    node is given: a lab node has none of its own.

    What the player does is on its transcript, written on the node by the
    seat's adapter and not by the harness it measures; it is mirrored to the
    ledger as ``player_start``, ``player_call``, ``player_usage`` and
    ``player_exit``. ``exited`` turns true at the last one."""

    HOME = "/home/player"
    TRANSCRIPT = f"{HOME}/player.jsonl"
    TOKEN, TERMS, SECRETS = f"{HOME}/seat.token", f"{HOME}/terms.env", f"{HOME}/secrets.env"
    RUN = "bash /player-run.sh"  # nodes/players/player-run.sh, staged by the scenario
    EVENTS = ("player_start", "player_call", "player_usage", "player_exit")

    def __init__(
        self, node, team, harness, seat, token, terms=None, secrets=None, resolvers=(), plane="core"
    ):
        super().__init__(
            node,
            self.RUN,
            "player.log",
            plane=plane,
            name=f"player:{team}",
            artifacts=[Artifact(node, self.TRANSCRIPT, f"player-{team}.jsonl")],
        )
        self.team, self.harness, self.token = team, harness, token
        ip, port, iface = seat
        self.terms = {
            "SEAT_IP": ip,
            "SEAT_PORT": port,
            "SEAT_IFACE": iface,
            "LAUNCHER": harness.launcher,
            "RESOLVERS": " ".join(resolvers),
            "CR_SEAT_URL": f"http://{ip}:{port}",
            "CR_SEAT_TOKEN_FILE": self.TOKEN,
            "CR_TEAM": team,
            "CR_TRANSCRIPT": self.TRANSCRIPT,
            **{k: v for k, v in (terms or {}).items() if v is not None},
        }
        self.secrets = dict(secrets or {})
        self.exited = False

    @staticmethod
    def _env(values):
        return "".join(f"{k}={shlex.quote(str(v))}\n" for k, v in values.items())

    def start(self, ctx):
        ctx.upload(self.node, self.TOKEN, self.token)
        ctx.upload(self.node, self.TERMS, self._env(self.terms))
        ctx.upload(self.node, self.SECRETS, self._env(self.secrets))
        super().start(ctx)

    def telemetry(self):
        return [TelemetrySource(self.node, self.TRANSCRIPT, "player")]

    def mirror(self, ev):
        kind = ev.get("kind")
        if kind not in self.EVENTS:
            return None
        if kind == "player_exit":
            self.exited = True
        fields = {k: v for k, v in ev.items() if k not in ("kind", "t")}
        return kind, fields | {"team": self.team, "guest_t": ev.get("t")}


class TelemetryCursor:
    """Incremental reader of a guest JSONL file.

    ``read(start_line)`` returns the file from 1-based line ``start_line`` on
    (``tail -n +N``). Only complete lines are consumed: a partial last line
    (the writer is mid-write) is read again next time. Unparseable complete
    lines are skipped, so one bad line never stalls the stream."""

    def __init__(self, read):
        self.read = read
        self.lines = 0

    def poll(self):
        raw = self.read(self.lines + 1) or ""
        complete = raw.split("\n")[:-1]  # the last element is "" or a partial line
        self.lines += len(complete)
        out = []
        for line in complete:
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out


def tail_reader(exec_text, machine, path):
    """A TelemetryCursor read function over ``exec_text(machine, cmd)``."""
    return lambda start: exec_text(machine, f"tail -n +{start} {path}")
