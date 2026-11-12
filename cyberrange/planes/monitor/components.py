"""components.py — monitoring plane building blocks (see cyberrange/core).

    Capture          tcpdump on one NIC, stopped and downloaded on demand
    TelemetryMirror  live copy of every started defense component's guest
                     telemetry onto the progress ledger (via its ``mirror``)
    PlantMirror      live physical state of the CPS twin onto the ledger
    WebTerminal      a team's shell on a node, served to a browser
    RecordedShell    every command typed on a node, onto the ledger

Mirrors only read: they never write into the containers, and a failed pull
never breaks a run. The last two are how people — a red and a blue team in a
playground — get into a lab without the range losing sight of what they do.
"""

import json
import logging
import time

from cyberrange.core.component import Artifact, Component, GuestAgent, TelemetryCursor, tail_reader

log = logging.getLogger("cyberrange.planes.monitor.components")

PLANE = "monitor"


class Capture(Component):
    """tcpdump on ``node``:``iface`` into guest ``file``; downloaded to
    ``local`` (default: the same name) after ``stop_capture``."""

    plane, name = PLANE, "capture"

    def __init__(self, node, iface, file, local=None):
        self.node, self.iface, self.file = node, iface, file
        self.local = local or file

    def start(self, ctx):
        ctx.exec(self.node, f"tcpdump -i {self.iface} -w {self.file}")

    def stop_capture(self, ctx, flush_s=2.0):
        ctx.run(self.node, "pkill -INT tcpdump")
        time.sleep(flush_s)  # let tcpdump flush the file before the download

    def artifacts(self):
        return [Artifact(self.node, self.file, self.local, required=True)]


class TelemetryMirror(Component):
    """Pulls new guest telemetry of every started component that declares
    some, and emits what that component's ``mirror(ev)`` maps it to."""

    plane, name = PLANE, "telemetry_mirror"

    def __init__(self):
        self._cursors = {}

    def poll(self, ctx):
        for c in list(ctx.components):
            mirror = getattr(c, "mirror", None)
            if mirror is None:
                continue
            for src in c.telemetry():
                key = (src.node, src.path)
                cur = self._cursors.get(key)
                if cur is None:
                    cur = self._cursors[key] = TelemetryCursor(
                        tail_reader(ctx.exec_text, src.node, src.path)
                    )
                try:
                    events = cur.poll()
                except Exception as e:
                    log.debug("telemetry pull %s:%s failed: %s", src.node, src.path, e)
                    continue
                for ev in events:
                    out = mirror(ev)
                    if out:
                        ctx.emit(out[0], **out[1])

    @property
    def lines(self):
        return {k: c.lines for k, c in self._cursors.items()}


class PlantMirror(Component):
    """The CPS twin's latest frame (engine_frames.jsonl), once per new step."""

    plane, name = PLANE, "plant_mirror"

    def __init__(self, node="engine", frames="/engine_frames.jsonl"):
        self.node, self.frames = node, frames
        self.step = None

    def poll(self, ctx):
        lines = [
            x
            for x in ctx.exec_text(self.node, f"tail -n 1 {self.frames}").splitlines()
            if x.strip()
        ]
        if not lines:
            return
        fr = json.loads(lines[-1])
        if fr.get("step") == self.step:
            return
        self.step = fr.get("step")
        act = fr.get("actuators") or {}
        ctx.emit(
            "plant",
            step=fr.get("step"),
            frame_t=fr.get("timestamp"),
            v_load=fr.get("v_load"),
            v_dg=fr.get("v_dg"),
            abnormal=fr.get("abnormal"),
            line_load=fr.get("line_load"),
            p_dg=fr.get("p_dg"),
            energy_kwh=fr.get("energy_kwh"),
            dg_setpoint=act.get("dg_setpoint"),
            ctrl_mode=act.get("ctrl_mode"),
            switch_cmd=act.get("switch_cmd"),
        )


# ── people in the lab ────────────────────────────────────────────────────────
ACCESS = "bash /team-access.sh"  # nodes/common/team-access.sh, staged by the scenario


class WebTerminal(GuestAgent):
    """A shell on ``node`` served to a browser on guest ``port`` (ttyd), behind
    ``user``:``password``. Each session is transcribed whole on the node, and
    its commands are recorded like any other interactive shell's (RecordedShell
    reads them)."""

    TRANSCRIPT = "/var/log/terminal.typescript"

    def __init__(self, node, port, user, password):
        super().__init__(
            node,
            f"{ACCESS} terminal {port} {user} {password}",
            "terminal.log",
            plane=PLANE,
            name=f"terminal:{node}",
            artifacts=[Artifact(node, self.TRANSCRIPT, f"{node}.terminal.typescript")],
        )


class RecordedShell(Component):
    """The commands typed in interactive shells on ``node`` (command_audit.sh),
    put on the ledger as ``team_command`` as they are typed.

    Whose shell it is is read from how it got there, never assumed:

        ``team``      the host's own people: over SSH (from ``jump`` only, when
                      given) or through the node's WebTerminal
        ``intruder``  the other side, on a host it may take: a shell that
                      descends from ``entry`` (a fragment of the command line
                      of the service it gets in through), one such a service
                      left behind as an orphan, or SSH from anywhere but
                      ``jump``
        CONTROL       anything else — the referee's own shell on the node

    An intruder's commands, like a ``witnessed`` team's, also go to the ground
    truth — the attack as it was really carried out. CONTROL's never do: a
    referee looking around must not be scored as an attack."""

    plane = PLANE
    LOG = "/var/log/commands.jsonl"
    CONTROL = "control"
    TERMINAL = "ttyd"  # what WebTerminal serves the shell with (team-access.sh)

    def __init__(self, node, team, intruder=None, witnessed=False, jump=None, entry=None):
        self.node, self.team, self.intruder, self.witnessed = node, team, intruder, witnessed
        self.jump, self.entry = jump, entry
        self.name = f"shell:{node}"
        self._cursor = None

    def whose(self, ev):
        """The team a recorded command belongs to."""
        src, ancestry = ev.get("from"), ev.get("ancestry") or []
        if src:
            if self.jump in (None, src):
                return self.team
            return self.intruder or self.CONTROL
        if self.intruder:
            if self.entry and any(self.entry in a for a in ancestry):
                return self.intruder
        if any(a.split("/")[-1].startswith(self.TERMINAL) for a in ancestry):
            return self.team
        if self.intruder and ev.get("orphan"):
            return self.intruder
        return self.CONTROL

    def start(self, ctx):
        ctx.exec(self.node, f"{ACCESS} audit", wait=True)

    def artifacts(self):
        return [Artifact(self.node, self.LOG, f"{self.node}.commands.jsonl")]

    def poll(self, ctx):
        if self._cursor is None:
            self._cursor = TelemetryCursor(tail_reader(ctx.exec_text, self.node, self.LOG))
        for ev in self._cursor.poll():
            if ev.get("kind") != "command":  # command_end only adds the exit code
                continue
            team = self.whose(ev)
            foreign = bool(self.intruder) and team == self.intruder
            fields = dict(
                team=team,
                node=self.node,
                cmd=ev.get("cmd"),
                cwd=ev.get("cwd"),
                via=ev.get("from") or None,
                guest_t=ev.get("t"),
            )
            ctx.emit("team_command", **fields)
            witnessed = self.witnessed and team == self.team
            if (foreign or witnessed) and ctx.gt is not None:
                ctx.gt.record(
                    "command", t=ev.get("t"), **{k: fields[k] for k in ("team", "node", "cmd")}
                )
