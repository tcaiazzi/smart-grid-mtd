"""components.py — monitoring plane building blocks (see cyberrange/core).

    Capture          tcpdump on one NIC, stopped and downloaded on demand
    TelemetryMirror  live copy of every started defense component's guest
                     telemetry onto the progress ledger (via its ``mirror``)
    PlantMirror      live physical state of the CPS twin onto the ledger

Mirrors only read: they never write into the containers, and a failed pull
never breaks a run.
"""

import json
import logging
import time

from cyberrange.core.component import (
    Artifact, Component, TelemetryCursor, tail_reader,
)

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
        time.sleep(flush_s)       # let tcpdump flush the file before the download

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
                        tail_reader(ctx.exec_text, src.node, src.path))
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
        lines = [x for x in ctx.exec_text(self.node, f"tail -n 1 {self.frames}").splitlines()
                 if x.strip()]
        if not lines:
            return
        fr = json.loads(lines[-1])
        if fr.get("step") == self.step:
            return
        self.step = fr.get("step")
        act = fr.get("actuators") or {}
        ctx.emit("plant", step=fr.get("step"), frame_t=fr.get("timestamp"),
                 v_load=fr.get("v_load"), v_dg=fr.get("v_dg"), abnormal=fr.get("abnormal"),
                 line_load=fr.get("line_load"), p_dg=fr.get("p_dg"),
                 energy_kwh=fr.get("energy_kwh"), dg_setpoint=act.get("dg_setpoint"),
                 ctrl_mode=act.get("ctrl_mode"), switch_cmd=act.get("switch_cmd"))
