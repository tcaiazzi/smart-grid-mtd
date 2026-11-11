"""component.py — the unit a scenario is composed of.

Each plane (attack_plane, defense_plane, traffic_generator, monitor) exposes
its building blocks as Components in ``<plane>/components.py``. A scenario
picks the ones it needs, configures them and starts them from its episode;
the core then stops them, collects their artifacts and mirrors their
telemetry onto the progress ledger.

    start(ctx)      launch the component (guest processes via ctx.exec, or a
                    host thread); ctx.start(c) calls it and registers c
    stop(ctx)       stop host-side work (threads); the core calls it for every
                    started component when the episode ends, in reverse order
    artifacts()     [Artifact] the files to download after the episode
    telemetry()     [TelemetrySource] the guest telemetry files it writes
    poll(ctx)       pull live state into the ledger while the run observes;
                    must never raise (the core swallows and logs anyway)
"""

import json
import logging
from dataclasses import dataclass

log = logging.getLogger("core.component")


@dataclass(frozen=True)
class Artifact:
    node: str
    guest_path: str
    local_name: str          # file name inside the run's output directory
    required: bool = False   # a missing required artifact fails the run


@dataclass(frozen=True)
class TelemetrySource:
    """A guest JSONL telemetry file written by a defense component."""
    node: str
    path: str                # guest path, e.g. "/telemetry.jsonl"
    name: str = ""           # label ("ot", "it", "mtd") for consumers that care


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

    def __init__(self, node, command, console_log, plane="core", name=None,
                 artifacts=(), wait=False):
        self.node, self.command, self.console_log = node, command, console_log
        self.plane, self.name = plane, name or console_log.rsplit(".", 1)[0]
        self._artifacts = list(artifacts)
        self.wait = wait

    def start(self, ctx):
        ctx.exec(self.node, self.command, console_log=self.console_log, wait=self.wait)

    def artifacts(self):
        return [Artifact(self.node, f"/{self.console_log}", f"{self.node}.{self.console_log}")] \
            + self._artifacts


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
        complete = raw.split("\n")[:-1]     # the last element is "" or a partial line
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
