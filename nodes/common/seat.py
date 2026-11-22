#!/usr/bin/env python3
"""seat.py — what a team's console offers a player that is not a browser: a
description of the seat, the team's briefing, and a shell.

A person at a console has a page to read and a web terminal next to it. A
program has neither: it cannot guess which actions the console takes, and a web
terminal is a websocket made for a browser. The two consoles (soc_operator.py,
red_console.py) serve this module's three answers next to their own routes, so
that a player of any kind sits at the same seat, behind the same token:

    describe()   which team, which actions, the node's clock
    briefing     the team's briefing, as the scenario wrote it
    shell(cmd)   one command on this node, as the team's shell would run it

The shell adds no privilege — the team already has a root shell on this node —
and it is recorded where the team's typed commands are (command_audit.sh), one
line when the command starts and one when it ends, marked with the seat so the
range attributes it to the team and not to whoever else is on the node.

Copied flat onto the nodes a team has a console on. Stdlib only.
"""

import json
import os
import re
import signal
import socket
import subprocess
import threading
import time

VERSION = 1  # of the seat's contract; a client refuses one it does not know
AUDIT_LOG = "/var/log/commands.jsonl"  # command_audit.sh's, read by the range
SHELL_TIMEOUT_S = 30.0
OUTPUT_MAX = 8000  # characters of each stream sent back; the rest is cut
NOTE_MAX = 500
AGENT = "agent:"  # how a player that is not a person names itself as operator
REDACTED = "<token>"  # what a team's secret is replaced with in a record


def without_credentials(url):
    """(url with no user:password in it, the user) — for a link a console
    hands out as data. The page that shows it puts its own token back; a player
    that reads the console's state as JSON is not handed the secret in it."""
    if not url:
        return url, None
    m = re.match(r"^(\w+://)([^/@:]*)(?::[^/@]*)?@(.*)$", url)
    return (m.group(1) + m.group(3), m.group(2)) if m else (url, None)


def note_of(doc):
    """The reason a player gave for an action, or None: free text, cut short."""
    note = doc.get("note") if isinstance(doc, dict) else None
    return str(note)[:NOTE_MAX] if note else None


def run_bash(cmd, timeout=SHELL_TIMEOUT_S):
    """-> (rc, stdout, stderr). From "/", where the node's tools are staged.

    The command gets a process group of its own: at the timeout the whole group
    is killed, or a tool it started in the background would outlive the answer
    and keep the pipes open."""
    p = subprocess.Popen(
        ["bash", "-c", cmd],
        cwd="/",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
    )
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, err = p.communicate()
        return -1, out, err + f"\ntimed out after {timeout:.0f}s"


class Seat:
    """One team's seat on this node. ``actions`` are the console's own, by
    name; ``knowledge`` says what the team was told about the attack."""

    def __init__(
        self,
        team,
        actions,
        knowledge=None,
        briefing="",
        audit_log=AUDIT_LOG,
        run=run_bash,
        clock=time.time,
        secrets=(),
    ):
        self.team, self.actions, self.knowledge = team, list(actions), knowledge
        # What must not be written down as typed: the team's token. A player
        # can find it on its own node and put it in a command, and the record
        # of that command is kept with the run.
        self.secrets = [s for s in secrets if s]
        self.briefing = briefing or ""
        self.audit_log, self.run, self.clock = audit_log, run, clock
        self._lock = threading.Lock()  # the audit file, written from the API's threads
        self._n = 0

    def describe(self):
        return {
            "version": VERSION,
            "team": self.team,
            "actions": self.actions + ["shell"],
            "now": round(self.clock(), 3),
            "knowledge": self.knowledge,
        }

    def redact(self, text):
        for secret in self.secrets:
            text = text.replace(secret, REDACTED)
        return text

    def _audit(self, kind, n, cmd, operator, note, **extra):
        """One line of the node's command record, in command_audit.sh's shape."""
        cmd, note = self.redact(cmd), self.redact(note) if note else note
        row = {
            "t": round(self.clock(), 3),
            "kind": kind,
            "n": n,
            "host": socket.gethostname(),
            "user": "root",
            "tty": "",
            "from": "",
            "cwd": "/",
            "cmd": cmd,
            "ancestry": [],
            "orphan": False,
            "seat": self.team,
            "operator": operator,
            **({"note": note} if note else {}),
            **extra,
        }
        try:
            with self._lock, open(self.audit_log, "a") as f:
                f.write(json.dumps(row) + "\n")
        except OSError:
            pass  # a record, not a control: a node without the log still runs the command

    def shell(self, cmd, operator=None, note=None):
        """Run ``cmd`` and answer with what it gave. Every call starts afresh
        from "/": nothing of one command (its directory, its variables) is
        there for the next."""
        with self._lock:
            self._n += 1
            n = self._n
        self._audit("command", n, cmd, operator, note)
        rc, out, err = self.run(cmd)
        self._audit("command_end", n, cmd, operator, note, rc=rc)
        return {
            "rc": rc,
            "stdout": out[-OUTPUT_MAX:],
            "stderr": err[-OUTPUT_MAX:],
            "truncated": len(out) > OUTPUT_MAX or len(err) > OUTPUT_MAX,
        }
