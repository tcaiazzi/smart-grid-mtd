#!/usr/bin/env python3
"""red_console.py — the red team's console: the attack's steps, run on demand.

The attacker's planner (red_agent.py) chooses its steps by itself; here a person
does. The console is given the attack tree as data (--tree-b64) and builds its
executable steps on this node (red_steps.build_steps) — each with the command
that realises it — then runs the one asked for, keeping what came of it. It
decides nothing and knows only what the tree tells it.

    GET  /             the console page (red_console.html)
    GET  /state        {"steps": [...], "history": [...], "terminal": url}
    POST /steps/<id>   run the step now; answers with its outcome
    GET  /seat         the seat: team, actions, the node's clock (seat.py)
    GET  /briefing     {"briefing": the team's briefing, Markdown}
    POST /shell        {"cmd": "...", "operator": "name"}; runs it on this node

A POST may carry the operator's name and a "note", the reason for the action in
the operator's words; both are kept with it on record. Everything but the page
carries ``Authorization: Bearer <token>``.

Every run is appended to --record as one JSON line ({"kind": "red_step", ...}
with the step's own machine-readable lines under "phases"): the range reads it
to know what the red team did. Copied flat onto the attacker node. Stdlib only.
"""

import argparse
import base64
import hmac
import json
import os
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import red_steps
import seat

PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "red_console.html")
STEP_TIMEOUT_S = 60.0
# Writes refused in a row after which a step stops trying: the way is cut, and
# a team is better told so in seconds than by the timeout.
GIVE_UP_AFTER = 3
OUTPUT_TAIL = 2000
HISTORY_KEPT = 200
MAX_BODY = 4096  # a name, a note and a command line; anything longer is none of them
ACTIONS = ("run_step",)


def run_shell(cmd, timeout=STEP_TIMEOUT_S):
    """-> (rc, output). From "/", where the node's tools are staged.

    A step cut at the timeout still did what it did until then: its output is
    kept, or the writes the plant took before the defence slowed the step down
    would be on no record, and the attack scored as one that never landed. The
    step runs in a process group of its own and the whole group is killed, or
    the step would go on writing to the plant after the console called it over."""
    p = subprocess.Popen(
        ["sh", "-c", cmd],
        cwd="/",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        start_new_session=True,
    )
    try:
        out, _err = p.communicate(timeout=timeout)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _err = p.communicate()
        return -1, f"{out}\ntimed out after {timeout:.0f}s"


def phases_of(text):
    """The machine-readable lines a step printed ({"t", "phase", ...})."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if isinstance(ev, dict) and "phase" in ev:
            out.append(ev)
    return out


class Bench:
    """The steps the team may run and what each run gave. One step at a time:
    two operators clicking together must not interleave two exploits."""

    def __init__(self, steps, record_path=None, run=run_shell, clock=time.time):
        self.steps = {s["id"]: s for s in steps}
        self.order = [s["id"] for s in steps]
        self.run, self.clock = run, clock
        self._lock = threading.Lock()  # history and file
        self._busy = threading.Lock()  # the step being run
        self._history = []
        self._file = open(record_path, "a", buffering=1) if record_path else None

    def launch(self, step_id, operator=None, note=None):
        """Run one step; returns its record, or None if there is no such step."""
        step = self.steps.get(step_id)
        if step is None:
            return None
        with self._busy:
            started = self.clock()
            rc, text = self.run(step["command"])
            phases = phases_of(text)
            # A step says so itself when it worked; one that printed nothing
            # of the kind is judged by its exit code.
            stage = step.get("stage") or step_id
            said = [p.get("ok") for p in phases if p.get("phase") == stage]
            row = {
                "t": round(started, 3),
                "kind": "red_step",
                "step": step_id,
                "stage": stage,
                **({"stage_rank": step["stage_rank"]} if "stage_rank" in step else {}),
                # How noticeable the step is, by the registry's reckoning: kept
                # with the run, so the range can say how quiet a team played.
                **(
                    {"detectability": step["detectability"]}
                    if step.get("detectability") is not None
                    else {}
                ),
                "ok": bool(said[-1]) if said else rc == 0,
                "rc": rc,
                "duration_s": round(self.clock() - started, 3),
                "operator": operator,
                **({"note": note} if note else {}),
                "phases": phases,
                "output": text[-OUTPUT_TAIL:],
            }
        with self._lock:
            self._history.append(row)
            del self._history[:-HISTORY_KEPT]
            if self._file:
                self._file.write(json.dumps(row) + "\n")
        return row

    def state(self):
        with self._lock:
            history = list(self._history)
        last = {r["step"]: r for r in history}
        done = {s for s, r in last.items() if r["ok"]}
        steps = []
        for sid in self.order:
            s = {k: v for k, v in self.steps[sid].items() if k != "command"}
            r = last.get(sid)
            s["command"] = self.steps[sid]["command"]
            s["last"] = {k: r[k] for k in ("t", "ok", "rc")} if r else None
            # Advice, not a gate: the team may try a step out of order and see it fail.
            s["ready"] = all(n in done for n in s.get("needs") or [])
            # One word for where the step stands, as the control dashboard says it.
            s["outcome"] = (
                ("done" if r["ok"] else "failed") if r else ("ready" if s["ready"] else "waiting")
            )
            steps.append(s)
        return {"now": round(self.clock(), 3), "steps": steps, "history": history}


class RedConsole:
    def __init__(self, bench, token, port=0, host="0.0.0.0", page=PAGE, terminal=None, seat=None):
        if not token:
            raise ValueError("the red console needs a token: it will not serve unauthenticated")
        self.bench, self.token, self.page, self.terminal = bench, str(token), page, terminal
        self.seat = seat  # a seat.Seat: what a player that is not a browser is served
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self.httpd.daemon_threads = True

    @property
    def port(self):
        return self.httpd.server_address[1]

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, name="red-console", daemon=True).start()
        return self

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _handler(self):
        console = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code, body, ctype="application/json"):
                self.send_response(code)
                self.send_header("Cache-Control", "no-store")
                if body:
                    self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _reply(self, code, obj):
                self._send(code, json.dumps(obj, default=str).encode())

            def _authorized(self):
                given = self.headers.get("Authorization") or ""
                return hmac.compare_digest(given.encode(), f"Bearer {console.token}".encode())

            def do_GET(self):
                path = self.path.split("?")[0].rstrip("/")
                if path in ("", "/index.html"):
                    try:
                        with open(console.page, "rb") as f:
                            self._send(200, f.read(), "text/html; charset=utf-8")
                    except OSError:
                        self._reply(404, {"error": "the console page is not installed"})
                elif not self._authorized():
                    self._reply(401, {"error": "a bearer token is required"})
                elif path == "/state":
                    self._reply(200, {**console.bench.state(), "terminal": console.terminal})
                elif path == "/seat" and console.seat:
                    self._reply(200, console.seat.describe())
                elif path == "/briefing" and console.seat:
                    self._reply(200, {"briefing": console.seat.briefing})
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self):
                if not self._authorized():
                    self._reply(401, {"error": "a bearer token is required"})
                    return
                parts = self.path.split("?")[0].strip("/").split("/")
                shell = parts == ["shell"] and console.seat is not None
                if not shell and (len(parts) != 2 or parts[0] != "steps"):
                    self._reply(404, {"error": "not found"})
                    return
                doc = {}
                try:
                    length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
                    if length > 0:
                        doc = json.loads(self.rfile.read(length))
                except ValueError:
                    pass  # the operator's name is optional; a bad body names nobody
                if not isinstance(doc, dict):
                    doc = {}
                operator = str(doc["operator"])[:80] if doc.get("operator") else None
                note = seat.note_of(doc)
                if shell:
                    if not isinstance(doc.get("cmd"), str) or not doc["cmd"].strip():
                        self._reply(400, {"error": "cmd must be a command line"})
                    else:
                        # Outside the bench's turn: a command typed while a step
                        # runs must not wait for it, as in the team's terminal.
                        self._reply(200, console.seat.shell(doc["cmd"], operator, note))
                    return
                row = console.bench.launch(parts[1], operator, note)
                if row is None:
                    self._reply(404, {"error": "no such step"})
                else:
                    self._reply(200, row)

            def log_message(self, *_args):
                pass

        return Handler


def main():
    ap = argparse.ArgumentParser(description="Red team console: the attack's steps on demand")
    ap.add_argument("--tree-b64", required=True, help="attack tree document, base64 of JSON")
    ap.add_argument("--target-url", required=True, help="the way in a step uses when it names none")
    ap.add_argument(
        "--way",
        action="append",
        default=[],
        metavar="HOST=URL",
        help="a way in of the tree (its via_<HOST>) and the URL of that host's application",
    )
    ap.add_argument("--plant-b64", default=None, help="the plant, for its feeders' ratings")
    ap.add_argument("--engine-ip", required=True)
    ap.add_argument("--engine-port", type=int, required=True)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--token", required=True)
    ap.add_argument("--record", default="/red_actions.jsonl")
    ap.add_argument("--terminal", default=None, help="URL of the team's web terminal")
    ap.add_argument("--team", default="red", help="the team that sits at this console")
    ap.add_argument("--briefing-b64", default=None, help="that team's briefing, base64 of text")
    args = ap.parse_args()
    tree = json.loads(base64.b64decode(args.tree_b64))
    steps = red_steps.build_steps(
        tree,
        args.target_url,
        args.engine_ip,
        args.engine_port,
        interval=args.interval,
        ways=dict(w.split("=", 1) for w in args.way),
        plant_b64=args.plant_b64,
        give_up=GIVE_UP_AFTER,
    )
    briefing = base64.b64decode(args.briefing_b64).decode() if args.briefing_b64 else ""
    # The console is given the attack tree itself: that is what this team knows.
    place = seat.Seat(args.team, ACTIONS, knowledge="tree", briefing=briefing)
    console = RedConsole(
        Bench(steps, args.record), args.token, args.port, terminal=args.terminal, seat=place
    )
    print(f"red console on port {console.port}, {len(steps)} steps", flush=True)
    console.httpd.serve_forever()


if __name__ == "__main__":
    main()
