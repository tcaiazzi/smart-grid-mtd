#!/usr/bin/env python3
"""red_console.py — the red team's console: the attack's steps, run on demand.

The attacker's planner chooses its steps by itself; here a person does. The
console is given the steps of the attack tree as data — each with the command
that realises it on this node — and runs the one asked for, keeping what came
of it. It decides nothing and knows nothing of the target beyond those steps.

    GET  /             the console page (red_console.html)
    GET  /state        {"steps": [...], "history": [...], "terminal": url}
    POST /steps/<id>   run the step now; answers with its outcome

Everything but the page carries ``Authorization: Bearer <token>``.

Every run is appended to --record as one JSON line ({"kind": "red_step", ...}
with the step's own machine-readable lines under "phases"): the range reads it
to know what the red team did. Copied flat onto the attacker node. Stdlib only.
"""

import argparse
import base64
import hmac
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "red_console.html")
STEP_TIMEOUT_S = 60.0
OUTPUT_TAIL = 2000
HISTORY_KEPT = 200


def run_shell(cmd):
    """-> (rc, output). From "/", where the node's tools are staged."""
    try:
        p = subprocess.run(
            ["sh", "-c", cmd], cwd="/", capture_output=True, text=True, timeout=STEP_TIMEOUT_S
        )
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {STEP_TIMEOUT_S:.0f}s"


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

    def launch(self, step_id, operator=None):
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
                "ok": bool(said[-1]) if said else rc == 0,
                "rc": rc,
                "duration_s": round(self.clock() - started, 3),
                "operator": operator,
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
            steps.append(s)
        return {"now": round(self.clock(), 3), "steps": steps, "history": history}


class RedConsole:
    def __init__(self, bench, token, port=0, host="0.0.0.0", page=PAGE, terminal=None):
        if not token:
            raise ValueError("the red console needs a token: it will not serve unauthenticated")
        self.bench, self.token, self.page, self.terminal = bench, str(token), page, terminal
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
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self):
                if not self._authorized():
                    self._reply(401, {"error": "a bearer token is required"})
                    return
                parts = self.path.split("?")[0].strip("/").split("/")
                if len(parts) != 2 or parts[0] != "steps":
                    self._reply(404, {"error": "not found"})
                    return
                operator = None
                try:
                    length = min(int(self.headers.get("Content-Length") or 0), 4096)
                    if length > 0:
                        operator = json.loads(self.rfile.read(length)).get("operator")
                except (ValueError, AttributeError):
                    pass  # the operator's name is optional; a bad body names nobody
                row = console.bench.launch(parts[1], str(operator)[:80] if operator else None)
                if row is None:
                    self._reply(404, {"error": "no such step"})
                else:
                    self._reply(200, row)

            def log_message(self, *_args):
                pass

        return Handler


def main():
    ap = argparse.ArgumentParser(description="Red team console: the attack's steps on demand")
    ap.add_argument("--steps-b64", required=True, help="the steps, base64 of a JSON list")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--token", required=True)
    ap.add_argument("--record", default="/red_actions.jsonl")
    ap.add_argument("--terminal", default=None, help="URL of the team's web terminal")
    args = ap.parse_args()
    steps = json.loads(base64.b64decode(args.steps_b64))
    console = RedConsole(Bench(steps, args.record), args.token, args.port, terminal=args.terminal)
    print(f"red console on port {console.port}, {len(steps)} steps", flush=True)
    console.httpd.serve_forever()


if __name__ == "__main__":
    main()
