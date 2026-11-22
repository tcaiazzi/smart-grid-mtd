#!/usr/bin/env python3
"""red_console.py — the red team's console: the attack's steps, run on demand.

The attacker's planner (red_agent.py) chooses its steps by itself; here a person
does. The console is given the attack tree as data (--tree-b64) and builds its
executable steps on this node (red_steps.build_steps) — each with the command
that realises it — then runs the one asked for, keeping what came of it. It
decides nothing and knows only what the tree tells it.

With --knowledge recon the team is given no tree. It reports what it finds in
the lab (POST /findings), and the console derives a *belief* tree from the
reports (belief_tree.py, the generator the SOC runs on its full inventory) and
lists the steps that tree makes possible, each aimed at what was reported. The
console knows no more of the lab than the team told it: a wrong report gives a
step that fails.

    GET  /             the console page (red_console.html)
    GET  /state        {"steps": [...], "history": [...], "terminal": url}
    POST /steps/<id>   run the step now; answers with its outcome
    GET  /seat         the seat: team, actions, the node's clock (seat.py)
    GET  /briefing     {"briefing": the team's briefing, Markdown}
    POST /shell        {"cmd": "...", "operator": "name"}; runs it on this node
    GET  /news         {"last": 0, "news": []}: nothing comes up here unasked
    POST /findings     (recon) what the team found; answers with the steps now listed

A POST may carry the operator's name and a "note", the reason for the action in
the operator's words; both are kept with it on record. Everything but the page
carries ``Authorization: Bearer <token>``.

Every run is appended to --record as one JSON line ({"kind": "red_step", ...}
with the step's own machine-readable lines under "phases"): the range reads it
to know what the red team did; so is every report ("recon") and the tree it
gave ("belief"). Copied flat onto the attacker node. Stdlib only — and, with
--knowledge recon, networkx through belief_tree.
"""

import argparse
import base64
import hmac
import ipaddress
import json
import os
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import red_steps
import seat
import steps
import tree_doc
from seat import without_credentials

PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "red_console.html")
STEP_TIMEOUT_S = 60.0
# Writes refused in a row after which a step stops trying: the way is cut, and
# a team is better told so in seconds than by the timeout.
GIVE_UP_AFTER = 3
OUTPUT_TAIL = 2000
HISTORY_KEPT = 200
MAX_BODY = 4096  # a name, a note and a command line; anything longer is none of them
ACTIONS = ("run_step",)
TREE, RECON = "tree", "recon"  # what the team knows of the attack: given it, or found by it
REPORT = "report_findings"  # the seat's action a team that reconnoitres has more
BELIEF = "/belief_tree.json"
# Where a step is aimed before the team has said where the engine is. Never
# reached: no step that writes to the plant is listed until then.
NOWHERE = "0.0.0.0"


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

    def replace(self, steps):
        """List ``steps`` instead of the current ones; the runs so far stay on
        record. Not while a step runs: it would end on a list that lost it."""
        with self._busy:
            self.steps = {s["id"]: s for s in steps}
            self.order = [s["id"] for s in steps]

    def note_down(self, **row):
        """One line of the record that is not a step's."""
        with self._lock:
            if self._file:
                self._file.write(json.dumps({"t": round(self.clock(), 3), **row}) + "\n")

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


def _address(value, name):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValueError(f"{name} must be an IP address") from None


def _port(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise ValueError(f"{name} must be a port number")
    return value


def _registers(value, name):
    """Register addresses, from a list or from "0,1,2"."""
    items = value.split(",") if isinstance(value, str) else value
    try:
        out = sorted({int(str(i).strip()) for i in items if str(i).strip()})
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be register addresses, as 0,1,2") from None
    if not out or min(out) < 0:
        raise ValueError(f"{name} must be register addresses, as 0,1,2")
    return out


# What a team may report, and how each is read. Flat on purpose: a report is
# typed by a person in a form, or sent by a program as a tool's arguments.
FINDINGS = {
    "foothold_ip": _address,
    "foothold_port": _port,
    "engine_ip": _address,
    "engine_port": _port,
    "registers": _registers,
    "workstation_ip": _address,
}


class Recon:
    """What the team reported so far, and the steps it gives.

    Reports add up: a team says what it found as it finds it, and a later
    report corrects an earlier one field by field. ``build`` is
    belief_tree.build, passed in so that a console that is given its tree
    never imports the generator."""

    def __init__(self, bench, build, belief_path=BELIEF, **step_options):
        self.bench, self.build, self.belief_path = bench, build, belief_path
        self.step_options = step_options
        self.known = {}
        self._lock = threading.Lock()
        self._relist()

    def findings(self):
        """The reports as belief_tree reads them."""
        k = self.known
        foothold = None
        if k.get("foothold_ip") and k.get("foothold_port"):
            foothold = {"ip": k["foothold_ip"], "port": k["foothold_port"]}
        ot = {}
        if k.get("engine_ip"):
            ot = {
                "engine_ip": k["engine_ip"],
                "modbus_port": k.get("engine_port"),
                # Only the registers the team named: an engine it found and did
                # not read gives no step that writes to it.
                "modbus_ok": False,
                "registers": {a: None for a in k.get("registers") or []},
                "workstation_ip": k.get("workstation_ip"),
            }
        return {"foothold": foothold, "ot": ot}

    def _relist(self):
        """The belief tree of what is known, and the steps it makes possible:
        those whose every prerequisite is possible too. The generator calls a
        step on the plant's network possible before any host was found there;
        such a step is neither listed nor left possible in the tree, or the
        team would be credited with a way it never found."""
        findings = self.findings()
        tree = self.build(findings)
        idx = tree_doc.index(tree)
        open_ = {i for i, n in idx.items() if tree_doc.feasible(n)}
        for i, n in idx.items():
            if steps.is_step(n) and not set(red_steps.needs(tree, i)) <= open_:
                n["feasible"] = False
        ot = findings["ot"]
        url = "http://{ip}:{port}".format(**findings["foothold"]) if findings["foothold"] else ""
        listed = red_steps.build_steps(
            tree,
            url or f"http://{NOWHERE}",
            ot.get("engine_ip") or NOWHERE,
            ot.get("modbus_port") or 0,
            **self.step_options,
        )
        self.bench.replace(listed)
        return tree, [s["id"] for s in listed]

    def report(self, doc, operator=None, note=None):
        """Take one report. -> {"known", "steps", "new"}; ValueError says what
        of it cannot be read, and then nothing of it is kept."""
        given = {k: doc[k] for k in FINDINGS if doc.get(k) is not None}
        if not given:
            raise ValueError("a report names at least one of: " + ", ".join(FINDINGS))
        read = {k: FINDINGS[k](v, k) for k, v in given.items()}
        with self._lock:
            before = set(self.bench.order)
            self.known.update(read)
            tree, listed = self._relist()
            new = [s for s in listed if s not in before]
            who = {"operator": operator, **({"note": note} if note else {})}
            told = {"reported": read, "known": dict(self.known), "steps": listed}
            self.bench.note_down(kind="recon", stage="report", **told, **who)
            self.bench.note_down(kind="belief", tree=tree)
            try:
                with open(self.belief_path, "w") as f:
                    json.dump(tree, f)
            except OSError:
                pass  # the record above holds the tree too
            return {"known": dict(self.known), "steps": listed, "new": new}


class RedConsole:
    def __init__(
        self, bench, token, port=0, host="0.0.0.0", page=PAGE, terminal=None, seat=None, recon=None
    ):
        if not token:
            raise ValueError("the red console needs a token: it will not serve unauthenticated")
        self.bench, self.token, self.page = bench, str(token), page
        self.recon = recon  # a Recon, when the team finds its own tree
        # The team's terminal is behind the same secret as this console. Its
        # link is served without it: the page adds the token it already holds.
        self.terminal, self.terminal_user = without_credentials(terminal)
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
                    link = {"terminal": console.terminal, "terminal_user": console.terminal_user}
                    known = {"known": dict(console.recon.known)} if console.recon else {}
                    self._reply(200, {**console.bench.state(), **link, **known})
                elif path == "/seat" and console.seat:
                    self._reply(200, console.seat.describe())
                elif path == "/briefing" and console.seat:
                    self._reply(200, {"briefing": console.seat.briefing})
                elif path == "/news" and console.seat:
                    # This console changes only when its team runs a step. What
                    # the defence did is not shown here: the team finds out as
                    # a person would, by a step that fails.
                    self._reply(200, {"last": 0, "news": []})
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self):
                if not self._authorized():
                    self._reply(401, {"error": "a bearer token is required"})
                    return
                parts = self.path.split("?")[0].strip("/").split("/")
                shell = parts == ["shell"] and console.seat is not None
                found = parts == ["findings"] and console.recon is not None
                if not shell and not found and (len(parts) != 2 or parts[0] != "steps"):
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
                if found:
                    try:
                        self._reply(200, console.recon.report(doc, operator, note))
                    except ValueError as e:
                        self._reply(400, {"error": str(e)})
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
    ap.add_argument("--knowledge", choices=(TREE, RECON), default=TREE)
    ap.add_argument("--tree-b64", default=None, help="attack tree document, base64 of JSON")
    ap.add_argument("--target-url", default=None, help="the way in a step uses when it names none")
    ap.add_argument(
        "--way",
        action="append",
        default=[],
        metavar="HOST=URL",
        help="a way in of the tree (its via_<HOST>) and the URL of that host's application",
    )
    ap.add_argument("--plant-b64", default=None, help="the plant, for its feeders' ratings")
    ap.add_argument("--engine-ip", default=None)
    ap.add_argument("--engine-port", type=int, default=None)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--token", required=True)
    ap.add_argument("--record", default="/red_actions.jsonl")
    ap.add_argument("--terminal", default=None, help="URL of the team's web terminal")
    ap.add_argument("--team", default="red", help="the team that sits at this console")
    ap.add_argument("--briefing-b64", default=None, help="that team's briefing, base64 of text")
    args = ap.parse_args()
    briefing = base64.b64decode(args.briefing_b64).decode() if args.briefing_b64 else ""
    options = {"interval": args.interval, "plant_b64": args.plant_b64, "give_up": GIVE_UP_AFTER}
    recon = None
    if args.knowledge == RECON:
        # Imported here: only a console whose team reconnoitres is staged the
        # tree generator, and has networkx to run it.
        import belief_tree

        bench = Bench([], args.record)
        recon = Recon(bench, belief_tree.build, **options)
    else:
        given = (args.tree_b64, args.target_url, args.engine_ip, args.engine_port)
        if any(v is None for v in given):
            ap.error("--tree-b64, --target-url, --engine-ip and --engine-port are required")
        steps = red_steps.build_steps(
            json.loads(base64.b64decode(args.tree_b64)),
            args.target_url,
            args.engine_ip,
            args.engine_port,
            ways=dict(w.split("=", 1) for w in args.way),
            **options,
        )
        bench = Bench(steps, args.record)
    # What this team knows of the attack: the tree itself, or what it finds.
    place = seat.Seat(
        args.team,
        ACTIONS + ((REPORT,) if recon else ()),
        knowledge=args.knowledge,
        briefing=briefing,
        secrets=[args.token],
    )
    console = RedConsole(
        bench, args.token, args.port, terminal=args.terminal, seat=place, recon=recon
    )
    print(f"red console on port {console.port}, {len(bench.order)} steps", flush=True)
    console.httpd.serve_forever()


if __name__ == "__main__":
    main()
