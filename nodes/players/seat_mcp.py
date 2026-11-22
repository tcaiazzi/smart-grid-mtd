#!/usr/bin/env python3
"""seat_mcp.py — a team's seat as MCP tools: what lets a harness play.

A harness (Claude Code, or any other MCP client) cannot click a console. This
is the console for it: an MCP server on stdio that the harness starts as a
subprocess, and that turns each tool call into the request a person's browser
would have made to the seat (seat.py, served by soc_operator.py or
red_console.py), with the team's token.

It is also where every harness is held to the same terms, because the terms
are applied here and not left to each harness: the tools and their wording, the
budget of calls (--max-calls), the deadline (--deadline), and the record of
every call with how long it took and how it ended (--transcript). That record
is what the range scores a harness on, so it is written by this adapter and
never by the harness it measures.

    seat_mcp.py --url http://HOST:PORT --token-file F --operator agent:NAME
                [--deadline EPOCH] [--max-calls N] [--transcript F]

Copied flat onto a player's node. Stdlib only.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

SEAT_VERSION = 1  # of the seat's contract (seat.py); another one is refused
# The protocol revisions this server speaks. It uses only what all of them
# share: tools, resources, and newline-delimited JSON-RPC on stdio.
PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
AGENT = "agent:"  # how a player that is not a person is named in every record
# Longer than a step may run on the red console (60 s) plus the one it may be
# queued behind: a call cut short here would be recorded as failed while its
# step still runs.
HTTP_TIMEOUT_S = 150.0
NOTE = {
    "type": "string",
    "description": "Why you are doing this, in a sentence. The referees read it.",
}


def tool(name, description, properties=None, required=()):
    schema = {"type": "object", "properties": properties or {}, "required": list(required)}
    return {"name": name, "description": description, "inputSchema": schema}


def text(s):
    return {"type": "string", "description": s}


# What every seat offers, then what each of the seat's actions adds. A tool is
# listed only when the seat names its action, so a team is never shown a lever
# of the other's.
COMMON = [
    tool("read_briefing", "Your team's briefing: the lab, your goal, the rules, the scoring."),
    tool("get_state", "Everything your team's console shows right now, as JSON."),
    tool("time_left", "Seconds left in the engagement and tool calls left in your budget."),
]
BY_ACTION = {
    "shell": [
        tool(
            "shell",
            "Run one command as root on your team's node and get its exit code and output. "
            "Each call starts afresh from /: no directory, variable or background job "
            "carries over. A command is cut after 30 seconds.",
            {"cmd": text("The command line, for bash."), "note": NOTE},
            ["cmd"],
        )
    ],
    "run_step": [
        tool("list_steps", "The attack's steps: id, what each does, what it needs, its outcome."),
        tool(
            "run_step",
            "Run one step of the attack now and get what came of it. Steps run one at a time.",
            {"id": text("The step's id, from list_steps."), "note": NOTE},
            ["id"],
        ),
    ],
    "answer_suggestion": [
        tool(
            "list_suggestions",
            "The countermeasures the SOC proposes and is waiting for your verdict on, with "
            "the reasons for each and when it expires; and the ones already closed.",
        ),
        tool(
            "answer_suggestion",
            "Approve or reject one suggestion. Approved, the countermeasure runs; left "
            "unanswered, it expires and does not.",
            {
                "id": text("The suggestion's request id, from list_suggestions."),
                "verdict": {"type": "string", "enum": ["approve", "reject"]},
                "note": NOTE,
            },
            ["id", "verdict"],
        ),
    ],
    "apply_countermeasure": [
        tool("list_countermeasures", "Every countermeasure the SOC has, and which are in effect."),
        tool(
            "apply_countermeasure",
            "Apply a countermeasure on your own initiative, without waiting for a suggestion.",
            {"id": text("The countermeasure's id, from list_countermeasures."), "note": NOTE},
            ["id"],
        ),
    ],
    "revert_countermeasure": [
        tool(
            "revert_countermeasure",
            "Undo a countermeasure that is in effect.",
            {"id": text("The countermeasure's id."), "note": NOTE},
            ["id"],
        )
    ],
    "set_mode": [
        tool(
            "set_mode",
            "advise: every countermeasure waits for your verdict. auto: the SOC runs what "
            "its policy decides without asking.",
            {"mode": {"type": "string", "enum": ["advise", "auto"]}, "note": NOTE},
            ["mode"],
        )
    ],
}


# The tools that act on the lab and say nothing of how it went beyond having
# been taken: a verdict, a countermeasure, a mode.
ACTS = ("answer_suggestion", "apply_countermeasure", "revert_countermeasure", "set_mode")


class RpcError(Exception):
    """A request this server cannot serve, as a JSON-RPC error."""

    METHOD_NOT_FOUND, INVALID_PARAMS = -32601, -32602

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class SeatError(Exception):
    """The seat answered no, or did not answer."""

    def __init__(self, outcome, message):
        super().__init__(message)
        self.outcome = outcome


class Seat:
    """The seat over HTTP, as the team's browser reaches it."""

    def __init__(self, url, token, operator, timeout=HTTP_TIMEOUT_S):
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout
        # Whatever the launcher passed, the records must tell a harness from a person.
        self.operator = operator if operator.startswith(AGENT) else AGENT + operator

    def call(self, method, path, body=None):
        data = None
        headers = {"Authorization": f"Bearer {self.token}"}
        if body is not None:
            data = json.dumps({**body, "operator": self.operator}).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                why = json.loads(e.read()).get("error")
            except ValueError:
                why = None
            raise SeatError("seat_error", why or f"the seat answered {e.code}") from e
        except (OSError, ValueError) as e:
            raise SeatError("unreachable", f"the seat did not answer: {e}") from e

    def wait(self, seconds, sleep=time.sleep, clock=time.time):
        """The seat's description, once it answers. A console may come up after
        its player: the red one is started only when the engagement opens."""
        until = clock() + seconds
        while True:
            try:
                return self.call("GET", "/seat")
            except SeatError as e:
                if e.outcome != "unreachable" or clock() >= until:
                    raise
                sleep(1.0)


def bad_arguments(spec, args):
    """Why ``args`` do not fit a tool's schema, or None. Only what the tools
    here use: required names, strings, and a closed set of values."""
    if not isinstance(args, dict):
        return "the arguments must be an object"
    schema = spec["inputSchema"]
    for name in schema["required"]:
        if name not in args:
            return f"{name} is required"
    for name, value in args.items():
        prop = schema["properties"].get(name)
        if prop is None:
            return f"{name} is not an argument of {spec['name']}"
        if not isinstance(value, str):
            return f"{name} must be a string"
        if "enum" in prop and value not in prop["enum"]:
            return f"{name} must be one of {', '.join(prop['enum'])}"
    return None


class Player:
    """The tools of one seat, with the terms every harness plays under."""

    def __init__(self, seat, described, deadline=None, max_calls=None, transcript=None, clock=None):
        self.seat, self.team = seat, described.get("team")
        # The team's token must not be written down as the harness typed it:
        # the transcript is kept with the run.
        self._secret = getattr(seat, "token", None)
        self.deadline, self.max_calls = deadline, max_calls
        self.clock = clock or time.time
        self.calls = 0
        self.tools = {t["name"]: t for t in COMMON}
        for action in described.get("actions") or []:
            self.tools.update({t["name"]: t for t in BY_ACTION.get(action, [])})
        self._transcript = open(transcript, "a", buffering=1) if transcript else None

    # ── the terms ────────────────────────────────────────────────────────────
    def left(self):
        return {
            "seconds_left": None if self.deadline is None else round(self.deadline - self.clock()),
            "calls_left": None if self.max_calls is None else max(0, self.max_calls - self.calls),
        }

    @staticmethod
    def _worked(name, result):
        """Whether an action the seat carried out did what it was for: a step
        that succeeded, a command that exited 0. None for a call that only
        looks, and for one the seat does not say it of."""
        if not isinstance(result, dict):
            return None
        if name == "run_step":
            return bool(result.get("ok"))
        if name == "shell":
            return result.get("rc") == 0
        return True if name in ACTS else None

    def _log(self, tool_name, started, outcome, args, worked=None):
        if not self._transcript:
            return
        row = {
            "t": round(started, 3),
            "kind": "player_call",
            "team": self.team,
            "tool": tool_name,
            "n": self.calls,
            "duration_s": round(self.clock() - started, 3),
            "outcome": outcome,
        }
        if worked is not None:
            # "ok" above says the seat took the call; this, that the action
            # did what it was for. A step can be run and fail.
            row["result_ok"] = worked
        # What was asked for, not what came back: a step's output or a shell's
        # may hold anything, and the seat keeps its own record of both.
        row.update({k: args[k] for k in ("id", "verdict", "mode", "cmd", "note") if k in args})
        if self._secret:
            for k in ("cmd", "note"):
                if isinstance(row.get(k), str):
                    row[k] = row[k].replace(self._secret, "<token>")
        self._transcript.write(json.dumps(row) + "\n")

    # ── the tools ────────────────────────────────────────────────────────────
    def _do(self, name, a):
        s = self.seat
        noted = {"note": a["note"]} if a.get("note") else {}
        if name == "read_briefing":
            return s.call("GET", "/briefing").get("briefing") or "(no briefing was given)"
        if name == "get_state":
            return s.call("GET", "/state")
        if name == "time_left":
            return self.left()
        if name == "shell":
            return s.call("POST", "/shell", {"cmd": a["cmd"], **noted})
        if name == "list_steps":
            return s.call("GET", "/state").get("steps")
        if name == "run_step":
            return s.call("POST", f"/steps/{a['id']}", noted)
        if name == "list_suggestions":
            return s.call("GET", "/approvals")
        if name == "answer_suggestion":
            return s.call("POST", f"/approvals/{a['id']}", {"verdict": a["verdict"], **noted})
        if name == "list_countermeasures":
            return s.call("GET", "/state").get("countermeasures")
        if name in ("apply_countermeasure", "revert_countermeasure"):
            op = name.split("_")[0]
            return s.call("POST", f"/countermeasures/{a['id']}", {"op": op, **noted})
        if name == "set_mode":
            return s.call("POST", "/mode", {"mode": a["mode"], **noted})
        raise KeyError(name)

    def call(self, name, args):
        """-> (result for the harness, whether it is an error). An unknown tool
        is the caller's to report: it raises KeyError."""
        started = self.clock()
        args = args if args is not None else {}
        spec = self.tools.get(name)
        if spec is None:
            self._log(name, started, "unknown_tool", {})
            raise KeyError(name)
        self.calls += 1
        wrong = bad_arguments(spec, args)
        if wrong:
            outcome, result = "bad_arguments", wrong
        elif self.deadline is not None and started >= self.deadline:
            outcome, result = "past_deadline", "the engagement is over: no more actions are taken"
        elif self.max_calls is not None and self.calls > self.max_calls:
            outcome, result = "over_budget", "your budget of tool calls is spent"
        else:
            try:
                outcome, result = "ok", self._do(name, args)
            except SeatError as e:
                outcome, result = e.outcome, str(e)
        worked = self._worked(name, result) if outcome == "ok" else None
        self._log(name, started, outcome, args if isinstance(args, dict) else {}, worked)
        return result, outcome != "ok"


# ── MCP on stdio ─────────────────────────────────────────────────────────────
RESOURCES = {
    "seat://briefing": ("briefing", "text/markdown", "read_briefing"),
    "seat://state": ("state", "application/json", "get_state"),
}


def as_text(result):
    return result if isinstance(result, str) else json.dumps(result, indent=1, default=str)


class Server:
    """JSON-RPC 2.0, one message per line. Requests are answered in the order
    they arrive: a seat takes one action at a time anyway."""

    def __init__(self, player):
        self.player = player

    def handle(self, msg):
        """The reply to one message, or None for a notification."""
        method, rid = msg.get("method"), msg.get("id")
        if rid is None or method is None:
            return None  # a notification, or a reply to something never asked
        try:
            return {"jsonrpc": "2.0", "id": rid, "result": self._result(method, msg.get("params"))}
        except RpcError as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": e.code, "message": str(e)}}

    def _result(self, method, params):
        params = params or {}
        p = self.player
        if method == "initialize":
            asked = params.get("protocolVersion")
            return {
                "protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "seat", "version": str(SEAT_VERSION)},
                "instructions": f"You play the {p.team} team of a cyber range through these "
                "tools and nothing else. Start with read_briefing.",
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": list(p.tools.values())}
        if method == "tools/call":
            try:
                result, failed = p.call(params.get("name"), params.get("arguments"))
            except KeyError:
                # Not a tool's failure but a call to nothing: a protocol error.
                wrong = f"no tool named {params.get('name')!r}"
                raise RpcError(RpcError.INVALID_PARAMS, wrong) from None
            return {"content": [{"type": "text", "text": as_text(result)}], "isError": failed}
        if method == "resources/list":
            return {
                "resources": [
                    {"uri": uri, "name": name, "mimeType": mime}
                    for uri, (name, mime, _tool) in RESOURCES.items()
                ]
            }
        if method == "resources/read":
            uri = params.get("uri")
            if uri not in RESOURCES:
                raise RpcError(RpcError.INVALID_PARAMS, f"no resource {uri!r}")
            _name, mime, tool_name = RESOURCES[uri]
            result, _failed = p.call(tool_name, {})
            return {"contents": [{"uri": uri, "mimeType": mime, "text": as_text(result)}]}
        raise RpcError(RpcError.METHOD_NOT_FOUND, f"method {method!r} is not supported")

    def serve(self, lines=sys.stdin, out=sys.stdout):
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                error = {"code": -32700, "message": "not JSON"}
                reply = {"jsonrpc": "2.0", "id": None, "error": error}
            else:
                reply = self.handle(msg) if isinstance(msg, dict) else None
            if reply is not None:
                # One line per message: an embedded newline would split it in two.
                out.write(json.dumps(reply) + "\n")
                out.flush()


def main():
    ap = argparse.ArgumentParser(description="A team's seat as MCP tools, on stdio")
    ap.add_argument("--url", required=True, help="the team's console, http://HOST:PORT")
    ap.add_argument("--token-file", required=True, help="a file holding the team's token")
    ap.add_argument("--operator", required=True, help="how this player is named: agent:<name>")
    ap.add_argument("--deadline", type=float, default=None, help="epoch seconds; no action after")
    ap.add_argument("--max-calls", type=int, default=None, help="budget of tool calls")
    ap.add_argument("--transcript", default=None, help="JSONL record of every call")
    ap.add_argument("--wait", type=float, default=120.0, help="seconds to wait for the seat")
    args = ap.parse_args()
    with open(args.token_file) as f:
        token = f.read().strip()
    seat = Seat(args.url, token, args.operator)
    try:
        described = seat.wait(args.wait)
    except SeatError as e:
        raise SystemExit(f"seat_mcp: {e}") from e
    if described.get("version") != SEAT_VERSION:
        raise SystemExit(
            f"seat_mcp: the seat speaks version {described.get('version')!r} of its contract, "
            f"this adapter version {SEAT_VERSION}: refusing to guess what its actions mean"
        )
    Server(Player(seat, described, args.deadline, args.max_calls, args.transcript)).serve()


if __name__ == "__main__":
    main()
