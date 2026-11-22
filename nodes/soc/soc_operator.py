#!/usr/bin/env python3
"""soc_operator.py — the SOC's operator console: what the SOC sees and
proposes, and what the operator answers and orders.

The analytics (soc_analytics.py) decides; a person supervises it from here.
This module is the whole of that interface: the desk both sides meet at, and
the HTTP server a browser reaches it through. The analytics publishes its view
and opens its suggestions on the desk; at its next step it collects what the
operator answered (verdicts) and asked for (orders). A console never reaches
further into the SOC than this.

    GET  /                       the console page (soc_console.html)
    GET  /state                  the SOC's view, with the suggestions
    GET  /approvals              {"now", "pending": [...], "closed": [...]}
    POST /approvals/<id>         {"verdict": "approve" | "reject", "operator": "name"}
    POST /countermeasures/<id>   {"op": "apply" | "revert", "operator": "name"}
    POST /mode                   {"mode": "advise" | "auto", "operator": "name"}

Every POST also takes a "note": the reason for the action, in the operator's
words, kept with it on record. Given a seat (seat.py), the console serves a
player that is not a browser as well:

    GET  /seat                   the seat: team, actions, the node's clock
    GET  /briefing               {"briefing": the team's briefing, Markdown}
    POST /shell                  {"cmd": "...", "operator": "name"}; runs it on this node
    GET  /news?since=<n>         {"last": n, "news": [...]}: what came up at the desk
                                 unasked after item n; without since, only "last"

Everything but the page carries ``Authorization: Bearer <token>``; the page is
static and holds no data of its own.

Copied flat onto the SOC node, imported by soc_analytics.py. Stdlib only.
"""

import hmac
import json
import os
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERDICTS = ("approve", "reject")
OPS = ("apply", "revert")
MODES = ("advise", "auto")
PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc_console.html")
MAX_BODY = 4096  # a verdict is a few dozen bytes; anything longer is not one
CLOSED_KEPT = 200  # closed suggestions kept for a console that connects late
NEWS_KEPT = 200  # items of news kept for a player that asks late
NOTE_MAX = 500  # a reason, not a report
ACTIONS = ("answer_suggestion", "apply_countermeasure", "revert_countermeasure", "set_mode")


def without_credentials(url):
    """(url with no user:password in it, the user), for a link served as data."""
    m = re.match(r"^(\w+://)([^/@:]*)(?::[^/@]*)?@(.*)$", url or "")
    return (m.group(1) + m.group(3), m.group(2)) if m else (url, None)


def note_of(doc):
    """The reason an operator gave for an action, or None."""
    return str(doc["note"])[:NOTE_MAX] if doc.get("note") else None


class ApprovalDesk:
    """What waits for the operator, and what the operator answered.

    Shared by the analytics loop (open, take, close) and the API's threads
    (listing, submit), hence the lock. A suggestion takes one verdict: the
    first one wins, so two consoles cannot approve and reject the same thing."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self._lock = threading.Lock()
        self._pending = {}  # request id -> suggestion, in the order opened
        self._closed = []
        self._verdicts = []  # submitted, not yet taken by the analytics
        self._decided = set()
        self._orders = []  # asked for at the console, not yet taken by the analytics
        self._state = {}  # the SOC's view, as last published by the analytics
        # What a person watching the console would see come up without having
        # asked: a suggestion opened, one that lapsed. Numbered, so a player
        # that waits can ask for what is new since it last looked.
        self._news = []
        self._news_n = 0

    def _tell(self, what, suggestion):
        """One item of news. Called with the lock held."""
        self._news_n += 1
        item = {"n": self._news_n, "t": round(self.clock(), 3), "what": what}
        item.update({k: suggestion[k] for k in ("request", "action", "due_t") if k in suggestion})
        item.update(self._expiry(suggestion))
        self._news.append(item)
        del self._news[:-NEWS_KEPT]

    def _expiry(self, suggestion):
        """{"expires_in_s"} of a suggestion that says when it lapses: what a
        reader would otherwise work out from ``due_t`` and a clock of its own."""
        due = suggestion.get("due_t")
        return {} if due is None else {"expires_in_s": max(0, round(due - self.clock()))}

    def news(self, since=None):
        """{"last", "news"}: the items after number ``since``; none without it,
        which is how a player learns where "from now on" starts."""
        with self._lock:
            items = [] if since is None else [i for i in self._news if i["n"] > since]
            return {"last": self._news_n, "news": items}

    def open(self, request, suggestion):
        with self._lock:
            self._pending[request] = {"request": request, **suggestion}
            self._tell("suggestion_opened", self._pending[request])

    def close(self, request, state, **fields):
        """The analytics' last word on a suggestion: granted, rejected, expired."""
        with self._lock:
            s = self._pending.pop(request, None)
            self._decided.discard(request)
            if s is None:
                return
            if state == "expired":
                # A verdict is the player's own doing, and no news to it.
                self._tell("suggestion_expired", s)
            self._closed.append({**s, "state": state, "closed_t": round(self.clock(), 3), **fields})
            del self._closed[:-CLOSED_KEPT]

    def listing(self):
        with self._lock:
            pending = [
                {**s, **self._expiry(s), "state": "decided" if r in self._decided else "requested"}
                for r, s in self._pending.items()
            ]
            return {"now": round(self.clock(), 3), "pending": pending, "closed": list(self._closed)}

    def submit(self, request, verdict, operator=None, note=None):
        """-> "ok" | "unknown" | "decided". Queued for the analytics' next step."""
        with self._lock:
            if request not in self._pending:
                return "unknown"
            if request in self._decided:
                return "decided"
            self._decided.add(request)
            self._verdicts.append(
                {
                    "request": request,
                    "verdict": verdict,
                    "operator": operator,
                    "t": round(self.clock(), 3),
                    **({"note": note} if note else {}),
                }
            )
            return "ok"

    def take(self):
        with self._lock:
            out, self._verdicts = self._verdicts, []
            return out

    def publish(self, state):
        with self._lock:
            self._state = state

    def state(self):
        with self._lock:
            state = dict(self._state)
        return {**state, "approvals": self.listing()}

    def knows(self, countermeasure):
        with self._lock:
            return any(c["id"] == countermeasure for c in self._state.get("countermeasures", []))

    def order(self, kind, operator=None, **fields):
        """Queue something the operator asked for, for the analytics' next step."""
        with self._lock:
            self._orders.append(
                {"kind": kind, "operator": operator, "t": round(self.clock(), 3), **fields}
            )

    def take_orders(self):
        with self._lock:
            out, self._orders = self._orders, []
            return out


class OperatorApi:
    """The desk over HTTP. Refuses to exist without a token: an open port that
    applies countermeasures for whoever asks is the attacker's best tool."""

    def __init__(self, desk, token, port=0, host="0.0.0.0", page=PAGE, terminal=None, seat=None):
        if not token:
            raise ValueError(
                "the operator console needs a token: it will not serve unauthenticated"
            )
        self.desk, self.token, self.page = desk, str(token), page
        # The operator's terminal is behind the same secret as this console.
        # Its link is served without it: the page adds the token it already
        # holds, and a player reading the state as JSON is not handed it.
        self.terminal, self.terminal_user = without_credentials(terminal)
        self.seat = seat  # a seat.Seat, where a team sits at this console
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self.httpd.daemon_threads = True

    @property
    def port(self):
        return self.httpd.server_address[1]

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, name="operator-api", daemon=True).start()
        return self

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _handler(self):
        api = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Cache-Control", "no-store")
                if body:
                    self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _reply(self, code, obj=None):
                body = b"" if obj is None else json.dumps(obj, default=str).encode()
                self._send(code, body, "application/json")

            def _authorized(self):
                given = self.headers.get("Authorization") or ""
                return hmac.compare_digest(given.encode(), f"Bearer {api.token}".encode())

            def _body(self):
                """The request's JSON object, or None after replying 400."""
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = -1
                if not 0 < length <= MAX_BODY:
                    self._reply(400, {"error": "a JSON body is required"})
                    return None
                try:
                    doc = json.loads(self.rfile.read(length))
                except ValueError:
                    doc = None
                if not isinstance(doc, dict):
                    self._reply(400, {"error": "the body is not a JSON object"})
                    return None
                return doc

            def do_GET(self):
                path = self.path.split("?")[0].rstrip("/")
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                if path in ("", "/index.html"):
                    # The page is static: it shows nothing until its script
                    # presents the token to the routes below.
                    try:
                        with open(api.page, "rb") as f:
                            self._send(200, f.read(), "text/html; charset=utf-8")
                    except OSError:
                        self._reply(404, {"error": "the console page is not installed"})
                elif not self._authorized():
                    self._reply(401, {"error": "a bearer token is required"})
                elif path == "/state":
                    link = {"terminal": api.terminal, "terminal_user": api.terminal_user}
                    self._reply(200, {**api.desk.state(), **link})
                elif path == "/approvals":
                    self._reply(200, api.desk.listing())
                elif path == "/seat" and api.seat:
                    self._reply(200, api.seat.describe())
                elif path == "/briefing" and api.seat:
                    self._reply(200, {"briefing": api.seat.briefing})
                elif path == "/news" and api.seat and hasattr(api.desk, "news"):
                    try:
                        since = int(query["since"][0]) if "since" in query else None
                    except ValueError:
                        self._reply(400, {"error": "since must be a whole number"})
                        return
                    self._reply(200, api.desk.news(since))
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self):
                if not self._authorized():
                    self._reply(401, {"error": "a bearer token is required"})
                    return
                parts = self.path.split("?")[0].strip("/").split("/")
                single = ("mode",) + (("shell",) if api.seat else ())
                if parts[0] not in ("approvals", "countermeasures") + single or len(parts) != (
                    1 if parts[0] in single else 2
                ):
                    self._reply(404, {"error": "not found"})
                    return
                doc = self._body()
                if doc is None:
                    return
                operator = str(doc.get("operator"))[:80] if doc.get("operator") else None
                # Kept only when given: an action nobody explained stays as it was.
                noted = {"note": note_of(doc)} if note_of(doc) else {}
                if parts[0] == "shell":
                    if not isinstance(doc.get("cmd"), str) or not doc["cmd"].strip():
                        self._reply(400, {"error": "cmd must be a command line"})
                        return
                    # The desk's lock is not held here: a command may run for
                    # seconds, and the analytics must keep taking verdicts.
                    self._reply(200, api.seat.shell(doc["cmd"], operator, noted.get("note")))
                elif parts[0] == "mode":
                    if doc.get("mode") not in MODES:
                        self._reply(400, {"error": f"mode must be one of {', '.join(MODES)}"})
                        return
                    api.desk.order("mode", operator, mode=doc["mode"], **noted)
                    self._reply(200, {"mode": doc["mode"]})
                elif parts[0] == "countermeasures":
                    if doc.get("op") not in OPS:
                        self._reply(400, {"error": f"op must be one of {', '.join(OPS)}"})
                    elif not api.desk.knows(parts[1]):
                        self._reply(404, {"error": "the SOC has no such countermeasure"})
                    else:
                        api.desk.order(
                            "countermeasure", operator, id=parts[1], op=doc["op"], **noted
                        )
                        self._reply(200, {"id": parts[1], "op": doc["op"]})
                else:
                    verdict = doc.get("verdict")
                    if verdict not in VERDICTS:
                        self._reply(400, {"error": f"verdict must be one of {', '.join(VERDICTS)}"})
                        return
                    status = api.desk.submit(parts[1], verdict, operator, noted.get("note"))
                    if status == "unknown":
                        self._reply(404, {"error": "no suggestion with this id is waiting"})
                    elif status == "decided":
                        self._reply(409, {"error": "this suggestion already has its verdict"})
                    else:
                        self._reply(200, {"request": parts[1], "verdict": verdict})

            def log_message(self, *_args):
                pass

        return Handler
