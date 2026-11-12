#!/usr/bin/env python3
"""soc_operator.py — the SOC's operator interface: suggestions out, verdicts in.

When the SOC advises instead of acting, every countermeasure it would run
waits here for a person. This module is the whole of that interface: the desk
that holds what is waiting, and the HTTP API a console reads it from and
answers it through. The analytics (soc_analytics.py) opens a suggestion,
collects the verdicts at its next step and closes it; a console never reaches
further into the SOC than this.

    GET  /approvals        {"now", "pending": [...], "closed": [...]}
    POST /approvals/<id>   {"verdict": "approve" | "reject", "operator": "name"}

Every request carries ``Authorization: Bearer <token>``. A browser console is
served from another origin, so the API answers CORS for the origins it was
given and for no other.

Copied flat onto the SOC node, imported by soc_analytics.py. Stdlib only.
"""

import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERDICTS = ("approve", "reject")
MAX_BODY = 4096  # a verdict is a few dozen bytes; anything longer is not one
CLOSED_KEPT = 200  # closed suggestions kept for a console that connects late


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

    def open(self, request, suggestion):
        with self._lock:
            self._pending[request] = {"request": request, **suggestion}

    def close(self, request, state, **fields):
        """The analytics' last word on a suggestion: granted, rejected, expired."""
        with self._lock:
            s = self._pending.pop(request, None)
            self._decided.discard(request)
            if s is None:
                return
            self._closed.append({**s, "state": state, "closed_t": round(self.clock(), 3), **fields})
            del self._closed[:-CLOSED_KEPT]

    def listing(self):
        with self._lock:
            pending = [
                {**s, "state": "decided" if r in self._decided else "requested"}
                for r, s in self._pending.items()
            ]
            return {"now": round(self.clock(), 3), "pending": pending, "closed": list(self._closed)}

    def submit(self, request, verdict, operator=None):
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
                }
            )
            return "ok"

    def take(self):
        with self._lock:
            out, self._verdicts = self._verdicts, []
            return out


class OperatorApi:
    """The desk over HTTP. Refuses to exist without a token: an open port that
    applies countermeasures for whoever asks is the attacker's best tool."""

    def __init__(self, desk, token, port=0, host="0.0.0.0", origins=()):
        if not token:
            raise ValueError("the operator API needs a token: it will not serve unauthenticated")
        self.desk, self.token = desk, str(token)
        self.origins = {o.strip().rstrip("/") for o in origins if o and o.strip()}
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
            def _reply(self, code, obj=None):
                body = b"" if obj is None else json.dumps(obj, default=str).encode()
                self.send_response(code)
                origin = (self.headers.get("Origin") or "").rstrip("/")
                if origin in api.origins:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                    self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                    self.send_header("Access-Control-Max-Age", "600")
                self.send_header("Vary", "Origin")
                self.send_header("Cache-Control", "no-store")
                if body:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self):
                given = self.headers.get("Authorization") or ""
                return hmac.compare_digest(given.encode(), f"Bearer {api.token}".encode())

            def do_OPTIONS(self):
                # The preflight carries no credentials; it only learns whether
                # its origin may ask, which the headers of _reply already say.
                self._reply(204)

            def do_GET(self):
                if not self._authorized():
                    self._reply(401, {"error": "a bearer token is required"})
                elif self.path.split("?")[0].rstrip("/") == "/approvals":
                    self._reply(200, api.desk.listing())
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self):
                if not self._authorized():
                    self._reply(401, {"error": "a bearer token is required"})
                    return
                parts = self.path.split("?")[0].strip("/").split("/")
                if len(parts) != 2 or parts[0] != "approvals":
                    self._reply(404, {"error": "not found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = -1
                if not 0 < length <= MAX_BODY:
                    self._reply(400, {"error": "a JSON verdict is required"})
                    return
                try:
                    doc = json.loads(self.rfile.read(length))
                    verdict = doc.get("verdict")
                    operator = doc.get("operator")
                except (ValueError, AttributeError):
                    self._reply(400, {"error": "the body is not a JSON object"})
                    return
                if verdict not in VERDICTS:
                    self._reply(400, {"error": f"verdict must be one of {', '.join(VERDICTS)}"})
                    return
                operator = str(operator)[:80] if operator else None
                status = api.desk.submit(parts[1], verdict, operator)
                if status == "unknown":
                    self._reply(404, {"error": "no suggestion with this id is waiting"})
                elif status == "decided":
                    self._reply(409, {"error": "this suggestion already has its verdict"})
                else:
                    self._reply(200, {"request": parts[1], "verdict": verdict})

            def log_message(self, *_args):
                pass

        return Handler
