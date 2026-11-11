#!/usr/bin/env python3
"""
mtd_dashboard.py — HTTP dashboard of the live MTD defense, runs on SEMP.

Serves the events recorded by mtd_telemetry.Telemetry and the page that renders
them (mtd_dashboard.html, copied next to this file):

  GET /                     the dashboard page
  GET /api/events?since=N   {"next": N + len(events), "events": [events with index >= N]}
  GET /telemetry.jsonl      every event so far, one JSON object per line

The page polls /api/events and folds the events into its state; the same page
opened as a file replays a downloaded telemetry.jsonl.

The dashboard shows the live attack surface (active broker port/IP, SCMC source
IP), so it must only be reachable over a management interface. run_experiment.py
reaches it through a Kathará bridged interface + port forward, never over the
broker link the attacker sniffs.

Stdlib only: copied flat into the semp container next to mtd_coordinator.py.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mtd_dashboard.html")


class DashboardServer:
    def __init__(self, telemetry, port: int, host: str = "0.0.0.0", page: str = PAGE):
        self.telemetry = telemetry
        self.page = page
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self.httpd.daemon_threads = True

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, body: bytes, ctype: str) -> None:
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                url = urlparse(self.path)
                if url.path in ("/", "/index.html"):
                    try:
                        with open(server.page, "rb") as f:
                            self._send(f.read(), "text/html; charset=utf-8")
                    except OSError:
                        self.send_error(404, "mtd_dashboard.html not deployed")
                elif url.path == "/api/events":
                    try:
                        since = max(0, int(parse_qs(url.query).get("since", ["0"])[0]))
                    except ValueError:
                        since = 0
                    events = server.telemetry.events(since)
                    body = {"next": since + len(events), "events": events}
                    self._send(json.dumps(body).encode(), "application/json")
                elif url.path == "/telemetry.jsonl":
                    lines = "".join(json.dumps(e) + "\n" for e in server.telemetry.events())
                    self._send(lines.encode(), "application/x-ndjson")
                else:
                    self.send_error(404)

            def log_message(self, *_args):
                pass                       # keep coordinator.log for the MTD only

        return Handler

    def start(self) -> None:
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        print(f"[dashboard] serving on :{self.port}", flush=True)
