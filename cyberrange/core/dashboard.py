"""dashboard.py — host-side progress dashboard of the platform, for every
scenario. It serves dashboard.html and the progress ledgers (cyberrange/core/progress.py)
found under --root: campaigns (cyberrange/core/campaign.py) and standalone
runs (cyberrange/core/lifecycle.py). The page shows what is common (queue,
phases, ETA, mean [95% CI]) for any scenario, plus each scenario's own panel
(its panel.js: the run detail, its results tables, its structure views).

It only READS files: it never touches the lab, can be started before, during
or after a campaign, and shows finished or interrupted campaigns as well as the
one running now. Same pattern as cyberrange/planes/defense/agents/mtd_dashboard.py (stdlib
ThreadingHTTPServer, the page polls, no CDN), but over files on the host.

Endpoints:
  GET /                         the page
  GET /graph.js                 topology / knowledge-graph / attack-tree drawing
  GET /api/ledgers              [{id, kind, name, status, …}] newest first
  GET /api/events?id=&since=    {"next": seq, "events": [...]} (seq >= since)
  GET /api/structure?id=&run=   {"source": "recorded"|"rebuilt", "kg", "tree"}
                                — a run's kg.json / tree.json, when its scenario
                                records a structure; rebuilt from the current
                                lab model when the run predates them

Only ledgers discovered under --root are served (the id is looked up, never
joined into a path); a run is served only if the ledger names it, and its
directory must resolve under --root. The server binds 127.0.0.1 by default.

Run: python -m cyberrange.core.dashboard --root output --port 8765
"""

import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cyberrange.core import registry
from cyberrange.core.ledgers import LedgerStore

PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


def scenario_panels():
    """The panel scripts declared by the registered scenarios (Scenario.panel_js).

    Served together as /graph.js: each panel guards its own drawing on the
    scenario of the run being shown, so a scenario without one simply draws
    nothing. The dashboard never names a scenario itself."""
    out = []
    for name in registry.names():
        try:
            path = registry.get(name).panel_js()
        except Exception:  # a scenario that cannot import
            continue
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                out.append(f.read())
    return out


class ProgressDashboard:
    def __init__(self, root, port=8765, host="127.0.0.1", page=PAGE, scenario=None):
        self.store = LedgerStore(root, scenario=scenario)
        self.page = page
        self.httpd = ThreadingHTTPServer((host, port), self._handler())
        self.httpd.daemon_threads = True

    @property
    def port(self):
        return self.httpd.server_address[1]

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, body, ctype, code=200):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _json(self, obj):
                self._send(json.dumps(obj).encode(), "application/json")

            def do_GET(self):
                url = urlparse(self.path)
                q = parse_qs(url.query)
                if url.path in ("/", "/index.html"):
                    try:
                        with open(server.page, "rb") as f:
                            self._send(f.read(), "text/html; charset=utf-8")
                    except OSError:
                        self.send_error(404, "dashboard.html missing")
                elif url.path == "/graph.js":
                    panels = scenario_panels()
                    if panels:
                        self._send(b"\n".join(panels), "text/javascript; charset=utf-8")
                    else:
                        self.send_error(404, "no scenario declares a panel")
                elif url.path == "/api/structure":
                    res = server.store.structure(q.get("id", [""])[0], q.get("run", [""])[0])
                    if res is None:
                        self.send_error(404, "unknown run")
                    elif "error" in res:
                        self.send_error(404, res["error"][:200])
                    else:
                        self._json(res)
                elif url.path == "/api/ledgers":
                    self._json(
                        {
                            "root": server.store.root,
                            "now": time.time(),
                            "ledgers": server.store.listing(),
                        }
                    )
                elif url.path == "/api/events":
                    lid = q.get("id", [""])[0]
                    try:
                        since = max(0, int(q.get("since", ["0"])[0]))
                    except ValueError:
                        since = 0
                    res = server.store.events(lid, since)
                    if res is None:
                        self.send_error(404, "unknown ledger")
                    else:
                        self._json(res)
                else:
                    self.send_error(404)

            def log_message(self, *_args):
                pass

        return Handler

    def serve_forever(self):
        self.httpd.serve_forever()

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def main():
    ap = argparse.ArgumentParser(description="Experiment progress dashboard (every scenario)")
    ap.add_argument("--root", default="output", help="where to look for progress ledgers")
    ap.add_argument(
        "--scenario",
        default=None,
        help="show only this scenario's runs and campaigns (default: all of them)",
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    os.makedirs(args.root, exist_ok=True)
    dash = ProgressDashboard(args.root, port=args.port, host=args.host, scenario=args.scenario)
    print(
        f"Progress dashboard: http://{args.host}:{dash.port}/  (root: {dash.store.root})",
        flush=True,
    )
    try:
        dash.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
