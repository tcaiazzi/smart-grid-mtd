"""cps_dashboard.py — host-side progress dashboard for the cyber-physical
experiments. It serves cps_dashboard.html and the progress ledgers
(monitor/progress.py) found under --root: campaigns written by
network_scenario/cps_campaign.py and standalone `make cps-lab/cps-attack` runs.

It only READS files: it never touches the lab, can be started before, during
or after a campaign, and shows finished or interrupted campaigns as well as the
one running now. Same pattern as defense_plane/agents/mtd_dashboard.py (stdlib
ThreadingHTTPServer, the page polls, no CDN), but over files on the host.

Endpoints:
  GET /                         the page
  GET /api/ledgers              [{id, kind, name, status, …}] newest first
  GET /api/events?id=&since=    {"next": seq, "events": [...]} (seq >= since)

Only ledgers discovered under --root are served (the id is looked up, never
joined into a path), and the server binds 127.0.0.1 by default.

Run: python -m monitor.cps_dashboard --root output/cps --port 8765
"""

import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cps_dashboard.html")
LEDGER_NAME = "progress.jsonl"
STALE_S = 30.0          # an unfinished ledger idle this long is "interrupted"


class _Ledger:
    """Incrementally parsed ledger file (by byte offset; a partial last line
    is kept for the next read)."""

    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.tail = b""
        self.events = []

    def refresh(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        if size < self.offset:                       # truncated / rewritten
            self.offset, self.tail, self.events = 0, b"", []
        if size == self.offset:
            return
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            chunk = f.read(size - self.offset)
        self.offset = size
        data = self.tail + chunk
        lines = data.split(b"\n")
        self.tail = lines.pop()                      # b"" if data ended with \n
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                self.events.append(json.loads(raw))
            except json.JSONDecodeError:
                continue


def summarize(events, mtime, now=None):
    """Status/progress summary of one ledger's events."""
    now = time.time() if now is None else now
    first = events[0] if events else {}
    kind = "campaign" if first.get("kind") == "campaign_start" else "run"
    s = {"kind": kind, "events": len(events), "mtime": round(mtime, 3),
         "started": first.get("t"), "last_t": events[-1].get("t") if events else None}
    if kind == "campaign":
        starts = [i for i, e in enumerate(events) if e.get("kind") == "campaign_start"]
        cur = events[starts[-1]:]
        head = cur[0]
        s["name"] = head.get("name")
        s["total"] = len(head.get("grid") or [])
        finished = {e.get("run_id") for e in cur if e.get("kind") in ("run_metrics", "run_skipped")}
        failed = {e.get("run_id") for e in cur if e.get("kind") == "run_failed"}
        s["done"], s["failed"] = len(finished), len(failed - finished)
        end = next((e for e in reversed(cur) if e.get("kind") == "campaign_end"), None)
        status = end.get("status") if end else None
    else:
        start = next((e for e in reversed(events) if e.get("kind") == "run_start"), {})
        s["name"] = start.get("run_id") or first.get("run_id")
        s["mode"], s["seed"] = start.get("mode"), start.get("seed")
        end = None
        if start:
            idx = events.index(start)
            end = next((e for e in events[idx:] if e.get("kind") == "run_end"), None)
        status = end.get("status") if end else None
    if status is None:
        status = "running" if now - mtime < STALE_S else "interrupted"
    s["status"] = status
    return s


class LedgerStore:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self._lock = threading.Lock()
        self._ledgers = {}           # id (relative path) -> _Ledger

    def discover(self):
        found = {}
        for dirpath, _dirs, files in os.walk(self.root):
            if LEDGER_NAME in files:
                full = os.path.join(dirpath, LEDGER_NAME)
                found[os.path.relpath(full, self.root)] = full
        with self._lock:
            for lid, full in found.items():
                if lid not in self._ledgers:
                    self._ledgers[lid] = _Ledger(full)
            for lid in list(self._ledgers):
                if lid not in found:
                    del self._ledgers[lid]
        return found

    def get(self, lid):
        with self._lock:
            led = self._ledgers.get(lid)
            if led is not None:
                led.refresh()
            return led

    def listing(self, now=None):
        self.discover()
        out = []
        with self._lock:
            items = list(self._ledgers.items())
        for lid, led in items:
            with self._lock:
                led.refresh()
                events = list(led.events)
            try:
                mtime = os.path.getmtime(led.path)
            except OSError:
                continue
            out.append({"id": lid, **summarize(events, mtime, now)})
        out.sort(key=lambda x: (x["status"] != "running", -(x["last_t"] or x["mtime"])))
        return out

    def events(self, lid, since=0):
        led = self.get(lid)
        if led is None:
            self.discover()
            led = self.get(lid)
        if led is None:
            return None
        with self._lock:
            evs = [e for e in led.events if e.get("seq", 0) >= since]
        nxt = (evs[-1].get("seq", since) + 1) if evs else since
        return {"next": nxt, "events": evs}


class ProgressDashboard:
    def __init__(self, root, port=8765, host="127.0.0.1", page=PAGE):
        self.store = LedgerStore(root)
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
                        self.send_error(404, "cps_dashboard.html missing")
                elif url.path == "/api/ledgers":
                    self._json({"root": server.store.root, "now": time.time(),
                                "ledgers": server.store.listing()})
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
    ap = argparse.ArgumentParser(description="CPS experiment progress dashboard")
    ap.add_argument("--root", default="output/cps", help="where to look for progress ledgers")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    os.makedirs(args.root, exist_ok=True)
    dash = ProgressDashboard(args.root, port=args.port, host=args.host)
    print(f"CPS progress dashboard: http://{args.host}:{dash.port}/  (root: {dash.store.root})",
          flush=True)
    try:
        dash.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
