#!/usr/bin/env python3
"""vuln_app.py — a deliberately-vulnerable "diagnostics" web app, the IT-zone
attack surface of the cyber-physical scenario. It runs on the HMI/SCADA host
(hmi) and is the foothold the active attacker exploits before pivoting to the
OT segment from the one IT host the boundary firewall trusts.

*** This app is intentionally insecure. It exists only inside the sandboxed
Kathará lab to provide a real exploit → real RCE → real pivot chain for the
prototype. Never deploy it anywhere reachable. ***

The /diag endpoint runs a shell `ping` against a caller-supplied host without
sanitising it — a textbook OS command injection (`host=...; <cmd>`). Copied flat
onto the hmi machine (see the scenario's guest_files.py). Stdlib only.
"""

import argparse
import json
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ACCESS_LOG = None  # set in main(); JSONL request log the IT sensor tails


def _access(src, path, target):
    if not ACCESS_LOG:
        return
    try:
        with open(ACCESS_LOG, "a") as f:
            f.write(
                json.dumps({"t": round(time.time(), 3), "src": src, "path": path, "target": target})
                + "\n"
            )
            f.flush()
    except OSError:
        pass


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode(errors="replace"))

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/health"):
            self._send(200, "nanogrid diagnostics service\n")
            return
        if u.path == "/diag":
            qs = parse_qs(u.query)
            target = (qs.get("target") or qs.get("host") or ["127.0.0.1"])[0]
            _access(self.client_address[0], u.path, target)
            # VULNERABLE ON PURPOSE: unsanitised input into a shell command.
            cmd = "ping -c 1 " + target
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                self._send(200, out.stdout + out.stderr)
            except Exception as e:
                self._send(500, f"error: {e}\n")
            return
        self._send(404, "not found\n")

    def log_message(self, *a):  # keep the lab console quiet
        pass


def main():
    ap = argparse.ArgumentParser(description="Deliberately-vulnerable lab web app")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument(
        "--access-log", default=None, help="JSONL request log for the IT sensor (off by default)"
    )
    args = ap.parse_args()
    global ACCESS_LOG
    ACCESS_LOG = args.access_log
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True
    print(f"vuln_app listening on {args.host}:{args.port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
