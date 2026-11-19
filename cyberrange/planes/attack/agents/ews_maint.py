#!/usr/bin/env python3
"""ews_maint.py — the engineering workstation's remote-maintenance service.

A small HTTP endpoint through which the HMI's operators run maintenance commands
on the workstation: ``GET /run?token=...&cmd=...`` runs ``cmd`` in a shell and
returns its output. It answers one client address only and asks for a shared
token — which the HMI keeps in a configuration file, readable by whoever
executes code there. That is the weakness: nothing is wrong with the service,
its credential lives on a host that can be taken.

Copied flat onto the engineering workstation (see the scenario's
guest_files.py). Stdlib only.
"""

import argparse
import hmac
import json
import subprocess
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RUN_TIMEOUT_S = 10.0


def make_handler(token, allow, access_log=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _note(self, **fields):
            if not access_log:
                return
            with open(access_log, "a") as fh:
                row = {"t": round(time.time(), 3), "client": self.client_address[0], **fields}
                fh.write(json.dumps(row) + "\n")

        def _reply(self, status, body):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(url.query)
            if url.path != "/run":
                return self._reply(404, "not found\n")
            if allow and self.client_address[0] not in allow:
                self._note(status=403, reason="client")
                return self._reply(403, "forbidden\n")
            if not hmac.compare_digest(q.get("token", [""])[0], token):
                self._note(status=403, reason="token")
                return self._reply(403, "forbidden\n")
            cmd = q.get("cmd", [""])[0]
            self._note(status=200, cmd=cmd)
            try:
                out = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=RUN_TIMEOUT_S, cwd="/"
                )
                body = out.stdout + out.stderr
            except subprocess.TimeoutExpired:
                body = f"timed out after {RUN_TIMEOUT_S:.0f}s\n"
            self._reply(200, body)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Remote-maintenance service of the workstation")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--token", required=True, help="shared secret every request must carry")
    ap.add_argument(
        "--allow", action="append", default=[], help="client address served (repeatable)"
    )
    ap.add_argument("--access-log", default=None, help="one JSON line per request")
    args = ap.parse_args()
    handler = make_handler(args.token, set(args.allow), args.access_log)
    ThreadingHTTPServer((args.host, args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
