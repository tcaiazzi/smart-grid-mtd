#!/usr/bin/env python3
"""cps_response.py — Wazuh active response that applies one countermeasure.

The manager asks for a countermeasure by id; this script runs the commands that
id maps to in the allowlist provisioned on this host, and nothing else. A
request never carries a command: whoever reaches the manager's API can choose
among the responses this host allows, not run code of their own on it.

Installed as /var/ossec/active-response/bin/cps-response on every host that
runs a Wazuh agent (wazuh-agent-setup.sh does it). Stdlib only.

Request (one JSON line on stdin, from wazuh-execd):
    {"command": "add", "parameters": {"extra_args": [ACTION, ID, REQUEST]}}
ACTION is "apply" or "revert", REQUEST an opaque token the requester uses to
find the outcome; a REQUEST already recorded is not run again, so a requester
that got no answer can safely ask twice. Outcome (one JSON line appended to RECORD, which the agent
also ships to the manager):
    {"kind": "cps_response", "id", "action", "request", "ok", "refused",
     "started_t", "done_t", "commands": [{"cmd", "rc", "out"}]}
"""

import json
import subprocess
import sys
import time

ALLOWLIST = "/var/ossec/etc/cps-response.json"
RECORD = "/var/ossec/logs/cps-response.jsonl"
ACTIONS = ("apply", "revert")
COMMAND_TIMEOUT_S = 20.0
OUTPUT_TAIL = 300  # characters of each command's output kept in the record


def parse_request(line):
    """(action, id, request) of an execd message; None where a field is absent."""
    try:
        args = json.loads(line)["parameters"]["extra_args"]
    except (ValueError, KeyError, TypeError):
        return None, None, None
    args = [str(a) for a in args] + [None, None, None]
    return args[0], args[1], args[2]


def run_shell(cmd):
    """Run one allowlisted command from "/", where the node's tools are staged."""
    try:
        p = subprocess.run(
            ["sh", "-c", cmd], cwd="/", capture_output=True, text=True, timeout=COMMAND_TIMEOUT_S
        )
        return p.returncode, (p.stdout + p.stderr)[-OUTPUT_TAIL:]
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {COMMAND_TIMEOUT_S:.0f}s"


def respond(action, cm_id, request, allowlist, run=run_shell, clock=time.time):
    """Apply (or revert) countermeasure ``cm_id``; returns the outcome record.
    Anything outside the allowlist is refused and runs nothing."""
    record = {
        "kind": "cps_response",
        "id": cm_id,
        "action": action,
        "request": request,
        "ok": False,
        "refused": None,
        "started_t": round(clock(), 3),
        "commands": [],
    }
    if action not in ACTIONS:
        record["refused"] = "unknown action"
    elif cm_id not in allowlist:
        record["refused"] = "countermeasure not allowed on this host"
    else:
        ok = True
        for cmd in allowlist[cm_id].get(action, []):
            rc, out = run(cmd)
            record["commands"].append({"cmd": cmd, "rc": rc, "out": out})
            ok = ok and rc == 0
        record["ok"] = ok
    record["done_t"] = round(clock(), 3)
    return record


def already_recorded(request):
    """Whether this request's outcome is on record: a repeated delivery of the
    same request must not open the breaker's restore, or a block, twice."""
    if not request:
        return False
    try:
        with open(RECORD) as f:
            return any(json.loads(line).get("request") == request for line in f if line.strip())
    except (OSError, ValueError):
        return False


def main():
    action, cm_id, request = parse_request(sys.stdin.readline())
    if already_recorded(request):
        return
    try:
        with open(ALLOWLIST) as f:
            allowlist = json.load(f)
    except (OSError, ValueError):
        allowlist = {}  # nothing provisioned: every request is refused, and recorded
    record = respond(action, cm_id, request, allowlist)
    with open(RECORD, "a") as f:
        f.write(json.dumps(record) + "\n")


if __name__ == "__main__":
    main()
