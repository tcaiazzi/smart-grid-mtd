#!/usr/bin/env python3
"""it_sensor.py — IT-side sensor on the HMI host for the cyber-physical scenario.

The OT DPI sensor (ot_sensor.py) sees only Modbus, so the attacker's first steps
— exploiting the web app and running commands on the HMI — are invisible to it.
This sensor watches the HMI host itself and makes those steps observable, so the
defence can act before the plant is touched. Three sources:

  1. the diagnostics app's access log  -> web_injection_pattern  (it_access, T1190)
     a /diag target that is not a plain host (shell metacharacters)
  2. the process table (/proc)          -> web_child_process      (it_exec, T1059)
     a descendant of the web server whose command is not a learned-normal one
  3. open connections (/proc/net/tcp)   -> unexpected_modbus_client (pivot)
     a new local port connected to the engine's Modbus endpoint

What is "normal" (the diagnostic children the operator spawns, the legitimate
Modbus client's connection) is learned during the first --learn-seconds, exactly
like the OT model. Findings share the ot_finding shape (detector="it") so the
same mapping/responder consume them. Copied flat onto the HMI; stdlib only.
"""

import argparse
import json
import os
import re
import time

from mtd_telemetry import Telemetry  # flat import; copied alongside on the guest

# A legitimate /diag target is a bare host or IP; anything else is suspicious.
PLAIN_HOST_RE = re.compile(r"^[A-Za-z0-9._-]+$")
INJECTION_CHARS = set(";|&`$()<>\n\\'\"")
# Diagnostic children an operator's "ping" legitimately spawns.
SEED_NORMAL_COMMS = {"sh", "bash", "dash", "ping", "ping6", "sleep"}
IT_DETECTOR = "it"


def is_injection(target):
    t = target or ""
    return bool(set(t) & INJECTION_CHARS) or not PLAIN_HOST_RE.match(t)


def descendants(procs, root_pids):
    """PIDs under any of ``root_pids`` (exclusive). ``procs``: [{pid,ppid,...}]."""
    by_parent = {}
    for p in procs:
        by_parent.setdefault(p["ppid"], []).append(p["pid"])
    seen, stack = set(), list(root_pids)
    while stack:
        for child in by_parent.get(stack.pop(), []):
            if child not in seen:
                seen.add(child)
                stack.append(child)
    return seen


class ITSensor:
    def __init__(
        self,
        engine_ip,
        engine_port,
        learn_seconds=45.0,
        telemetry=None,
        app_match="vuln_app.py",
        t0=None,
    ):
        self.engine_ip, self.engine_port = engine_ip, int(engine_port)
        self.learn_seconds = float(learn_seconds)
        # NB: an empty Telemetry is falsy (__len__ == 0), so test "is not None".
        self.tel = telemetry if telemetry is not None else Telemetry()
        self.app_match = app_match
        self._t0 = t0
        self.normal_comms = set(SEED_NORMAL_COMMS)
        self.normal_ports = set()
        self._seen_web = set()
        self._seen_proc = set()
        self._seen_port = set()

    def _learning(self, now):
        if self._t0 is None:
            self._t0 = now
        return now < self._t0 + self.learn_seconds

    def _finding(self, klass, node, confidence, src, evidence):
        return {
            "detector": IT_DETECTOR,
            "klass": klass,
            "reasons": [klass],
            "confidence": round(confidence, 3),
            "maps_to": node,
            "entities": {"src": src, "dst": None, "unit": None, "register": None, "name": None},
            "evidence": evidence,
        }

    def _emit(self, finding, now):
        self.tel.emit("ot_finding", t=round(now, 3), **finding)

    # ── sources (parsed observations in, findings out) ───────────────────────
    def observe_web(self, entries, now=None):
        now = time.time() if now is None else now
        learning = self._learning(now)
        for e in entries:
            target = e.get("target", "")
            if not is_injection(target):
                continue
            key = (e.get("src"), target)
            if learning or key in self._seen_web:
                continue
            self._seen_web.add(key)
            self._emit(
                self._finding(
                    "web_injection_pattern",
                    "it_access",
                    0.9,
                    e.get("src"),
                    {"target": target[:120], "path": e.get("path")},
                ),
                now,
            )

    def observe_procs(self, procs, now=None):
        now = time.time() if now is None else now
        learning = self._learning(now)
        app_pids = {p["pid"] for p in procs if self.app_match in (p.get("cmdline") or "")}
        for pid in descendants(procs, app_pids):
            p = next((x for x in procs if x["pid"] == pid), None)
            if p is None:
                continue
            comm = p.get("comm", "")
            if learning:
                self.normal_comms.add(comm)
                continue
            if comm in self.normal_comms or pid in self._seen_proc:
                continue
            self._seen_proc.add(pid)
            self._emit(
                self._finding(
                    "web_child_process",
                    "it_exec",
                    0.9,
                    None,
                    {"pid": pid, "comm": comm, "cmdline": (p.get("cmdline") or "")[:120]},
                ),
                now,
            )

    def observe_conns(self, conns, now=None):
        now = time.time() if now is None else now
        learning = self._learning(now)
        for c in conns:
            if (
                c.get("raddr_ip") != self.engine_ip
                or int(c.get("raddr_port", 0)) != self.engine_port
            ):
                continue
            port = int(c.get("laddr_port", 0))
            if learning:
                self.normal_ports.add(port)
                continue
            if port in self.normal_ports or port in self._seen_port:
                continue
            self._seen_port.add(port)
            self._emit(
                self._finding(
                    "unexpected_modbus_client",
                    "pivot",
                    0.85,
                    None,
                    {"laddr_port": port, "state": c.get("state")},
                ),
                now,
            )

    # ── live sources (production) ────────────────────────────────────────────
    def scan_procs(self):
        procs = []
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/stat") as f:
                    fields = f.read().rsplit(")", 1)
                comm = fields[0].split("(", 1)[1]
                ppid = int(fields[1].split()[1])
                with open(f"/proc/{pid}/cmdline") as f:
                    cmdline = f.read().replace("\x00", " ").strip()
            except (OSError, IndexError, ValueError):
                continue
            procs.append({"pid": int(pid), "ppid": ppid, "comm": comm, "cmdline": cmdline})
        return procs

    def scan_conns(self):
        want = _hex_endpoint(self.engine_ip, self.engine_port)
        conns = []
        try:
            with open("/proc/net/tcp") as f:
                next(f, None)
                for line in f:
                    cols = line.split()
                    if len(cols) < 4 or cols[2].upper() != want:
                        continue
                    lp = int(cols[1].split(":")[1], 16)
                    conns.append(
                        {
                            "laddr_port": lp,
                            "raddr_ip": self.engine_ip,
                            "raddr_port": self.engine_port,
                            "state": cols[3],
                        }
                    )
        except OSError:
            pass
        return conns

    def run(self, access_log, interval=0.5, duration=0.0):
        self.tel.emit(
            "sensor_up",
            role="it_sensor",
            engine=self.engine_ip,
            port=self.engine_port,
            learn_seconds=self.learn_seconds,
        )
        start = time.time()
        pos = 0
        while True:
            now = time.time()
            if duration and now - start >= duration:
                break
            self.observe_procs(self.scan_procs(), now)
            self.observe_conns(self.scan_conns(), now)
            pos = self._read_access(access_log, pos, now)
            time.sleep(interval)

    def _read_access(self, path, pos, now):
        if not path or not os.path.exists(path):
            return pos
        try:
            with open(path) as f:
                f.seek(pos)
                entries = []
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                pos = f.tell()
            self.observe_web(entries, now)
        except OSError:
            pass
        return pos


def _hex_endpoint(ip, port):
    """IP:port -> the /proc/net/tcp rem_address hex (little-endian IP, be port)."""
    octets = [int(x) for x in ip.split(".")]
    ip_hex = "".join(f"{o:02X}" for o in reversed(octets))
    return f"{ip_hex}:{port:04X}"


def main():
    ap = argparse.ArgumentParser(description="IT-side sensor on the HMI host")
    ap.add_argument("--engine-ip", required=True)
    ap.add_argument("--engine-port", type=int, default=5020)
    ap.add_argument("--access-log", default="/vuln_app.access.jsonl")
    ap.add_argument("--app-match", default="vuln_app.py")
    ap.add_argument("--learn-seconds", type=float, default=45.0)
    ap.add_argument("--telemetry-file", default="it_telemetry.jsonl")
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--duration", type=float, default=0.0)
    args = ap.parse_args()
    sensor = ITSensor(
        args.engine_ip,
        args.engine_port,
        learn_seconds=args.learn_seconds,
        telemetry=Telemetry(args.telemetry_file),
        app_match=args.app_match,
    )
    print(
        f"it_sensor on HMI: engine {args.engine_ip}:{args.engine_port}, "
        f"learn {args.learn_seconds}s",
        flush=True,
    )
    sensor.run(args.access_log, interval=args.interval, duration=args.duration)


if __name__ == "__main__":
    main()
