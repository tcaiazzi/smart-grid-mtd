"""Labelled windows for the delivery-attack detector, from recorded runs.

For every run directory holding telemetry.jsonl (the SEMP's MTD telemetry),
ground_truth.jsonl (the host's record of blackholes and benign faults, see
network_scenario/detection_scenario.py) and the SCMC / router captures, this replays
the telemetry through delivery_detector.replay — the exact featurizer the SEMP runs
live — and labels each 1 s window:

  label = 1  while a blackhole is in effect on the SCMC <-> SEMP path.

"In effect" is judged from the captures, never from the SEMP's own view (that is
what the detector sees, so labelling from it would be circular):

  • it starts when a block lands on an address the path uses — the SCMC's source or
    the broker, read from the SCMC's own packets on link A (scmc_capture.pcap): its
    MQTT data and its MQTT connection attempts (SYNs), carried forward while the SCMC
    is stalled — or when the path moves onto an already blocked address. The SYNs
    matter: a source hop onto a blocked address leaves the executor retrying its
    connect from there, sending no data at all;
  • it is released when the block is lifted or the path moves off that address;
  • it ends when the broker receives nanogrid data again after the release — the
    first "Received PUBLISH from <scmc> ... 'grid/..." line in mosquitto.log (1 s
    resolution, so the end is rounded up to the end of that second). Not at the
    release itself: TCP's exponential retransmission backoff and the MQTT keepalive
    keep data from flowing for a while after an unblock, and that outage is still the
    attack's doing. Not at the first packet crossing the router either: after a
    reconnection that is the TLS handshake, seconds before any MQTT data. Runs
    without a broker log fall back to the first NEW SCMC data segment crossing to the
    SEMP's link (router_capture.pcap).

Output: output/detector/windows.csv — one row per (window, SCMC) with the features,
the threshold-rule decision, the label and what was going on (attack kind, benign
fault in progress) for per-scenario breakdowns.

Usage:
  python -m monitor.delivery_dataset [--runs output/detector/runs] [--out output/detector/windows.csv]
"""

import argparse
import bisect
import glob
import json
import os
import re

import dpkt
import numpy as np
import pandas as pd

from defense_plane.delivery_detector import FEATURES, replay, rule_decision
from monitor.plot_results import iter_ip_tcp

SEQ_MOD = 1 << 32


def load_jsonl(path: str) -> list:
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass                      # truncated last line of a killed run
    return out


SYN_QUIET_S = 2.0   # a SYN is path evidence only if no data follows this soon


def _extends(top: dict, flow: tuple, tcp) -> bool:
    """True if this segment carries NEW data for its flow (its end sequence number
    passes the highest seen so far); records it. Retransmissions return False."""
    end = (tcp.seq + len(tcp.data)) % SEQ_MOD
    prev = top.get(flow)
    if prev is None or 0 < (end - prev) % SEQ_MOD < SEQ_MOD // 2:
        top[flow] = end
        return True
    return False


def scmc_path(scmc_pcap: str, scmc_pool, port_pool) -> tuple:
    """(times, [(src, dst)]) of the SCMC's MQTT packets carrying new data and of its
    MQTT connection attempts (SYN) on link A, sorted — the path it uses or is trying
    to use.

    Retransmissions don't count: after a hop, the abandoned connection to a blocked
    broker keeps retransmitting its unacknowledged data for a while, which is not the
    path in use. (A stalled SCMC keeps its path anyway: the last one is carried forward.)
    A SYN counts only when no new data follows within SYN_QUIET_S: a make-before-break
    broker hop also sends SYNs (possibly to a blocked address) while data keeps flowing
    on the old connection, and that is not an outage."""
    data, syns, top = [], [], {}
    for ts, src, dst, tcp in iter_ip_tcp(scmc_pcap):
        if src not in scmc_pool or tcp.dport not in port_pool:
            continue
        if len(tcp.data) > 0:
            if _extends(top, (src, tcp.sport, dst, tcp.dport), tcp):
                data.append((ts, src, dst))
        elif (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
            syns.append((ts, src, dst))
    data.sort()
    data_t = [r[0] for r in data]
    quiet = [r for r in syns
             if bisect.bisect_right(data_t, r[0] + SYN_QUIET_S) == bisect.bisect_right(data_t, r[0])]
    rows = sorted(data + quiet)
    return [r[0] for r in rows], [(r[1], r[2]) for r in rows]


def new_deliveries(router_pcap: str, scmc_pool, port_pool) -> list:
    """Times at which NEW SCMC MQTT data crossed to the SEMP's link: segments whose end
    sequence number passes the highest one already seen for that flow (retransmissions
    of delivered data don't count)."""
    top: dict = {}
    times = []
    for ts, src, dst, tcp in iter_ip_tcp(router_pcap):
        if src not in scmc_pool or tcp.dport not in port_pool or not tcp.data:
            continue
        if _extends(top, (src, tcp.sport, dst, tcp.dport), tcp):
            times.append(ts)
    times.sort()
    return times


_PUBLISH_RE = re.compile(r"^(\d+): Received PUBLISH from (\S+) .*'grid/", re.M)


def broker_publishes(mosquitto_log: str) -> list:
    """Epoch seconds (floored, as mosquitto logs them) at which the broker received a
    nanogrid PUBLISH from an SCMC, sorted; [] if the log is missing."""
    if not os.path.exists(mosquitto_log):
        return []
    with open(mosquitto_log, errors="replace") as f:
        return sorted(float(m.group(1)) for m in _PUBLISH_RE.finditer(f.read()))


def _blocks(gt: list, run_end: float) -> list:
    """[(ip, start, end, target)] from block/unblock records; unlifted blocks last
    until run_end."""
    open_, out = {}, []
    for ev in gt:
        if ev["kind"] == "block":
            open_[ev["ip"]] = (ev["t"], ev.get("target", ""))
        elif ev["kind"] == "unblock" and ev["ip"] in open_:
            t0, target = open_.pop(ev["ip"])
            out.append((ev["ip"], t0, ev["t"], target))
    out += [(ip, t0, run_end, target) for ip, (t0, target) in open_.items()]
    return sorted(out, key=lambda b: b[1])


def impact_intervals(blocks: list, path_t: list, path: list, deliveries: list,
                     run_end: float, resolution: float = 0.0) -> list:
    """[(start, end, ip, target)]: when each blackhole was in effect (module docstring).
    `deliveries` are the times data reached the SEMP again; with a `resolution` (the
    broker log's 1 s), a delivery at d stands for [d, d + resolution) and the impact
    ends at d + resolution."""

    def path_at(t):
        i = bisect.bisect_right(path_t, t) - 1
        return path[i] if i >= 0 else None

    def uses(p, ip):
        return p is not None and ip in p

    out = []
    for ip, s, e, target in blocks:
        # Times inside the block at which the path may change, plus the block start.
        ts = [s] + path_t[bisect.bisect_right(path_t, s):bisect.bisect_left(path_t, e)]
        i = 0
        while i < len(ts):
            if not uses(path_at(ts[i]), ip):
                i += 1
                continue
            start = ts[i]
            j = i + 1
            while j < len(ts) and uses(path_at(ts[j]), ip):
                j += 1
            release = ts[j] if j < len(ts) else e
            k = (bisect.bisect_right(deliveries, release - resolution) if resolution
                 else bisect.bisect_left(deliveries, release))
            end = deliveries[k] + resolution if k < len(deliveries) else run_end
            out.append((start, min(end, run_end), ip, target))
            i = j
    return out


def _covered(t: float, intervals: list) -> bool:
    return any(a <= t < b for a, b, *_ in intervals)


def build_run(run_dir: str) -> pd.DataFrame:
    tel = load_jsonl(os.path.join(run_dir, "telemetry.jsonl"))
    gt = load_jsonl(os.path.join(run_dir, "ground_truth.jsonl"))
    meta = next((e for e in gt if e["kind"] == "run_meta"), {})
    pool = {x.strip() for x in (meta.get("scmc_ip_pool") or "").split(",") if x.strip()}
    ports = {int(x) for x in (meta.get("port_pool") or "8883").split(",") if x.strip()}
    run_end = next((e["t"] for e in gt if e["kind"] == "post_attack_end"),
                   tel[-1]["t"] if tel else 0.0)

    path_t, path = scmc_path(os.path.join(run_dir, "scmc_capture.pcap"), pool, ports)
    deliveries, resolution = broker_publishes(os.path.join(run_dir, "mosquitto.log")), 1.0
    if not deliveries:
        deliveries = new_deliveries(os.path.join(run_dir, "router_capture.pcap"), pool, ports)
        resolution = 0.0
    intervals = impact_intervals(_blocks(gt, run_end), path_t, path, deliveries, run_end,
                                 resolution)

    faults = []                                   # (start, end, type)
    started = {}
    for ev in gt:
        if ev["kind"] == "impair_start":
            started[ev["type"]] = ev["t"]
        elif ev["kind"] == "impair_stop" and ev["type"] in started:
            faults.append((started.pop(ev["type"]), ev["t"], ev["type"]))
        elif ev["kind"] == "executor_restart" and ev.get("phase") == "kill":
            faults.append((ev["t"], ev["t"] + 15.0, "restart"))   # restart + reconnect
    faults += [(t0, run_end, kind) for kind, t0 in started.items()]
    post_start = next((e["t"] for e in gt if e["kind"] == "post_attack_start"), None)

    rows = []
    for t, sid, x in replay(tel):
        if t > run_end:
            break
        fault = next((k for a, b, k in faults if a <= t < b), "")
        rows.append({
            "run": os.path.basename(os.path.normpath(run_dir)),
            "variant": "rl" if meta.get("rl_policy") else "fixed",
            "attack": "oracle" if meta.get("oracle_block") else "cnn",
            "seed": meta.get("seed"),
            "t": t,
            "t_post": None if post_start is None else t - post_start,
            "scmc_id": sid,
            **{f: float(v) for f, v in zip(FEATURES, x)},
            "rule": int(rule_decision(x)),
            "fault": fault,
            "label": int(_covered(t, intervals)),
        })
    return pd.DataFrame(rows)


def find_runs(root: str) -> list:
    return sorted(os.path.dirname(p) for p in
                  glob.glob(os.path.join(root, "**", "ground_truth.jsonl"), recursive=True)
                  if os.path.exists(os.path.join(os.path.dirname(p), "telemetry.jsonl")))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--runs", default="output/detector/runs",
                    help="Root searched for run dirs (ground_truth.jsonl + telemetry.jsonl)")
    ap.add_argument("--out", default="output/detector/windows.csv")
    args = ap.parse_args()

    runs = find_runs(args.runs)
    if not runs:
        raise SystemExit(f"no run with ground_truth.jsonl + telemetry.jsonl under {args.runs}")
    frames = []
    for d in runs:
        df = build_run(d)
        print(f"[dataset] {d}: {len(df)} windows, {int(df['label'].sum()) if len(df) else 0} positive")
        frames.append(df)
    data = pd.concat(frames, ignore_index=True)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    data.to_csv(args.out, index=False)
    print(f"[dataset] {len(data)} windows from {len(runs)} runs "
          f"({data['label'].mean():.1%} positive) -> {args.out}")


if __name__ == "__main__":
    main()
