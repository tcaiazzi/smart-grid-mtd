"""mqtt_metrics.py — per-run metrics of the MQTT smart-grid scenario (the
counterpart of cps_metrics.py), from one attack run directory:

  detection  how confidently the attacker fingerprints the nanogrid: its
             nanogrid_frac averaged over the nanogrid's own IPs (SCMC pool +
             SEMP subnet) — MTD lowering it is the win
  block      which IP the attacker blackholed, and whether it was the nanogrid
  cost       availability cost the MTD paid (per-knob weights of the RL reward,
             from the SCMC executor's client.log)
  mtd        the coordinator's actions by outcome, and delivery gaps it observed
  validity   publishes the SCMC made (0 = an unusable run)

Also the shared helpers the paper figures use (plot_results,
compare_coordinators): ranking_nanogrid_detection and availability_cost.

Run:  python -m cyberrange.scenarios.mqtt_mtd.metrics --out-dir output/<slug>/attack/model-baseline
"""

import argparse
import collections
import csv
import datetime
import json
import math
import os
import re

from cyberrange.planes.defense.rl_policy import KNOB_COST, KNOBS
from cyberrange.core.streams import read_jsonl

COST = dict(zip(KNOBS, KNOB_COST))
DEFAULT_SCMC_IP = "10.0.0.2"
# Lab subnets that carry the nanogrid: 10.0.0.x = SCMC side, 10.1.0.x = SEMP side.
# Everything else in a capture (192.168.x, public internet replay) is background.
NANOGRID_SUBNET_PREFIXES = ("10.0.0.", "10.1.0.")


def _is_nanogrid(ip, scmc_pool):
    return ip in scmc_pool or str(ip).startswith(NANOGRID_SUBNET_PREFIXES)


def ranking_nanogrid_detection(ranking_csv: str, scmc_pool) -> tuple:
    """Average attacker nanogrid_frac over the src_ips that belong to the nanogrid.

    Parse a saved nanogrid_ranking.csv (the attack run's per-source-IP nanogrid_frac
    = fraction of that IP's packets the attacker flagged as nanogrid) and average it
    across the genuinely-nanogrid endpoints in this experiment — the SCMC source pool
    plus the SEMP broker subnet. This is how confidently the attacker fingerprints the
    real nanogrid IPs; MTD lowering it is the win.

    Returns (mean_frac, n_ips); (nan, 0) when the file/columns are unusable.
    """
    if not ranking_csv or not os.path.exists(ranking_csv):
        return float("nan"), 0
    with open(ranking_csv, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows or "src_ip" not in rows[0] or "nanogrid_frac" not in rows[0]:
        return float("nan"), 0
    fracs = []
    for r in rows:
        if _is_nanogrid(r["src_ip"], scmc_pool):
            try:
                fracs.append(float(r["nanogrid_frac"]))
            except (TypeError, ValueError):
                continue
    if not fracs:
        return float("nan"), 0
    return float(sum(fracs) / len(fracs)), len(fracs)


# Knob-actuation event lines the SCMC executor writes to client.log. Each carries an
# ISO wall-clock timestamp and maps to a costed knob (see COST). The broker hop line
# carries both endpoints so we can tell an ip hop (0.30) from a port-only hop (0.15).
_LOG_TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)")
_BROKER_HOP_RE = re.compile(
    r"\] hop seq=\d+\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+→\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)"
)
_SRC_HOP_RE = re.compile(r"\] src hop seq=\d+")
_PAD_RE = re.compile(r"\] padding policy →")
_FREQ_RE = re.compile(r"\] publish interval →")


def availability_cost(log_path: str) -> dict:
    """Cumulative availability cost the MTD paid, from an SCMC client.log.

    Every knob actuation the SCMC executor logs is charged the SAME per-knob weight
    the RL reward uses (COST). A broker hop is costed per field that actually
    changed — ip (0.30) and/or port (0.15) — so a port-only NAT swap is cheap while
    a full ip+port hop is dear. src hops cost 0.30; padding/frequency retimes 0.01
    each. The baseline (no MTD) emits none of these lines: its cost stays 0.

    Times are anchored to the first log line. Returns
    {"rel_events": [(rel_t, cost), ...] sorted, "total_cost": float, "window_s": float}.
    """

    def _ts(line: str):
        m = _LOG_TS_RE.match(line)
        return (
            datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").timestamp() if m else None
        )

    t0, events = None, []
    with open(log_path, errors="replace") as f:
        for line in f:
            ts = _ts(line)
            if ts is None:
                continue
            if t0 is None:
                t0 = ts
            cost = 0.0
            m = _BROKER_HOP_RE.search(line)
            if m:
                old_ip, old_port, new_ip, new_port = m.group(1), m.group(2), m.group(3), m.group(4)
                if new_ip != old_ip:
                    cost += COST["ip"]
                if new_port != old_port:
                    cost += COST["port"]
            elif _SRC_HOP_RE.search(line):
                cost = COST["src"]
            elif _PAD_RE.search(line):
                cost = COST["pad"]
            elif _FREQ_RE.search(line):
                cost = COST["freq"]
            if cost > 0.0:
                events.append((ts - t0, cost))

    events.sort()
    return {
        "rel_events": events,
        "total_cost": float(sum(c for _, c in events)),
        "window_s": events[-1][0] if events else 0.0,
    }


# ── per-run metrics ───────────────────────────────────────────────────────────
def _scmc_pool(run_dir):
    pool = {DEFAULT_SCMC_IP}
    for path in (
        os.path.join(run_dir, "scmc_ips.txt"),
        os.path.join(run_dir, "..", "..", "datasets", "scmc_ips.txt"),
    ):
        if os.path.exists(path):
            with open(path) as f:
                pool |= {ip.strip() for ip in f.read().split(",") if ip.strip()}
            break
    return pool


def _nan_to_none(x):
    return None if isinstance(x, float) and math.isnan(x) else x


def compute_metrics(run_dir: str) -> dict:
    """Metrics of one attack run directory (see the module docstring)."""
    from cyberrange.scenarios.mqtt_mtd.scenario import count_publishes

    gt = read_jsonl(os.path.join(run_dir, "ground_truth.jsonl"))
    meta = next((e for e in gt if e.get("kind") == "run_meta"), {})
    pool = _scmc_pool(run_dir)
    frac, n_ips = ranking_nanogrid_detection(os.path.join(run_dir, "nanogrid_ranking.csv"), pool)
    cnn_ip = meta.get("cnn_ip") or None
    blocks = [e for e in gt if e.get("kind") == "block"]
    client_log = os.path.join(run_dir, "client.log")
    cost = availability_cost(client_log) if os.path.exists(client_log) else {}
    tel = read_jsonl(os.path.join(run_dir, "telemetry.jsonl"))
    outcomes = collections.Counter(
        e.get("status") for e in tel if e.get("kind") == "action_outcome"
    )
    actions = collections.Counter(e.get("action") for e in tel if e.get("kind") == "action_outcome")
    gaps = [e for e in tel if e.get("kind") == "data_gap"]
    return {
        "variant": meta.get("variant"),
        "rl_policy": meta.get("rl_policy"),
        "seed": meta.get("seed"),
        "publishes": count_publishes(client_log),
        "nanogrid_detect": _nan_to_none(frac),
        "n_nanogrid_ips": n_ips,
        "blocked_ip": cnn_ip,
        "blocked_is_nanogrid": (_is_nanogrid(cnn_ip, pool) if cnn_ip else None),
        "blocked_is_scmc": (cnn_ip in pool if cnn_ip else None),
        "blocks": len(blocks),
        "availability_cost": cost.get("total_cost", 0.0),
        "n_costed_actions": len(cost.get("rel_events", [])),
        "mtd_actions": dict(actions),
        "mtd_outcomes": dict(outcomes),
        "data_gaps": len(gaps),
        "max_data_gap_s": max((g.get("gap_s") or 0 for g in gaps), default=None),
    }


def format_report(m: dict) -> str:
    lines = ["# MQTT run metrics", ""]
    for k in (
        "variant",
        "rl_policy",
        "seed",
        "publishes",
        "nanogrid_detect",
        "n_nanogrid_ips",
        "blocked_ip",
        "blocked_is_scmc",
        "blocks",
        "availability_cost",
        "n_costed_actions",
        "data_gaps",
        "max_data_gap_s",
    ):
        lines.append(f"- {k}: {m.get(k)}")
    if m.get("mtd_outcomes"):
        lines.append(f"- mtd outcomes: {json.dumps(m['mtd_outcomes'], sort_keys=True)}")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Per-run metrics of an MQTT attack run")
    ap.add_argument("--out-dir", required=True, help="attack run directory")
    ap.add_argument("--report", default=None, help="also write a markdown report here")
    args = ap.parse_args()
    m = compute_metrics(args.out_dir)
    print(json.dumps(m, indent=2))
    if args.report:
        with open(args.report, "w") as f:
            f.write(format_report(m))


if __name__ == "__main__":
    main()
