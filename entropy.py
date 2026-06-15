#!/usr/bin/env python3
"""
entropy.py — information-theoretic MTD effectiveness metric.

The attack-side metrics (detection score / availability in plot_results.py) tell
us *whether* the fingerprinter wins. This module quantifies *why* MTD works, with
a model-free measure: the Shannon entropy of the traffic the attacker observes.

Every MTD knob in mtd_coordinator.py moves one observable on the wire, and every
IP / port / source hop forces a TCP reconnect (mtd_executor.py) → a brand-new
4-tuple flow. So we measure two things over the *real nanogrid packets* in a pcap
(SCMC↔SEMP, labeled by IP pools exactly like classify.py):

  • Flow-distribution entropy (headline): group nanogrid packets by their 4-tuple
    flow_key and measure how spread the signal is across flows.
        baseline  → ~1 persistent flow            → H_flow ≈ 0
        MTD       → many ephemeral hopped flows    → H_flow large
    This is the "dilute the nanogrid signal across many candidate flows" effect
    the Makefile describes, now quantified.

  • Per-field entropy (breakdown): marginal Shannon entropy of each observable
    field, attributing the dilution to the specific knob that moved it:
        src_ip            ← SCMC source-IP hop
        dst_ip            ← broker IP hop
        dst_port          ← broker port hop
        packet_len        ← payload padding
        tcp_payload_len   ← payload padding
        iat               ← message-frequency hop

Both are restricted to the client→broker direction (src_ip in the SCMC pool) so
each field carries a single meaning (dst_* is always the broker).

Usage:
  python entropy.py --test-pcap output/<slug>/datasets/test.pcap \\
      --scmc-ip-pool 10.0.0.2,10.0.0.4,10.0.0.5 \\
      --semp-ip-pool 10.1.0.2,10.1.0.4,10.1.0.5 \\
      --out-dir output/<slug>
  # writes entropy.csv + entropy_timeseries.csv into --out-dir

  # baseline-vs-MTD comparison figure (after both configs have an entropy.csv):
  python entropy.py --compare --baseline-csv output/baseline-mbps2/entropy.csv \\
      --mtd-csv output/mtd-<slug>/entropy.csv --out-dir output/mtd-<slug>
"""

import argparse
import os
from typing import Optional

import matplotlib

matplotlib.use("Agg")  # headless: write PDFs, no display needed
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from classify import extract_features

# Continuous fields are histogram-binned before counting; discrete ones use the
# raw category counts. 32 bins is plenty to resolve the padding buckets / publish
# intervals without inflating entropy through empty bins.
CONT_BINS = 32

# Fields whose marginal entropy is reported, in plot order. Continuous fields are
# binned; the rest use value counts. dst_* are parsed from flow_key.
DISCRETE_FIELDS = ["src_ip", "dst_ip", "dst_port"]
CONTINUOUS_FIELDS = ["packet_len", "tcp_payload_len", "iat"]
FIELD_ORDER = DISCRETE_FIELDS + CONTINUOUS_FIELDS


# ── Entropy primitives ─────────────────────────────────────────────────────────

def shannon_entropy(values: pd.Series, bins: Optional[int] = None) -> tuple:
    """Shannon entropy of a sample, in bits.

    Returns (H_bits, H_norm, n_distinct) where
      • H_bits    = -Σ p log2 p over the category probabilities,
      • H_norm    = H_bits / log2(n_categories)  ∈ [0, 1]  (0 when ≤1 category),
      • n_distinct= number of non-empty categories.

    Discrete fields (bins=None) use the raw value counts; continuous fields pass
    a bin count and are histogram-binned first. An empty sample → (0, 0, 0).
    """
    values = pd.Series(values).dropna()
    n = len(values)
    if n == 0:
        return 0.0, 0.0, 0

    if bins is None:
        counts = values.value_counts().values.astype(float)
    else:
        counts, _ = np.histogram(values.values.astype(float), bins=bins)
        counts = counts[counts > 0].astype(float)

    n_distinct = int(len(counts))
    if n_distinct <= 1:
        return 0.0, 0.0, n_distinct

    p = counts / counts.sum()
    h = float(-np.sum(p * np.log2(p)))
    h_norm = h / np.log2(n_distinct)
    return h, h_norm, n_distinct


# ── Nanogrid packet selection ──────────────────────────────────────────────────

def _split_flow_key(fk: str) -> tuple:
    """Parse 'src:sport->dst:dport' back into (src, sport, dst, dport)."""
    src_part, dst_part = fk.split("->")
    src_ip, sport = src_part.rsplit(":", 1)
    dst_ip, dport = dst_part.rsplit(":", 1)
    return src_ip, int(sport), dst_ip, int(dport)


def load_nanogrid_packets(
    pcap_path: str, scmc_ips: list, semp_ips: list
) -> pd.DataFrame:
    """Extract nanogrid client→broker packets from a pcap.

    Reuses classify.extract_features to label SCMC↔SEMP traffic by IP pools, then
    keeps only the client→broker direction (src in the SCMC pool) and recovers
    dst_ip / dst_port from flow_key so per-field entropy has a single meaning
    (dst_* = the broker, src_ip = the SCMC).
    """
    df = extract_features(pcap_path, scmc_ips=scmc_ips, semp_ips=semp_ips)
    scmc_set = set(scmc_ips)
    ng = df[(df["is_nanogrid"] == 1) & (df["src_ip"].isin(scmc_set))].copy()
    if ng.empty:
        raise ValueError(
            f"No nanogrid client→broker packets in {pcap_path} "
            f"(scmc={scmc_ips}, semp={semp_ips})"
        )
    parsed = ng["flow_key"].map(_split_flow_key)
    ng["dst_ip"] = parsed.map(lambda t: t[2])
    ng["dst_port"] = parsed.map(lambda t: t[3])
    return ng


# ── Metrics ────────────────────────────────────────────────────────────────────

def compute_flow_entropy(df_ng: pd.DataFrame) -> dict:
    """Headline metric: entropy of the packets-per-flow distribution.

    Each hop spawns a fresh 4-tuple, so a high H_flow means the nanogrid signal
    is fragmented across many candidate flows the attacker must sift.
    """
    h, h_norm, n_flows = shannon_entropy(df_ng["flow_key"])
    return {
        "H_flow_bits": h,
        "H_flow_norm": h_norm,
        "n_flows": n_flows,
        "n_packets": int(len(df_ng)),
    }


def compute_field_entropies(df_ng: pd.DataFrame) -> pd.DataFrame:
    """Per-field marginal entropy table (one row per observable field)."""
    rows = []
    for field in FIELD_ORDER:
        bins = CONT_BINS if field in CONTINUOUS_FIELDS else None
        h, h_norm, n_distinct = shannon_entropy(df_ng[field], bins=bins)
        rows.append(
            {
                "field": field,
                "entropy_bits": h,
                "entropy_norm": h_norm,
                "n_distinct": n_distinct,
            }
        )
    return pd.DataFrame(rows)


def compute_entropy_timeseries(
    df_ng: pd.DataFrame, window_s: float, step_s: float
) -> pd.DataFrame:
    """Sliding-window entropy over time — shows the target moving live.

    Per window emits the flow entropy plus each per-field entropy, so the figure
    tracks how unpredictable the traffic stays as the run proceeds.
    """
    t0 = float(df_ng["timestamp"].min())
    t_end = float(df_ng["timestamp"].max())
    ts = df_ng["timestamp"].values.astype(float)

    rows = []
    start = t0
    while start <= t_end:
        end = start + window_s
        win = df_ng[(ts >= start) & (ts < end)]
        rel_t = round(start - t0, 3)
        if win.empty:
            rows.append({"t": rel_t, "n_packets": 0, "H_flow_bits": 0.0,
                         **{f"H_{f}_bits": 0.0 for f in FIELD_ORDER}})
        else:
            row = {
                "t": rel_t,
                "n_packets": int(len(win)),
                "H_flow_bits": shannon_entropy(win["flow_key"])[0],
            }
            for field in FIELD_ORDER:
                bins = CONT_BINS if field in CONTINUOUS_FIELDS else None
                row[f"H_{field}_bits"] = shannon_entropy(win[field], bins=bins)[0]
            rows.append(row)
        start += step_s
    return pd.DataFrame(rows)


def build_entropy_csv(flow: dict, fields: pd.DataFrame) -> pd.DataFrame:
    """Combine the flow row + per-field rows into one long-form table.

    One row per metric: metric='flow' for the headline, metric='<field>' for each
    field; columns entropy_bits / entropy_norm / n_distinct (n_flows lands in
    n_distinct for the flow row). This shape is what the comparison plot reads.
    """
    flow_row = pd.DataFrame([{
        "metric": "flow",
        "entropy_bits": flow["H_flow_bits"],
        "entropy_norm": flow["H_flow_norm"],
        "n_distinct": flow["n_flows"],
        "n_packets": flow["n_packets"],
    }])
    field_rows = fields.rename(columns={"field": "metric"}).copy()
    field_rows["n_packets"] = flow["n_packets"]
    return pd.concat([flow_row, field_rows], ignore_index=True)


# ── Plots ───────────────────────────────────────────────────────────────────────

def plot_entropy_comparison(baseline_csv: str, mtd_csv: str, out_path: str) -> None:
    """Grouped bar chart: baseline vs MTD entropy per metric (flow + fields).

    The money figure — flow entropy plus every per-field entropy side by side, so
    the dilution and which knobs drive it are visible at a glance.
    """
    base = pd.read_csv(baseline_csv).set_index("metric")["entropy_bits"]
    mtd = pd.read_csv(mtd_csv).set_index("metric")["entropy_bits"]

    metrics = ["flow"] + FIELD_ORDER
    base_v = [float(base.get(m, 0.0)) for m in metrics]
    mtd_v = [float(mtd.get(m, 0.0)) for m in metrics]

    x = np.arange(len(metrics))
    w = 0.4
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(x - w / 2, base_v, w, label="Baseline (no MTD)",
           color="#7f8c8d", edgecolor="black")
    ax.bar(x + w / 2, mtd_v, w, label="MTD",
           color="#27ae60", edgecolor="black")

    ax.set_xticks(x)
    ax.set_xticklabels([m.replace("_", "\n") for m in metrics])
    ax.set_ylabel("Shannon entropy (bits)")
    ax.set_title("MTD raises the entropy of the nanogrid traffic the attacker sees")
    ax.legend()
    ax.grid(True, axis="y", alpha=0.3)

    for xi, (bv, mv) in enumerate(zip(base_v, mtd_v)):
        ax.annotate(f"{bv:.2f}", (xi - w / 2, bv), ha="center", va="bottom", fontsize=8)
        ax.annotate(f"{mv:.2f}", (xi + w / 2, mv), ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f"[plot] entropy comparison -> {out_path}")


def plot_entropy_timeseries(ts_csv: str, out_path: str) -> None:
    """Flow + per-field entropy over time — the live moving target."""
    df = pd.read_csv(ts_csv)
    fig, ax = plt.subplots(figsize=(10, 5))

    ax.plot(df["t"], df["H_flow_bits"], lw=2.4, color="#c0392b",
            label="flow (headline)")
    for field in FIELD_ORDER:
        col = f"H_{field}_bits"
        if col in df.columns:
            ax.plot(df["t"], df[col], lw=1.3, alpha=0.8, label=field)

    ax.set_xlabel("time since first nanogrid packet (s)")
    ax.set_ylabel("windowed Shannon entropy (bits)")
    ax.set_title("Entropy over time — the moving target during the run")
    ax.legend(fontsize=8, ncol=2)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f"[plot] entropy timeseries -> {out_path}")


# ── CLI ──────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Flow/field entropy of the nanogrid traffic (MTD metric)"
    )
    p.add_argument("--test-pcap", metavar="PCAP", default=None,
                   help="PCAP to measure (default: output/<slug>/datasets/test.pcap)")
    p.add_argument("--scmc-ip-pool", default="10.0.0.2,10.0.0.4,10.0.0.5",
                   help="Comma-separated SCMC source-IP pool (nanogrid one end).")
    p.add_argument("--semp-ip-pool", default="10.1.0.2,10.1.0.4,10.1.0.5",
                   help="Comma-separated SEMP broker-IP pool (nanogrid other end).")
    p.add_argument("--out-dir", default="output",
                   help="Where entropy.csv / figures are written.")
    p.add_argument("--window", type=float, default=5.0,
                   help="Sliding-window length in seconds (default: 5).")
    p.add_argument("--step", type=float, default=1.0,
                   help="Sliding-window step in seconds (default: 1).")
    p.add_argument("--compare", action="store_true",
                   help="Only emit the baseline-vs-MTD comparison figure from two "
                        "existing entropy.csv files (--baseline-csv / --mtd-csv).")
    p.add_argument("--baseline-csv", default=None,
                   help="Baseline entropy.csv (for --compare).")
    p.add_argument("--mtd-csv", default=None,
                   help="MTD entropy.csv (for --compare).")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    if args.compare:
        if not (args.baseline_csv and args.mtd_csv):
            raise SystemExit("[ERROR] --compare needs --baseline-csv and --mtd-csv")
        plot_entropy_comparison(
            args.baseline_csv, args.mtd_csv,
            os.path.join(args.out_dir, "entropy_comparison.pdf"),
        )
        return

    if not args.test_pcap:
        raise SystemExit("[ERROR] --test-pcap required (or use --compare)")

    scmc_ips = [x.strip() for x in args.scmc_ip_pool.split(",") if x.strip()]
    semp_ips = [x.strip() for x in args.semp_ip_pool.split(",") if x.strip()]

    print(f"[entropy] Loading nanogrid packets from {args.test_pcap}")
    df_ng = load_nanogrid_packets(args.test_pcap, scmc_ips, semp_ips)

    flow = compute_flow_entropy(df_ng)
    fields = compute_field_entropies(df_ng)

    print(f"[entropy] nanogrid packets={flow['n_packets']}  flows={flow['n_flows']}")
    print(f"[entropy] H_flow = {flow['H_flow_bits']:.3f} bits "
          f"(norm {flow['H_flow_norm']:.3f})")
    print(fields.to_string(index=False))

    csv = build_entropy_csv(flow, fields)
    csv_path = os.path.join(args.out_dir, "entropy.csv")
    csv.to_csv(csv_path, index=False)
    print(f"[entropy] table -> {csv_path}")

    ts = compute_entropy_timeseries(df_ng, args.window, args.step)
    ts_path = os.path.join(args.out_dir, "entropy_timeseries.csv")
    ts.to_csv(ts_path, index=False)
    print(f"[entropy] timeseries -> {ts_path}")

    plot_entropy_timeseries(ts_path, os.path.join(args.out_dir, "entropy_timeseries.pdf"))


if __name__ == "__main__":
    main()
