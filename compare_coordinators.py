#!/usr/bin/env python3
"""
compare_coordinators.py — RL MTD coordinator vs the fixed-timer one (model-free).

Compares three coordinators at the SAME parameter config, side by side:

    Baseline (no MTD)   output/baseline-mbps<M>/
    MTD (fixed timers)  output/mtd-<slug>/
    MTD (RL policy)     output/mtdrl-<slug>/

on two model-free signals that run_single.sh already produces — no lab attack
needed (it reads the held-out eval + entropy artifacts, never re-runs the lab):

  • Fingerprintability (security, ↓ better): how well the CNN attacker separates
    the SCMC on the held-out TEST set, from each config's eval predictions.csv —
    threshold-free ROC-AUC plus the nanogrid recall (fraction of real SCMC packets
    the attacker catches). Each MTD config is scored by its OWN matched model
    (model-mtd); the baseline by the baseline model.

  • Traffic entropy (diffusion, ↑ better): flow-distribution + per-field Shannon
    entropy of the nanogrid traffic, from each config's entropy.csv (make entropy).
    Shows WHICH wire fields each coordinator moves (src_ip / dst_ip / dst_port /
    packet_len / tcp_payload_len / iat) and by how much.

Outputs (default output/compare-<slug>/):
    comparison.csv            the full metric table
    security_comparison.pdf   AUC + recall per coordinator
    entropy_comparison.pdf    flow + per-field entropy, grouped by coordinator

Usage:
  .venv/bin/python compare_coordinators.py \\
      --slug hop4-padint3-ips6-ports7-pads7-srcips6-mbps2-freqint5-freqs6 \\
      --bg-replay-mbps 2
"""

import argparse
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from entropy import FIELD_ORDER

# One bar group per coordinator. model_src picks which eval model scored it: each
# MTD config is judged by its own matched model; the baseline by the baseline model.
COORDINATORS = [
    ("Baseline\n(no MTD)", "baseline", "baseline", "#7f8c8d"),
    ("MTD\n(fixed timers)", "mtd", "mtd", "#2980b9"),
    ("MTD\n(RL blend)", "mtdrl", "mtd", "#27ae60"),
]
# Colours for extra tagged RL policies (--rl-tags), e.g. the entropy-max policy.
TAG_COLORS = ["#8e44ad", "#e67e22", "#16a085", "#c0392b"]
ENTROPY_METRICS = ["flow"] + FIELD_ORDER     # headline flow entropy + per-field


def resolve(root: str, slug: str, mbps: int, rl_tags=()) -> list:
    """Build the per-coordinator artifact paths for this parameter config.

    The base three (baseline / fixed / RL blend) plus one extra RL coordinator per
    tag in rl_tags (dir prefix mtdrl-<tag>, e.g. the entropy-max policy)."""
    specs = list(COORDINATORS)
    for i, tag in enumerate(rl_tags):
        specs.append((f"MTD\n(RL {tag})", f"mtdrl-{tag}", "mtd",
                      TAG_COLORS[i % len(TAG_COLORS)]))
    coords = []
    for label, prefix, model_src, color in specs:
        exp_dir = (os.path.join(root, f"baseline-mbps{mbps}") if prefix == "baseline"
                   else os.path.join(root, f"{prefix}-{slug}"))
        coords.append({
            "label": label,
            "color": color,
            "exp_dir": exp_dir,
            "pred_csv": os.path.join(exp_dir, "eval", f"model-{model_src}", "predictions.csv"),
            "entropy_csv": os.path.join(exp_dir, "entropy.csv"),
            "ts_csv": os.path.join(exp_dir, "entropy_timeseries.csv"),
        })
    return coords


def load_security(pred_csv: str) -> dict:
    """Fingerprint metrics from an eval predictions.csv (ROC-AUC + nanogrid recall)."""
    if not os.path.exists(pred_csv):
        print(f"[warn] {pred_csv} missing — no security metrics for this coordinator")
        return {}
    df = pd.read_csv(pred_csv)
    if "label_true" not in df.columns:
        print(f"[warn] {pred_csv} has no label_true — skipping security metrics")
        return {}
    y, prob, pred = df["label_true"].values, df["prob"].values, df["label_pred"].values
    pos = y == 1
    out = {
        "auc": float(roc_auc_score(y, prob)) if len(np.unique(y)) > 1 else float("nan"),
        "nanogrid_recall": float(pred[pos].mean()) if pos.any() else float("nan"),
        "n_packets": int(len(df)),
        "n_nanogrid": int(pos.sum()),
    }
    return out


def load_entropy(entropy_csv: str) -> dict:
    """metric→entropy_bits map from an entropy.csv (make entropy)."""
    if not os.path.exists(entropy_csv):
        print(f"[warn] {entropy_csv} missing — no entropy for this coordinator")
        return {}
    df = pd.read_csv(entropy_csv).set_index("metric")["entropy_bits"]
    return {m: float(df.get(m, float("nan"))) for m in ENTROPY_METRICS}


def load_timeseries(ts_csv: str):
    """Sliding-window entropy timeseries from an entropy_timeseries.csv, or None."""
    if not os.path.exists(ts_csv):
        print(f"[warn] {ts_csv} missing — no entropy timeseries for this coordinator")
        return None
    return pd.read_csv(ts_csv)


# ── Plots ──────────────────────────────────────────────────────────────────────

def plot_security(coords: list, out_path: str) -> None:
    """Grouped bars: fingerprint AUC and nanogrid recall per coordinator (↓ better)."""
    have = [c for c in coords if "auc" in c]
    if not have:
        print("[plot] no security data — skipping security comparison")
        return
    metrics = [("auc", "ROC-AUC"), ("nanogrid_recall", "nanogrid recall")]
    x = np.arange(len(metrics))
    w = 0.8 / len(have)

    fig, ax = plt.subplots(figsize=(8, 5))
    for i, c in enumerate(have):
        vals = [c.get(m[0], float("nan")) for m in metrics]
        bars = ax.bar(x + (i - (len(have) - 1) / 2) * w, vals, w,
                      color=c["color"], edgecolor="black",
                      label=c["label"].replace("\n", " "))
        for bar, v in zip(bars, vals):
            if not np.isnan(v):
                ax.annotate(f"{v:.2f}", (bar.get_x() + bar.get_width() / 2, v),
                            ha="center", va="bottom", fontsize=8)

    ax.axhline(0.5, ls="--", color="gray", lw=1, label="random (AUC 0.5)")
    ax.set_xticks(x)
    ax.set_xticklabels([m[1] for m in metrics])
    ax.set_ylabel("attacker fingerprinting  (↓ = better defense)")
    ax.set_ylim(0, 1.05)
    ax.set_title("Fingerprintability of the SCMC — RL vs fixed MTD")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[plot] security comparison -> {out_path}")


def plot_entropy(coords: list, out_path: str) -> None:
    """Grouped bars: flow + per-field entropy per coordinator (↑ = more diffusion)."""
    have = [c for c in coords if "entropy" in c and c["entropy"]]
    if not have:
        print("[plot] no entropy data — skipping entropy comparison")
        return
    x = np.arange(len(ENTROPY_METRICS))
    w = 0.8 / len(have)

    fig, ax = plt.subplots(figsize=(11, 5))
    for i, c in enumerate(have):
        vals = [c["entropy"].get(m, float("nan")) for m in ENTROPY_METRICS]
        ax.bar(x + (i - (len(have) - 1) / 2) * w, vals, w,
               color=c["color"], edgecolor="black",
               label=c["label"].replace("\n", " "))

    ax.set_xticks(x)
    ax.set_xticklabels([m.replace("_", "\n") for m in ENTROPY_METRICS])
    ax.set_ylabel("Shannon entropy (bits)  (↑ = harder to fingerprint)")
    ax.set_title("Traffic entropy the attacker sees — RL vs fixed MTD")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[plot] entropy comparison -> {out_path}")


def plot_timeseries(coords: list, out_path: str) -> None:
    """Overlay the headline flow-entropy over time for every coordinator.

    Each coordinator's entropy_timeseries.csv (make entropy) is a sliding-window
    H_flow over the run; overlaying them shows the RL policy's diffusion *as it
    moves*, next to the fixed timer and baseline."""
    have = [c for c in coords if c.get("ts") is not None]
    if not have:
        print("[plot] no timeseries data — skipping entropy timeseries comparison")
        return
    fig, ax = plt.subplots(figsize=(10, 5))
    for c in have:
        ts = c["ts"]
        ax.plot(ts["t"], ts["H_flow_bits"], lw=2, color=c["color"],
                label=c["label"].replace("\n", " "))
    ax.set_xlabel("time since first nanogrid packet (s)")
    ax.set_ylabel("windowed flow entropy (bits)  (↑ = harder to fingerprint)")
    ax.set_title("Flow entropy over time — RL vs fixed MTD")
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[plot] entropy timeseries comparison -> {out_path}")


def plot_timeseries_fields(coords: list, out_path: str) -> None:
    """Per-field entropy over time: one panel per wire field, lines = coordinators."""
    have = [c for c in coords if c.get("ts") is not None]
    if not have:
        return
    cols = [("H_flow_bits", "flow")] + [(f"H_{f}_bits", f) for f in FIELD_ORDER]
    cols = [(col, name) for col, name in cols if any(col in c["ts"].columns for c in have)]
    n = len(cols)
    ncol = 2
    nrow = (n + ncol - 1) // ncol
    fig, axes = plt.subplots(nrow, ncol, figsize=(12, 2.6 * nrow), squeeze=False)
    for ax, (col, name) in zip(axes.ravel(), cols):
        for c in have:
            ts = c["ts"]
            if col in ts.columns:
                ax.plot(ts["t"], ts[col], lw=1.6, color=c["color"],
                        label=c["label"].replace("\n", " "))
        ax.set_title(name, fontsize=10)
        ax.grid(True, alpha=0.3)
        ax.set_ylabel("bits")
    for ax in axes.ravel()[n:]:
        ax.set_visible(False)
    axes.ravel()[0].legend(fontsize=8, loc="upper right")
    fig.suptitle("Per-field entropy over time — RL vs fixed MTD", y=1.005)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[plot] per-field entropy timeseries -> {out_path}")


def build_table(coords: list) -> pd.DataFrame:
    rows = []
    for c in coords:
        row = {"coordinator": c["label"].replace("\n", " ")}
        row["fingerprint_auc"] = c.get("auc")
        row["nanogrid_recall"] = c.get("nanogrid_recall")
        row["n_nanogrid_pkts"] = c.get("n_nanogrid")
        for m in ENTROPY_METRICS:
            row[f"H_{m}"] = c.get("entropy", {}).get(m)
        rows.append(row)
    return pd.DataFrame(rows)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Compare RL vs fixed MTD coordinators (model-free)")
    p.add_argument("--slug", required=True,
                   help="MTD parameter slug shared by the mtd-/mtdrl- dirs, e.g. "
                        "hop4-padint3-ips6-ports7-pads7-srcips6-mbps2-freqint5-freqs6")
    p.add_argument("--bg-replay-mbps", type=int, default=2,
                   help="Selects the baseline-mbps<M> dir (default: 2).")
    p.add_argument("--output-root", default="output")
    p.add_argument("--out-dir", default=None,
                   help="Where to write the comparison (default: output/compare-<slug>).")
    p.add_argument("--rl-tags", default="",
                   help="Comma-separated extra RL policy tags to add as their own "
                        "coordinators (dir prefix mtdrl-<tag>), e.g. 'entropy'.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = args.out_dir or os.path.join(args.output_root, f"compare-{args.slug}")
    os.makedirs(out_dir, exist_ok=True)

    rl_tags = [t.strip() for t in args.rl_tags.split(",") if t.strip()]
    coords = resolve(args.output_root, args.slug, args.bg_replay_mbps, rl_tags)
    for c in coords:
        print(f"[compare] {c['label'].replace(chr(10), ' ')}: {c['exp_dir']}")
        c.update(load_security(c["pred_csv"]))
        c["entropy"] = load_entropy(c["entropy_csv"])
        c["ts"] = load_timeseries(c["ts_csv"])

    table = build_table(coords)
    print("\n=== Comparison ===")
    print(table.to_string(index=False))
    csv_path = os.path.join(out_dir, "comparison.csv")
    table.to_csv(csv_path, index=False)
    print(f"\n[compare] table -> {csv_path}")

    plot_security(coords, os.path.join(out_dir, "security_comparison.pdf"))
    plot_entropy(coords, os.path.join(out_dir, "entropy_comparison.pdf"))
    plot_timeseries(coords, os.path.join(out_dir, "entropy_timeseries_comparison.pdf"))
    plot_timeseries_fields(coords, os.path.join(out_dir, "entropy_timeseries_fields.pdf"))


if __name__ == "__main__":
    main()
