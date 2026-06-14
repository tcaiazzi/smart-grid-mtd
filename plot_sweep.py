#!/usr/bin/env python3
"""
plot_sweep.py — paper sweep figures from run_sweep.sh results

Reads:   output/sweep_manifest.csv            (slug column = experiment dir name)
         output/<exp-dir>/summary.csv         (one per config, from plot_results.py)
Writes:  output/sweep/e1_address_diversity.pdf
         output/sweep/e2_hop_interval.pdf
         output/sweep/e3_bg_noise.pdf
         output/sweep/sweep_results.csv

Usage:
  .venv/bin/python plot_sweep.py
  .venv/bin/python plot_sweep.py --manifest output/sweep_manifest.csv
"""

import argparse
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

DETECT_THRESHOLD  = 0.3
LABEL_MTD_MODEL   = "MTD (MTD model)"
LABEL_BASE_MODEL  = "MTD (baseline model)"
LABEL_BASELINE    = "Baseline (no MTD)"

COLOR_MTD    = "#2980b9"
COLOR_XMODEL = "#e67e22"
COLOR_BASE   = "#7f8c8d"


# ── Data loading ──────────────────────────────────────────────────────────────

def load_sweep(manifest_path: str, plots_root: str) -> pd.DataFrame:
    """Merge manifest rows with per-config summary CSVs into one DataFrame."""
    manifest = pd.read_csv(manifest_path)
    rows = []
    for _, m in manifest.iterrows():
        slug = m["slug"]
        path = os.path.join(plots_root, str(slug), "summary.csv")
        if not os.path.exists(path):
            print(f"[warn] missing {path} — skipping '{slug}'")
            continue
        for _, s in pd.read_csv(path).iterrows():
            rows.append({
                **dict(m),
                "scenario":        s["scenario"],
                "detection_score": s.get("scmc_nanogrid_frac"),
                "blocked":         s.get("scmc_blocked"),
                "publishes":       s.get("publishes"),
                "sent_msgs":       s.get("sent_msgs"),
                "delivery_ratio":  s.get("delivery_ratio"),
            })
    return pd.DataFrame(rows)


def _pick(df: pd.DataFrame, col: str, scenario: str, **filters) -> float:
    mask = df["scenario"] == scenario
    for k, v in filters.items():
        mask &= (df[k] == v)
    vals = df[mask][col].dropna()
    return float(vals.iloc[0]) if not vals.empty else float("nan")


def score(df: pd.DataFrame, scenario: str, **filters) -> float:
    return _pick(df, "detection_score", scenario, **filters)


def delivery(df: pd.DataFrame, scenario: str, **filters) -> float:
    return _pick(df, "delivery_ratio", scenario, **filters)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _threshold(ax):
    ax.axhline(DETECT_THRESHOLD, ls=":", color="gray", lw=1.5, zorder=2,
               label=f"detection threshold ({DETECT_THRESHOLD})")


def _finish(ax, title: str, xlabel: str = None):
    if xlabel:
        ax.set_xlabel(xlabel)
    ax.set_ylabel("nanogrid score of SCMC IP  (↓ = harder for attacker)")
    ax.set_ylim(0, 1.05)
    ax.set_title(title)
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3, zorder=1)
    ax.figure.tight_layout()


def _label_bar(ax, bar, v):
    if not np.isnan(v):
        ax.annotate(f"{v:.2f}",
                    (bar.get_x() + bar.get_width() / 2, v + 0.015),
                    ha="center", va="bottom", fontsize=8)


# ── E1 — address-space diversity ──────────────────────────────────────────────

def plot_e1(df: pd.DataFrame, out_path: str) -> None:
    """Grouped bar: 2x2 factorial of IP hop x port hop."""
    # (label, experiment tag, n_ips x n_ports description)
    configs = [
        ("No hop\n(1 × 1 = 1)",    "E1-no-hop"),
        ("Port only\n(1 × 5 = 5)",  "E1-port-only"),
        ("IP only\n(3 × 1 = 3)",    "E1-ip-only"),
        ("Both\n(3 × 5 = 15)",      "E0-default"),
    ]
    labels        = [c[0] for c in configs]
    mtd_scores    = [score(df, LABEL_MTD_MODEL,  experiment=c[1]) for c in configs]
    xmodel_scores = [score(df, LABEL_BASE_MODEL, experiment=c[1]) for c in configs]

    x, w = np.arange(len(configs)), 0.35
    fig, ax = plt.subplots(figsize=(9, 5))

    bars_mtd = ax.bar(x - w/2, mtd_scores,    w, color=COLOR_MTD,    edgecolor="black",
                      label="MTD-trained model",      zorder=3)
    bars_x   = ax.bar(x + w/2, xmodel_scores, w, color=COLOR_XMODEL, edgecolor="black",
                      label="Baseline-trained model", zorder=3)

    for bar, v in zip([*bars_mtd, *bars_x], [*mtd_scores, *xmodel_scores]):
        _label_bar(ax, bar, v)

    _threshold(ax)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    _finish(ax, "E1 — Address-space diversity: IP hop × port hop")

    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[sweep] {out_path}")


# ── E2 — hop interval sweep ───────────────────────────────────────────────────

def plot_e2(df: pd.DataFrame, out_path: str, base_ref: float) -> None:
    """Line plot: detection score vs hop interval (log x-axis)."""
    e2 = df[df["experiment"].str.startswith("E2-") | (df["experiment"] == "E0-default")]
    hop_vals = sorted(e2["hop"].dropna().unique())

    mtd_scores    = [score(e2, LABEL_MTD_MODEL,  hop=h) for h in hop_vals]
    xmodel_scores = [score(e2, LABEL_BASE_MODEL, hop=h) for h in hop_vals]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(hop_vals, mtd_scores,    "o-",  color=COLOR_MTD,    lw=2,
            label="MTD-trained model",      zorder=3)
    ax.plot(hop_vals, xmodel_scores, "s--", color=COLOR_XMODEL, lw=2,
            label="Baseline-trained model", zorder=3)

    if not np.isnan(base_ref):
        ax.axhline(base_ref, ls="--", color=COLOR_BASE, lw=1.5, zorder=2,
                   label=f"no-MTD baseline ({base_ref:.2f})")

    _threshold(ax)
    ax.set_xscale("log")
    ax.set_xticks(hop_vals)
    ax.set_xticklabels([str(int(h)) for h in hop_vals])
    _finish(ax, "E2 — Hop interval: security vs reconnection tradeoff",
            xlabel="hop interval (s)")

    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[sweep] {out_path}")


# ── E3 — background noise sweep ───────────────────────────────────────────────

def plot_e3(df: pd.DataFrame, out_path: str) -> None:
    """Line plot: detection score vs background replay rate."""
    e3 = df[df["experiment"].str.startswith("E3-") | (df["experiment"] == "E0-default")]
    mbps_vals = sorted(e3["bg_mbps"].dropna().unique())

    mtd_scores    = [score(e3, LABEL_MTD_MODEL,  bg_mbps=m) for m in mbps_vals]
    xmodel_scores = [score(e3, LABEL_BASE_MODEL, bg_mbps=m) for m in mbps_vals]
    base_scores   = [score(e3, LABEL_BASELINE,   bg_mbps=m) for m in mbps_vals]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(mbps_vals, mtd_scores,    "o-",  color=COLOR_MTD,    lw=2,
            label="MTD-trained model",      zorder=3)
    ax.plot(mbps_vals, xmodel_scores, "s--", color=COLOR_XMODEL, lw=2,
            label="Baseline-trained model", zorder=3)
    ax.plot(mbps_vals, base_scores,   "^:",  color=COLOR_BASE,   lw=2,
            label="Baseline (no MTD)",      zorder=3)

    _threshold(ax)
    _finish(ax, "E3 — Background noise: attacker accuracy vs SNR",
            xlabel="background traffic replay rate (Mbit/s)")

    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[sweep] {out_path}")


# ── E2b — hop interval vs delivery ratio ─────────────────────────────────────

def plot_e2_delivery(df: pd.DataFrame, out_path: str) -> None:
    """Line plot: MQTT delivery ratio vs hop interval.

    More frequent hops cause more reconnection windows during which the broker
    receives no publishes, so shorter intervals trade security for availability.
    """
    e2 = df[df["experiment"].str.startswith("E2-") | (df["experiment"] == "E0-default")]
    hop_vals = sorted(e2["hop"].dropna().unique())

    mtd_delivery    = [delivery(e2, LABEL_MTD_MODEL,  hop=h) for h in hop_vals]
    xmodel_delivery = [delivery(e2, LABEL_BASE_MODEL, hop=h) for h in hop_vals]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(hop_vals, mtd_delivery,    "o-",  color=COLOR_MTD,    lw=2,
            label="MTD-trained model",      zorder=3)
    ax.plot(hop_vals, xmodel_delivery, "s--", color=COLOR_XMODEL, lw=2,
            label="Baseline-trained model", zorder=3)

    ax.set_xscale("log")
    ax.set_xticks(hop_vals)
    ax.set_xticklabels([str(int(h)) for h in hop_vals])
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("hop interval (s)")
    ax.set_ylabel("delivery ratio  (broker received / client sent)")
    ax.set_title("E2 — Hop interval: MQTT delivery ratio vs reconnection frequency")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3, zorder=1)
    ax.figure.tight_layout()

    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"[sweep] {out_path}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Generate paper sweep figures")
    p.add_argument("--manifest",   default="output/sweep_manifest.csv")
    p.add_argument("--plots-root", default="output",
                   help="Root dir containing the per-experiment dirs "
                        "(each holds summary.csv)")
    p.add_argument("--out-dir",    default="output/sweep")
    args = p.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    df = load_sweep(args.manifest, args.plots_root)
    if df.empty:
        print("[error] no data loaded — did you run run_sweep.sh?")
        return

    base_ref = score(df, LABEL_BASELINE, experiment="E0-default")

    plot_e1(df, os.path.join(args.out_dir, "e1_address_diversity.pdf"))
    plot_e2(df, os.path.join(args.out_dir, "e2_hop_interval.pdf"), base_ref)
    plot_e2_delivery(df, os.path.join(args.out_dir, "e2_delivery_ratio.pdf"))
    plot_e3(df, os.path.join(args.out_dir, "e3_bg_noise.pdf"))

    out_csv = os.path.join(args.out_dir, "sweep_results.csv")
    df.to_csv(out_csv, index=False)
    print(f"[sweep] master CSV → {out_csv}")


if __name__ == "__main__":
    main()
