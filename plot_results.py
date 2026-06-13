#!/usr/bin/env python3
"""
plot_results.py — compare the experiment scenarios produced by run_experiment.py

Three scenarios are compared (defaults match the output tree built by the
Makefile targets):

  1. Baseline           no MTD,  attacker model trained on baseline traffic
                        -> output/baseline/
  2. MTD / base model   MTD on,  attacker model trained on baseline traffic
                        -> output/mtd/model-baseline/   (make attack MODEL_SRC=baseline)
  3. MTD / MTD model    MTD on,  attacker model trained on MTD traffic
                        -> output/mtd/

Two metrics are derived straight from the artifacts each attack run leaves on
disk — no need to re-run the lab:

  • Detection (security): re-score the scenario's attacker_capture.pcap with the
    model that scenario used (same code path as run_experiment.detect_nanogrid_ip)
    and read off the nanogrid score of the real SCMC IP and whether it was the
    top-ranked (i.e. blocked) IP. Higher score / rank-1 = attacker wins.

  • Availability (outcome): parse mosquitto.log for "Received PUBLISH from scmc1"
    lines and bin them per second. When the router blackholes the SCMC the broker
    stops receiving publishes, so the rate drops to zero — a blocked SCMC is
    visibly cut off, a surviving one keeps publishing.

Usage:
  python plot_results.py                       # default 3 scenarios -> output/plots/
  python plot_results.py --no-detection        # availability only (skip pcap scoring)
  python plot_results.py --plots-dir output/plots --scmc-ip 10.0.0.2
"""

import argparse
import os
import re
from dataclasses import dataclass, field

import matplotlib

matplotlib.use("Agg")  # headless: write PNGs, no display needed
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from classify import (
    extract_features,
    load_artifacts,
    predict_packets,
    rank_nanogrid_ips,
)

DEFAULT_SCMC_IP = "10.0.0.2"   # SCMC source IP as seen on the wire (lab default)
DETECT_THRESHOLD = 0.3         # matches classify._detect_nanogrid_ip
PUBLISH_RE = re.compile(r"^(\d+):\s+Received PUBLISH from scmc1\b")
CONNECT_RE = re.compile(r"New (?:connection|client connected) from (\d+\.\d+\.\d+\.\d+)")
# Matches the telemetry line in both simple_client.log and mtd_executor.log.
# Baseline:  [scmc1] power=  84.6 kW ...
# MTD:       [scmc1] #1 → 10.1.0.2:8883  power=  84.6 kW ...
SENT_RE = re.compile(r"\] (?:#\d+ → \S+\s+)?power=")


@dataclass
class Scenario:
    """One experiment run: where its artifacts live and which model it used."""
    label: str
    out_dir: str                 # holds attacker_capture.pcap, mosquitto.log, ...
    model_dir: str               # ml_results dir with model.pt + scaler.pkl
    ranking_csv: str = ""        # nanogrid_ranking.csv from attack run
    predictions_csv: str = ""    # predictions.csv from evaluate run (has label_true)
    # filled in by the analysis below
    publish_epochs: list = field(default_factory=list)
    sent_count: int = 0
    delivery_ratio: float = float("nan")
    scmc_frac: float = float("nan")
    top_ip: str = ""
    top_frac: float = float("nan")
    blocked_scmc: bool = False
    ranking: pd.DataFrame = None


def default_scenarios(root: str, mtd_params_slug: str, bg_replay_mbps: int = 2) -> list:
    """The three scenarios the experiment is designed to compare."""
    slug_b  = f"baseline-scenario-baseline-model-mbps{bg_replay_mbps}"
    slug_mb = f"mtd-scenario-baseline-model-{mtd_params_slug}"
    slug_mm = f"mtd-scenario-mtd-model-{mtd_params_slug}"
    return [
        Scenario(
            "Baseline\n(no MTD)",
            os.path.join(root, "experiment-results", slug_b),
            os.path.join(root, "models", "baseline"),
            ranking_csv=os.path.join(root, "experiment-results", slug_b, "nanogrid_ranking.csv"),
            predictions_csv=os.path.join(root, "ml-results", slug_b, "predictions.csv"),
        ),
        Scenario(
            "MTD\n(baseline model)",
            os.path.join(root, "experiment-results", slug_mb),
            os.path.join(root, "models", "baseline"),
            ranking_csv=os.path.join(root, "experiment-results", slug_mb, "nanogrid_ranking.csv"),
            predictions_csv=os.path.join(root, "ml-results", slug_mb, "predictions.csv"),
        ),
        Scenario(
            "MTD\n(MTD model)",
            os.path.join(root, "experiment-results", slug_mm),
            os.path.join(root, "models", "mtd"),
            ranking_csv=os.path.join(root, "experiment-results", slug_mm, "nanogrid_ranking.csv"),
            predictions_csv=os.path.join(root, "ml-results", slug_mm, "predictions.csv"),
        ),
    ]


# ── Availability: parse mosquitto.log ─────────────────────────────────────────

def parse_client_sent(log_path: str) -> int:
    """Count MQTT messages sent by the client (4 per telemetry step)."""
    count = sum(1 for line in open(log_path, errors="replace") if SENT_RE.search(line))
    return count * 4


def parse_publish_epochs(log_path: str) -> list:
    """Return the epoch timestamp of every PUBLISH the broker received from scmc1."""
    epochs = []
    with open(log_path, "r", errors="replace") as f:
        for line in f:
            m = PUBLISH_RE.match(line)
            if m:
                epochs.append(int(m.group(1)))
    return epochs


def scmc_ip_from_log(log_path: str) -> str:
    """Best-effort: the SCMC source IP the broker saw connect (fallback to default)."""
    try:
        with open(log_path, "r", errors="replace") as f:
            for line in f:
                m = CONNECT_RE.search(line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ""


# ── Detection: re-score attacker_capture.pcap with the scenario's model ───────

def score_detection(pcap_path: str, model_dir: str, scmc_ip: str) -> pd.DataFrame:
    """Replicate run_experiment.detect_nanogrid_ip: rank source IPs by nanogrid frac."""
    model_path = os.path.join(model_dir, "model.pt")
    scaler_path = os.path.join(model_dir, "scaler.pkl")
    df = extract_features(pcap_path)  # unlabeled, like the attacker sees it
    model, scaler = load_artifacts(model_path, scaler_path)
    preds = predict_packets(df, model, scaler)
    return rank_nanogrid_ips(preds)


# ── Plots ─────────────────────────────────────────────────────────────────────

def plot_detection(scenarios: list, out_path: str) -> None:
    """Bar chart: nanogrid score of the real SCMC IP per scenario (attacker's win)."""
    labels = [s.label for s in scenarios]
    fracs = [s.scmc_frac for s in scenarios]
    x = np.arange(len(scenarios))

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ["#c0392b" if s.blocked_scmc else "#27ae60" for s in scenarios]
    bars = ax.bar(x, fracs, color=colors, width=0.6, edgecolor="black")

    ax.axhline(DETECT_THRESHOLD, ls="--", color="gray",
               label=f"detection threshold ({DETECT_THRESHOLD})")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("nanogrid score of the real SCMC IP")
    ax.set_ylim(0, 1.05)
    ax.set_title("Attacker fingerprinting — can it pick the SCMC?")

    for bar, s in zip(bars, scenarios):
        v = 0.0 if np.isnan(s.scmc_frac) else s.scmc_frac
        verdict = "BLOCKED" if s.blocked_scmc else "evaded"
        ax.annotate(f"{v:.2f}\n({verdict})",
                    (bar.get_x() + bar.get_width() / 2, v),
                    ha="center", va="bottom", fontsize=9)

    # legend proxies for the colour meaning
    from matplotlib.patches import Patch
    handles = [
        Patch(facecolor="#c0392b", edgecolor="black", label="SCMC top-ranked → blocked"),
        Patch(facecolor="#27ae60", edgecolor="black", label="SCMC not top-ranked → survives"),
    ]
    handles += ax.get_legend_handles_labels()[0]
    ax.legend(handles=handles, loc="upper right", fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f"[plot] detection chart -> {out_path}")


def plot_availability(scenarios: list, out_path: str) -> None:
    """Cumulative broker-received publishes over time — telemetry delivered.

    A surviving SCMC keeps climbing at ~4 msg/s; once the router blackholes it
    the broker receives nothing more and the curve plateaus. Cumulative (vs a
    per-second rate) is monotonic, so it's free of the transient one-second gaps
    that MTD hop reconnections cause, and overlapping lines stay readable.
    """
    have = [s for s in scenarios if s.publish_epochs]
    if not have:
        print("[plot] no publish data — skipping availability chart")
        return

    # Common axis: align each scenario to its own first publish, extend every
    # curve flat to the longest run so an early plateau (cut-off) stands out.
    spans = [max(s.publish_epochs) - min(s.publish_epochs) for s in have]
    t_max = max(spans) + 3
    styles = ["-", "--", ":", "-."]

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, s in enumerate(have):
        t0 = min(s.publish_epochs)
        rel = np.array(sorted(e - t0 for e in s.publish_epochs), dtype=float)
        cum = np.arange(1, len(rel) + 1, dtype=float)
        # frame at 0 and hold the final value to t_max (flat tail = no telemetry)
        rel = np.concatenate(([0.0], rel, [t_max]))
        cum = np.concatenate(([0.0], cum, [cum[-1]]))
        ax.step(rel, cum, where="post", lw=2.2, alpha=0.8,
                ls=styles[i % len(styles)], label=s.label.replace("\n", " "))

    ax.set_xlabel("time since first publish (s)")
    ax.set_ylabel("cumulative PUBLISH received by broker")
    ax.set_title("SCMC availability — telemetry delivered during the attack")
    ax.legend(loc="upper left", fontsize=9)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f"[plot] availability chart -> {out_path}")


def plot_topk_flows(scenarios: list, out_path: str, k: int = 5) -> None:
    """Horizontal bar chart: top-k most-suspected flows and their confidence score.

    Flows are ranked by mean prediction probability across their packets (from
    predictions.csv). Each scenario gets its own subplot so the three rankings
    can be compared side by side.
    """
    valid = []
    for s in scenarios:
        if not s.predictions_csv or not os.path.exists(s.predictions_csv):
            print(f"[warn] {s.predictions_csv or '(none)'} missing — skipping top-k for '{s.label}'")
            continue
        valid.append(s)

    if not valid:
        print("[plot] no predictions data — skipping top-k flows chart")
        return

    fig, axes = plt.subplots(1, len(valid), figsize=(5 * len(valid), max(3, k * 0.55 + 1.5)),
                             sharey=False)
    if len(valid) == 1:
        axes = [axes]

    for ax, s in zip(axes, valid):
        preds = pd.read_csv(s.predictions_csv)

        flow_conf = (
            preds.groupby("flow_key")["prob"]
            .mean()
            .sort_values(ascending=False)
            .head(k)
        )

        labels = [fk if len(fk) <= 35 else f"…{fk[-33:]}" for fk in flow_conf.index]
        confs = flow_conf.values

        bars = ax.barh(range(len(confs)), confs, color="#2980b9", edgecolor="black", height=0.6)
        ax.set_yticks(range(len(confs)))
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlim(0, 1.05)
        ax.axvline(DETECT_THRESHOLD, ls="--", color="gray", lw=1,
                   label=f"threshold ({DETECT_THRESHOLD})")
        ax.set_xlabel("confidence (mean prob)")
        ax.set_title(s.label.replace("\n", " "), fontsize=10)
        ax.legend(fontsize=8, loc="lower right")
        ax.grid(True, axis="x", alpha=0.3)

        for bar, conf in zip(bars, confs):
            ax.text(min(conf + 0.02, 1.0), bar.get_y() + bar.get_height() / 2,
                    f"{conf:.2f}", va="center", fontsize=8)

    fig.suptitle(f"Top-{k} suspected flows by nanogrid confidence", fontsize=12, y=1.01)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    print(f"[plot] top-{k} flows chart -> {out_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def analyse(scenarios: list, scmc_ip: str, do_detection: bool) -> None:
    for s in scenarios:
        log_path = os.path.join(s.out_dir, "mosquitto.log")
        pcap_path = os.path.join(s.out_dir, "attacker_capture.pcap")

        # Availability
        if os.path.exists(log_path):
            s.publish_epochs = parse_publish_epochs(log_path)
            ip = scmc_ip or scmc_ip_from_log(log_path) or DEFAULT_SCMC_IP
        else:
            print(f"[warn] {log_path} missing — no availability for '{s.label}'")
            ip = scmc_ip or DEFAULT_SCMC_IP

        # Delivery ratio: compare what the client sent vs what the broker received
        for client_log_name in ("simple_client.log", "mtd_executor.log"):
            client_log = os.path.join(s.out_dir, client_log_name)
            if os.path.exists(client_log):
                s.sent_count = parse_client_sent(client_log)
                break
        if s.sent_count > 0 and s.publish_epochs:
            s.delivery_ratio = len(s.publish_epochs) / s.sent_count

        # Detection
        if do_detection:
            model_ok = os.path.exists(os.path.join(s.model_dir, "model.pt"))
            if os.path.exists(pcap_path) and model_ok:
                print(f"[score] {s.label!r}: {pcap_path}  with model {s.model_dir}")
                ranking = score_detection(pcap_path, s.model_dir, ip)
                s.ranking = ranking
                if not ranking.empty:
                    s.top_ip = str(ranking.index[0])
                    s.top_frac = float(ranking.iloc[0]["nanogrid_frac"])
                    if ip in ranking.index:
                        s.scmc_frac = float(ranking.loc[ip, "nanogrid_frac"])
                    s.blocked_scmc = (
                        s.top_ip == ip and s.top_frac >= DETECT_THRESHOLD
                    )
            else:
                print(f"[warn] cannot score '{s.label}' "
                      f"(pcap or model missing) — skipping detection")


def print_summary(scenarios: list) -> None:
    rows = []
    for s in scenarios:
        n_pub = len(s.publish_epochs)
        span = (max(s.publish_epochs) - min(s.publish_epochs)) if n_pub else 0
        rows.append({
            "scenario": s.label.replace("\n", " "),
            "scmc_nanogrid_frac": round(s.scmc_frac, 3) if not np.isnan(s.scmc_frac) else None,
            "top_ip": s.top_ip,
            "scmc_blocked": s.blocked_scmc,
            "publishes": n_pub,
            "publish_span_s": span,
            "sent_msgs": s.sent_count if s.sent_count > 0 else None,
            "delivery_ratio": round(s.delivery_ratio, 4) if not np.isnan(s.delivery_ratio) else None,
        })
    df = pd.DataFrame(rows)
    print("\n=== Summary ===")
    print(df.to_string(index=False))
    return df


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Plot & compare experiment scenarios")
    p.add_argument("--output-root", default="output",
                   help="Root of the experiment output tree (default: output)")
    p.add_argument("--plots-dir", default=None,
                   help="Where to write the PNGs (default: <output-root>/plots)")
    p.add_argument("--scmc-ip", default=None,
                   help=f"Real SCMC source IP (default: auto from log, else {DEFAULT_SCMC_IP})")
    p.add_argument("--no-detection", action="store_true",
                   help="Skip pcap re-scoring (availability plot only)")
    p.add_argument("--topk", type=int, default=5,
                   help="Number of top suspected flows to show (default: 5)")
    p.add_argument("--mtd-params-slug",
                   default="hop2-padint3-ports5-pads7-mbps2",
                   metavar="SLUG",
                   help="MTD parameter slug used in output dir names "
                        "(default: matches Makefile defaults: hop2-padint3-ports5-pads7-mbps2).")
    p.add_argument("--bg-replay-mbps", type=int, default=2, metavar="MBPS",
                   help="Background replay rate used in this run (default: 2). "
                        "Encoded in the baseline scenario slug.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    plots_dir = args.plots_dir or os.path.join(args.output_root, "plots")
    os.makedirs(plots_dir, exist_ok=True)

    scenarios = default_scenarios(args.output_root, args.mtd_params_slug, args.bg_replay_mbps)
    analyse(scenarios, args.scmc_ip, do_detection=not args.no_detection)

    summary = print_summary(scenarios)
    summary.to_csv(os.path.join(plots_dir, "summary.csv"), index=False)
    print(f"[plot] summary table -> {os.path.join(plots_dir, 'summary.csv')}")

    if not args.no_detection:
        plot_detection(scenarios, os.path.join(plots_dir, "detection.pdf"))
    plot_availability(scenarios, os.path.join(plots_dir, "availability.pdf"))
    plot_topk_flows(scenarios, os.path.join(plots_dir, "topk_flows.pdf"), k=args.topk)


if __name__ == "__main__":
    main()
