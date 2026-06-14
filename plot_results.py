#!/usr/bin/env python3
"""
plot_results.py — compare the experiment scenarios produced by run_experiment.py

Three scenarios are compared (defaults match the per-experiment output dirs
built by the Makefile targets — output/<exp-slug>/{eval,attack}/model-<src>/):

  1. Baseline           no MTD,  attacker model trained on baseline traffic
                        -> output/baseline-mbps<M>/.../model-baseline/
  2. MTD / base model   MTD on,  attacker model trained on baseline traffic
                        -> output/mtd-<slug>/.../model-baseline/  (make attack MODEL_SRC=baseline)
  3. MTD / MTD model    MTD on,  attacker model trained on MTD traffic
                        -> output/mtd-<slug>/.../model-mtd/

Two metrics are derived straight from the artifacts each attack run leaves on
disk — no need to re-run the lab:

  • Detection (security): re-score the scenario's attacker_capture.pcap with the
    model that scenario used (same code path as run_experiment.detect_nanogrid_ip)
    and read off the nanogrid score of the real SCMC IP and its rank. Higher score
    / rank-1 = the attacker's fingerprinting succeeds.

  • scmc_blocked (outcome): did the attacker's drop rule actually cut the SCMC off?
    True iff delivery to the SEMP falls silent and stays silent until the capture
    ends — the SCMC keeps publishing but nothing more reaches the SEMP for the whole
    post-attack window. (A surviving SCMC keeps delivering right up to the end.) The
    attack run.log confirms a rule was placed and names the dropped IP. Note this is
    independent of detection rank: blocking the wrong IP — or the broker's reply IP —
    can still, or fail to, sever delivery.

  • Availability (outcome): match every data packet the SCMC sent (scmc_capture.pcap,
    link A) against the packets that actually reached the SEMP segment
    (router_capture.pcap, the router's link-B / eth1 capture). A packet counts as
    delivered when its TCP segment — forwarded unchanged by the router — shows up in
    the link-B capture. When the router blackholes the SCMC it keeps emitting on
    link A but its packets never cross to link B, so the cumulative delivered curve
    plateaus while a surviving SCMC keeps climbing. This is MTD-agnostic: it follows
    packets by content, not by the SCMC's (hopping) broker IP/port, and needs no
    broker log.

Usage:
  python plot_results.py                       # default 3 scenarios -> output/<exp-slug>/
  python plot_results.py --no-detection        # availability only (skip pcap scoring)
  python plot_results.py --plots-dir output/mtd-<slug> --scmc-ip 10.0.0.2
"""

import argparse
import datetime
import hashlib
import os
import re
import socket
from dataclasses import dataclass, field

import dpkt
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
CUTOFF_GAP_S = 8.0             # silence after which a surviving SCMC is deemed cut off

# Markers left by run_experiment.py in the attack run.log.
BLOCK_RE = re.compile(r"Blocking nanogrid IP:\s*(\d{1,3}(?:\.\d{1,3}){3})")
NOBLOCK_RE = re.compile(r"No nanogrid IP detected")
LOG_TS_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3})")


@dataclass
class Scenario:
    """One experiment run: where its artifacts live and which model it used."""
    label: str
    out_dir: str                 # holds attacker_capture.pcap, scmc/router captures, ...
    model_dir: str               # <exp-dir>/model with model.pt + scaler.pkl
    ranking_csv: str = ""        # nanogrid_ranking.csv from attack run
    predictions_csv: str = ""    # predictions.csv from evaluate run (has label_true)
    # filled in by the analysis below
    delivered_epochs: list = field(default_factory=list)
    sent_count: int = 0
    delivery_ratio: float = float("nan")
    scmc_frac: float = float("nan")
    top_ip: str = ""
    top_frac: float = float("nan")
    blocked_scmc: bool = False
    blocked_ip: str = ""
    ranking: pd.DataFrame = None


def make_scenario(label: str, exp_dir: str, model_exp_dir: str, model_src: str) -> Scenario:
    """Build a Scenario from an experiment dir and the model that scores it.

    Artifacts for a config live under output/<exp-slug>/, keyed by the scoring
    model: attack/model-<src>/ and eval/model-<src>/. The model is read from the
    model-source config's model/ dir, so a cross-model run (MTD traffic scored by
    the baseline model) resolves to its own distinct files.
    """
    attack_dir = os.path.join(exp_dir, "attack", f"model-{model_src}")
    return Scenario(
        label,
        attack_dir,
        os.path.join(model_exp_dir, "model"),
        ranking_csv=os.path.join(attack_dir, "nanogrid_ranking.csv"),
        predictions_csv=os.path.join(
            exp_dir, "eval", f"model-{model_src}", "predictions.csv"
        ),
    )


def default_scenarios(root: str, mtd_params_slug: str, bg_replay_mbps: int = 2) -> list:
    """The three scenarios the experiment is designed to compare."""
    baseline_exp = os.path.join(root, f"baseline-mbps{bg_replay_mbps}")
    mtd_exp = os.path.join(root, f"mtd-{mtd_params_slug}")
    return [
        make_scenario("Baseline\n(no MTD)", baseline_exp, baseline_exp, "baseline"),
        make_scenario("MTD\n(baseline model)", mtd_exp, baseline_exp, "baseline"),
        make_scenario("MTD\n(MTD model)", mtd_exp, mtd_exp, "mtd"),
    ]


def baseline_scenarios(root: str, bg_replay_mbps: int = 2) -> list:
    """Just the no-MTD baseline run, for standalone baseline figures."""
    baseline_exp = os.path.join(root, f"baseline-mbps{bg_replay_mbps}")
    return [make_scenario("Baseline\n(no MTD)", baseline_exp, baseline_exp, "baseline")]


# ── Availability: match SCMC-sent packets against what reached the SEMP ───────

def _iter_tcp(pcap_path: str):
    """Yield (timestamp, src_ip, tcp) for every IPv4/TCP packet in a pcap.

    Uses dpkt (much faster than scapy on the multi-MB link-B captures) and stops
    cleanly on a truncated trailing record — tcpdump is killed mid-write, so the
    last pcap record is frequently partial.
    """
    with open(pcap_path, "rb") as f:
        reader = iter(dpkt.pcap.Reader(f))
        while True:
            try:
                ts, buf = next(reader)
            except StopIteration:
                break
            except dpkt.dpkt.NeedData:
                break  # truncated tail record (tcpdump killed mid-write)
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except dpkt.dpkt.UnpackError:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            yield ts, socket.inet_ntoa(ip.src), tcp


def _segment_key(tcp) -> bytes:
    """Content fingerprint of a TCP segment, identical at every capture point.

    The router forwards the datagram changing only the IP TTL and checksum, so the
    TCP sequence number, source port and (TLS-encrypted) payload uniquely identify
    the same packet on both link A (SCMC) and link B (SEMP segment).
    """
    return hashlib.md5(
        tcp.seq.to_bytes(4, "big") + tcp.sport.to_bytes(2, "big") + tcp.data
    ).digest()


def compute_delivery(scmc_pcap: str, router_pcap: str, scmc_ip: str) -> tuple:
    """Match SCMC-sent data packets against the packets that reached the SEMP.

    Returns (delivered_epochs, sent_count, router_t_max):
      • delivered_epochs — epoch timestamps of SCMC data packets (payload > 0) that
        also appear in the router's link-B capture, i.e. were forwarded to the SEMP.
      • sent_count       — SCMC data packets captured on link A within the router
        capture's time window (packets emitted after the router capture stopped
        can't be judged, so they're excluded).
      • router_t_max     — last timestamp in the link-B capture (the observation
        window end, used to decide whether delivery went silent before the run did).

    A blackholed SCMC keeps emitting on link A but its packets never cross to link B,
    so delivered_epochs stops advancing while sent_count keeps growing — the
    cumulative availability curve plateaus at the moment of the cut-off.
    """
    router_keys = set()
    router_t_max = 0.0
    for ts, _src, tcp in _iter_tcp(router_pcap):
        router_t_max = max(router_t_max, ts)
        if len(tcp.data) > 0:
            router_keys.add(_segment_key(tcp))

    delivered, sent = [], 0
    for ts, src, tcp in _iter_tcp(scmc_pcap):
        if src != scmc_ip or len(tcp.data) == 0 or ts > router_t_max:
            continue
        sent += 1
        if _segment_key(tcp) in router_keys:
            delivered.append(ts)
    return delivered, sent, router_t_max


def parse_block_event(run_log_path: str) -> tuple:
    """Read the attacker's drop-rule decision from an attack run.log.

    Returns (block_epoch, blocked_ip, decided_no_block):
      • block_epoch       — epoch seconds of the "Blocking nanogrid IP …" line, else None
      • blocked_ip        — the IP the attacker dropped ("" if none / unknown)
      • decided_no_block  — True iff the log explicitly recorded that nothing was blocked
    A missing or truncated log yields (None, "", False) → caller falls back to the
    capture-only heuristic.
    """
    block_epoch, blocked_ip, decided_no_block = None, "", False
    if not os.path.exists(run_log_path):
        return block_epoch, blocked_ip, decided_no_block
    with open(run_log_path, errors="replace") as f:
        for line in f:
            m = BLOCK_RE.search(line)
            if m:
                blocked_ip = m.group(1)
                tm = LOG_TS_RE.match(line)
                if tm:
                    block_epoch = datetime.datetime.strptime(
                        tm.group(1), "%Y-%m-%d %H:%M:%S,%f"
                    ).timestamp()
                return block_epoch, blocked_ip, decided_no_block
            if NOBLOCK_RE.search(line):
                decided_no_block = True
    return block_epoch, blocked_ip, decided_no_block


def scmc_cut_off(delivered_epochs: list, router_t_max: float,
                 block_epoch, decided_no_block: bool) -> bool:
    """Did the attacker's drop rule actually sever the SCMC→SEMP telemetry?

    True iff delivery to the SEMP falls silent and stays silent until the capture
    ends: a surviving SCMC keeps delivering right up to router_t_max (its client
    runs until lab teardown, past the router capture), whereas a cut-off one goes
    quiet right after the rule and never recovers for the whole post-attack window.
    We test the trailing silence rather than "zero packets after the block" so the
    handful of in-flight packets that squeak through in the instant after the rule
    (before TCP stalls) don't mask a real cut-off.

    decided_no_block (the attacker installed no rule) forces a survive verdict;
    block_epoch is used only to call an all-silent run a block when a rule was
    actually placed.
    """
    if decided_no_block:
        return False
    if not delivered_epochs:
        return block_epoch is not None  # a rule was placed and nothing got through
    return (router_t_max - max(delivered_epochs)) > CUTOFF_GAP_S


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
        verdict = "CUT OFF" if s.blocked_scmc else "survived"
        ax.annotate(f"{v:.2f}\n({verdict})",
                    (bar.get_x() + bar.get_width() / 2, v),
                    ha="center", va="bottom", fontsize=9)

    # legend proxies for the colour meaning (outcome, not detection rank)
    from matplotlib.patches import Patch
    handles = [
        Patch(facecolor="#c0392b", edgecolor="black", label="SCMC cut off after block"),
        Patch(facecolor="#27ae60", edgecolor="black", label="SCMC survived"),
    ]
    handles += ax.get_legend_handles_labels()[0]
    ax.legend(handles=handles, loc="upper right", fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    plt.close(fig)
    print(f"[plot] detection chart -> {out_path}")


def plot_availability(scenarios: list, out_path: str) -> None:
    """Cumulative SCMC packets delivered to the SEMP over time.

    Each step is an SCMC data packet that reached the SEMP segment (matched
    between the link-A and link-B captures). A surviving SCMC keeps climbing;
    once the router blackholes it nothing more crosses to link B and the curve
    plateaus. Cumulative (vs a per-second rate) is monotonic, so it's free of the
    transient gaps that MTD hop reconnections cause, and overlapping lines stay
    readable.
    """
    have = [s for s in scenarios if s.delivered_epochs]
    if not have:
        print("[plot] no delivery data — skipping availability chart")
        return

    # Common axis: align each scenario to its own first delivery, extend every
    # curve flat to the longest run so an early plateau (cut-off) stands out.
    spans = [max(s.delivered_epochs) - min(s.delivered_epochs) for s in have]
    t_max = max(spans) + 3
    styles = ["-", "--", ":", "-."]

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, s in enumerate(have):
        t0 = min(s.delivered_epochs)
        rel = np.array(sorted(e - t0 for e in s.delivered_epochs), dtype=float)
        cum = np.arange(1, len(rel) + 1, dtype=float)
        # frame at 0 and hold the final value to t_max (flat tail = no telemetry)
        rel = np.concatenate(([0.0], rel, [t_max]))
        cum = np.concatenate(([0.0], cum, [cum[-1]]))
        ax.step(rel, cum, where="post", lw=2.2, alpha=0.8,
                ls=styles[i % len(styles)], label=s.label.replace("\n", " "))

    ax.set_xlabel("time since first delivery (s)")
    ax.set_ylabel("cumulative SCMC packets delivered to SEMP")
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
    ip = scmc_ip or DEFAULT_SCMC_IP   # SCMC source IP on both link A and link B
    for s in scenarios:
        scmc_pcap = os.path.join(s.out_dir, "scmc_capture.pcap")
        router_pcap = os.path.join(s.out_dir, "router_capture.pcap")
        attacker_pcap = os.path.join(s.out_dir, "attacker_capture.pcap")

        # Availability: match SCMC-sent packets against what reached the SEMP, then
        # decide the outcome — was the SCMC actually cut off after the attacker's
        # drop rule? (independent of whether detection ranked it first).
        if os.path.exists(scmc_pcap) and os.path.exists(router_pcap):
            print(f"[avail] {s.label!r}: matching {scmc_pcap} vs {router_pcap}")
            s.delivered_epochs, s.sent_count, router_t_max = compute_delivery(
                scmc_pcap, router_pcap, ip
            )
            if s.sent_count > 0:
                s.delivery_ratio = len(s.delivered_epochs) / s.sent_count
            block_epoch, s.blocked_ip, no_block = parse_block_event(
                os.path.join(s.out_dir, "run.log")
            )
            s.blocked_scmc = scmc_cut_off(
                s.delivered_epochs, router_t_max, block_epoch, no_block
            )
        else:
            print(f"[warn] scmc/router capture missing in {s.out_dir} — "
                  f"no availability for '{s.label}'")

        # Detection (fingerprinting score / rank — separate from the block outcome)
        if do_detection:
            model_ok = os.path.exists(os.path.join(s.model_dir, "model.pt"))
            if os.path.exists(attacker_pcap) and model_ok:
                print(f"[score] {s.label!r}: {attacker_pcap}  with model {s.model_dir}")
                ranking = score_detection(attacker_pcap, s.model_dir, ip)
                s.ranking = ranking
                if not ranking.empty:
                    s.top_ip = str(ranking.index[0])
                    s.top_frac = float(ranking.iloc[0]["nanogrid_frac"])
                    if ip in ranking.index:
                        s.scmc_frac = float(ranking.loc[ip, "nanogrid_frac"])
            else:
                print(f"[warn] cannot score '{s.label}' "
                      f"(pcap or model missing) — skipping detection")


def print_summary(scenarios: list) -> None:
    rows = []
    for s in scenarios:
        n_deliv = len(s.delivered_epochs)
        span = (max(s.delivered_epochs) - min(s.delivered_epochs)) if n_deliv else 0
        rows.append({
            "scenario": s.label.replace("\n", " "),
            "scmc_nanogrid_frac": round(s.scmc_frac, 3) if not np.isnan(s.scmc_frac) else None,
            "top_ip": s.top_ip,
            "blocked_ip": s.blocked_ip,
            "scmc_blocked": s.blocked_scmc,
            "publishes": n_deliv,
            "publish_span_s": round(span, 1),
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
                        "Selects the baseline-mbps<M> experiment dir.")
    p.add_argument("--baseline-only", action="store_true",
                   help="Plot just the no-MTD baseline run (its own figures, into "
                        "the baseline-mbps<M> dir) instead of the 3-scenario "
                        "MTD comparison.")
    p.add_argument("--replot-all", action="store_true",
                   help="Regenerate figures + summary.csv for every experiment dir "
                        "found under --output-root (each baseline-mbps<M>/ and "
                        "mtd-<slug>/), writing into each dir. Ignores --plots-dir / "
                        "--mtd-params-slug / --bg-replay-mbps / --baseline-only.")
    return p.parse_args()


def generate_figures(scenarios: list, plots_dir: str, scmc_ip, do_detection: bool,
                     topk: int) -> None:
    """Analyse the scenarios and write summary.csv + figures into plots_dir."""
    os.makedirs(plots_dir, exist_ok=True)
    analyse(scenarios, scmc_ip, do_detection=do_detection)

    summary = print_summary(scenarios)
    summary.to_csv(os.path.join(plots_dir, "summary.csv"), index=False)
    print(f"[plot] summary table -> {os.path.join(plots_dir, 'summary.csv')}")

    if do_detection:
        plot_detection(scenarios, os.path.join(plots_dir, "detection.pdf"))
    plot_availability(scenarios, os.path.join(plots_dir, "availability.pdf"))
    plot_topk_flows(scenarios, os.path.join(plots_dir, "topk_flows.pdf"), k=topk)


def discover_configs(root: str) -> list:
    """Find every experiment dir under root and build its (scenarios, plots_dir).

    Baseline dirs (baseline-mbps<M>/) get the standalone baseline figure set; MTD
    dirs (mtd-<slug>-mbps<M>/) get the 3-scenario comparison. The replay rate and
    MTD slug are recovered from the directory name.
    """
    configs = []
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        m = re.fullmatch(r"baseline-mbps(\d+)", name)
        if m:
            mbps = int(m.group(1))
            configs.append((baseline_scenarios(root, mbps), path))
            continue
        m = re.fullmatch(r"mtd-(.+-mbps(\d+))", name)
        if m:
            slug, mbps = m.group(1), int(m.group(2))
            configs.append((default_scenarios(root, slug, mbps), path))
    return configs


def main() -> None:
    args = parse_args()

    if args.replot_all:
        configs = discover_configs(args.output_root)
        if not configs:
            print(f"[plot] no experiment dirs found under {args.output_root}")
            return
        print(f"[plot] replotting {len(configs)} experiment dir(s) under {args.output_root}")
        for scenarios, plots_dir in configs:
            print(f"\n=== {plots_dir} ===")
            generate_figures(scenarios, plots_dir, args.scmc_ip,
                             not args.no_detection, args.topk)
        return

    # Single config. Default the outputs (summary.csv + plots) into the relevant
    # config's experiment dir, matching the Makefile (which passes --plots-dir).
    if args.baseline_only:
        default_dir = os.path.join(args.output_root, f"baseline-mbps{args.bg_replay_mbps}")
        scenarios = baseline_scenarios(args.output_root, args.bg_replay_mbps)
    else:
        default_dir = os.path.join(args.output_root, f"mtd-{args.mtd_params_slug}")
        scenarios = default_scenarios(
            args.output_root, args.mtd_params_slug, args.bg_replay_mbps,
        )
    plots_dir = args.plots_dir or default_dir
    generate_figures(scenarios, plots_dir, args.scmc_ip,
                     not args.no_detection, args.topk)


if __name__ == "__main__":
    main()
