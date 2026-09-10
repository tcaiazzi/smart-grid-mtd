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

plt.rcParams["axes.labelsize"] = 12  # axis (x/y) label font size
plt.rcParams["xtick.labelsize"] = 12  # x tick-label font size
plt.rcParams["ytick.labelsize"] = 12  # y tick-label font size
import pandas as pd

from classify import (
    extract_features,
    load_artifacts,
    predict_packets,
    rank_nanogrid_ips,
)
from entropy import plot_entropy_comparison, plot_entropy_timeseries

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
    exp_dir: str = ""            # per-config root (holds entropy.csv / entropy_timeseries.csv)
    ranking_csv: str = ""        # nanogrid_ranking.csv from attack run
    predictions_csv: str = ""    # predictions.csv from evaluate run (has label_true)
    # filled in by the analysis below
    delivered_epochs: list = field(default_factory=list)
    router_t_min: float = float("nan")   # link-B capture window start (axis anchor)
    router_t_max: float = float("nan")   # link-B capture window end
    nanogrid_detect: float = float("nan")  # avg attacker nanogrid_frac over the nanogrid IPs
    n_nanogrid_ips: int = 0
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
        exp_dir=exp_dir,
        ranking_csv=os.path.join(attack_dir, "nanogrid_ranking.csv"),
        predictions_csv=os.path.join(
            exp_dir, "eval", f"model-{model_src}", "predictions.csv"
        ),
    )


def default_scenarios(root: str, mtd_params_slug: str, bg_replay_mbps: int = 2,
                      mtd_prefix: str = "mtd") -> list:
    """The three scenarios the experiment is designed to compare.

    `mtd_prefix` selects the coordinator dir under test (mtd / mtdrl / mtdrl-<tag>)
    so RL runs compare against their own artifacts, not the fixed-timer mtd- dir.
    """
    baseline_exp = os.path.join(root, f"baseline-mbps{bg_replay_mbps}")
    mtd_exp = os.path.join(root, f"{mtd_prefix}-{mtd_params_slug}")
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


def compute_delivery(scmc_pcap: str, router_pcap: str, scmc_ips) -> tuple:
    """Match SCMC-sent data packets against the packets that reached the SEMP.

    `scmc_ips` is the SCMC source-IP pool (a set/iterable). Under MTD source-IP
    hopping the client emits from several addresses, so matching a single IP would
    drop every hopped packet from both sent and delivered counts; we keep any packet
    whose source is in the pool. Delivery matching is IP-agnostic anyway (the content
    fingerprint ignores the IP header), so a packet still matches across a hop.

    Returns (delivered_epochs, sent_count, router_t_min, router_t_max):
      • delivered_epochs — epoch timestamps of SCMC data packets (payload > 0) that
        also appear in the router's link-B capture, i.e. were forwarded to the SEMP.
      • sent_count       — SCMC data packets captured on link A within the router
        capture's time window (packets emitted after the router capture stopped
        can't be judged, so they're excluded).
      • router_t_min     — first timestamp in the link-B capture (the observation
        window start: the client runs the whole experiment, so this anchors the
        availability axis to the full router trace, not just the delivery span).
      • router_t_max     — last timestamp in the link-B capture (the observation
        window end, used to decide whether delivery went silent before the run did).

    A blackholed SCMC keeps emitting on link A but its packets never cross to link B,
    so delivered_epochs stops advancing while sent_count keeps growing — the
    cumulative availability curve plateaus at the moment of the cut-off.
    """
    router_keys = set()
    router_t_min, router_t_max = float("inf"), 0.0
    for ts, _src, tcp in _iter_tcp(router_pcap):
        router_t_min = min(router_t_min, ts)
        router_t_max = max(router_t_max, ts)
        if len(tcp.data) > 0:
            router_keys.add(_segment_key(tcp))
    if router_t_min == float("inf"):
        router_t_min = 0.0  # empty link-B capture

    scmc_set = {scmc_ips} if isinstance(scmc_ips, str) else set(scmc_ips)
    delivered, sent = [], 0
    for ts, src, tcp in _iter_tcp(scmc_pcap):
        if src not in scmc_set or len(tcp.data) == 0 or ts > router_t_max:
            continue
        sent += 1
        if _segment_key(tcp) in router_keys:
            delivered.append(ts)
    return delivered, sent, router_t_min, router_t_max


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


# Lab subnets that carry the nanogrid: 10.0.0.x = SCMC side, 10.1.0.x = SEMP side.
# Everything else in a capture (192.168.x, public internet replay) is background.
NANOGRID_SUBNET_PREFIXES = ("10.0.0.", "10.1.0.")


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
    df = pd.read_csv(ranking_csv)
    if "src_ip" not in df.columns or "nanogrid_frac" not in df.columns:
        return float("nan"), 0

    def _is_nanogrid(ip: str) -> bool:
        return ip in scmc_pool or ip.startswith(NANOGRID_SUBNET_PREFIXES)

    ng = df[df["src_ip"].map(_is_nanogrid)]
    if ng.empty:
        return float("nan"), 0
    return float(ng["nanogrid_frac"].mean()), int(len(ng))


# ── Plots ─────────────────────────────────────────────────────────────────────

def plot_detection(scenarios: list, out_path: str) -> None:
    """Attacker fingerprinting of the nanogrid IPs — baseline vs MTD.

    One bar per scenario that has a saved nanogrid_ranking.csv: the average attacker
    nanogrid_frac over the src_ips that belong to the nanogrid in that experiment
    (ranking_nanogrid_detection). The attacker model is held fixed; MTD diluting the
    nanogrid signal pulls the average down, so a lower MTD bar is the win.
    """
    have = [s for s in scenarios if not np.isnan(s.nanogrid_detect)]
    if not have:
        print("[plot] no nanogrid ranking data — skipping detection chart")
        return

    labels = [s.label.replace("\n", " ") for s in have]
    vals = [s.nanogrid_detect for s in have]
    x = np.arange(len(have))
    # baseline grey, MTD green (matches the coordinator-comparison palette)
    colors = ["#7f8c8d" if os.path.basename(s.exp_dir).startswith("baseline-")
              else "#27ae60" for s in have]

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(x, vals, color=colors, width=0.55, edgecolor="black")

    
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Avg attacker accuracy on nanogrid IPs")
    ax.set_ylim(0, 1.05)

    for bar, s in zip(bars, have):
        ax.annotate(f"{s.nanogrid_detect:.2f}\n({s.n_nanogrid_ips} IPs)",
                    (bar.get_x() + bar.get_width() / 2, s.nanogrid_detect),
                    ha="center", va="bottom", fontsize=9)

    ax.legend(loc="upper right", fontsize=9)
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

    # Common axis spanning the whole experiment: anchor every curve to the start of
    # its router (link-B) capture and extend flat to the longest router trace. The
    # SCMC client runs for the entire run, so a cut-off scenario's plateau then
    # stretches across the full window instead of stopping at its last delivery.
    t_max = max(s.router_t_max - s.router_t_min for s in have)
    styles = ["-", "--", ":", "-."]

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, s in enumerate(have):
        t0 = s.router_t_min
        rel = np.array(sorted(max(e - t0, 0.0) for e in s.delivered_epochs), dtype=float)
        cum = np.arange(1, len(rel) + 1, dtype=float)
        # frame at 0 and hold the final value to t_max (flat tail = no telemetry)
        rel = np.concatenate(([0.0], rel, [t_max]))
        cum = np.concatenate(([0.0], cum, [cum[-1]]))
        ax.step(rel, cum, where="post", lw=2.2, alpha=0.8,
                ls=styles[i % len(styles)], label=s.label.replace("\n", " "))

    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Cumulative Updates Delivered")
    ax.legend(loc="upper left", fontsize=12)
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


def plot_entropy_section(scenarios: list, plots_dir: str) -> None:
    """Emit the entropy figures from each config's precomputed entropy CSVs.

    Reuses entropy.py's plotters and the CSVs `make entropy` wrote into each
    config dir (entropy.csv + entropy_timeseries.csv), so no pcap is re-parsed
    here. The comparison needs both a baseline-mbps<M>/ and an mtd-<slug>/ config;
    the timeseries comes from the MTD config (or the baseline one for baseline-only
    runs). Missing CSVs are warn-skipped, like the top-k flows chart.
    """
    def _exp_dir(pred):
        return next(
            (s.exp_dir for s in scenarios
             if s.exp_dir and pred(os.path.basename(s.exp_dir))),
            None,
        )

    # The MTD dir is whichever scenario isn't the baseline — covers mtd / mtdrl /
    # mtdrl-<tag> without hardcoding a prefix (so RL runs use their own entropy.csv).
    baseline_dir = _exp_dir(lambda n: n.startswith("baseline-"))
    mtd_dir = _exp_dir(lambda n: not n.startswith("baseline-"))

    # Timeseries — the live moving target (MTD config, else the baseline run).
    ts_dir = mtd_dir or baseline_dir
    ts_csv = os.path.join(ts_dir, "entropy_timeseries.csv") if ts_dir else None
    if ts_csv and os.path.exists(ts_csv):
        plot_entropy_timeseries(ts_csv, os.path.join(plots_dir, "entropy_timeseries.pdf"))
    else:
        print(f"[warn] {ts_csv or '(no exp dir)'} missing — skipping entropy timeseries")

    # Comparison — baseline vs MTD (needs both configs' entropy.csv).
    if not (baseline_dir and mtd_dir):
        print("[plot] no baseline+MTD pair — skipping entropy comparison")
        return
    baseline_csv = os.path.join(baseline_dir, "entropy.csv")
    mtd_csv = os.path.join(mtd_dir, "entropy.csv")
    if os.path.exists(baseline_csv) and os.path.exists(mtd_csv):
        plot_entropy_comparison(
            baseline_csv, mtd_csv, os.path.join(plots_dir, "entropy_comparison.pdf")
        )
    else:
        missing = [p for p in (baseline_csv, mtd_csv) if not os.path.exists(p)]
        print(f"[warn] {missing} missing — skipping entropy comparison "
              f"(run `make entropy` first)")


# ── Main ──────────────────────────────────────────────────────────────────────

def load_scmc_pool(exp_dir: str, fallback_ip: str) -> set:
    """SCMC source-IP pool for a config, from datasets/scmc_ips.txt.

    MTD hops the SCMC source IP across this pool, so availability must match every
    address it uses, not just the base IP. The file is the comma-separated pool
    written at dataset time; `fallback_ip` (the auto-detected/base IP) is always
    included and is the sole entry when the file is missing (e.g. baseline).
    """
    pool = {fallback_ip}
    path = os.path.join(exp_dir, "datasets", "scmc_ips.txt")
    if os.path.exists(path):
        with open(path) as f:
            pool |= {ip.strip() for ip in f.read().split(",") if ip.strip()}
    return pool


def analyse(scenarios: list, scmc_ip: str, do_detection: bool) -> None:
    ip = scmc_ip or DEFAULT_SCMC_IP   # SCMC source IP on both link A and link B
    for s in scenarios:
        scmc_pcap = os.path.join(s.out_dir, "scmc_capture.pcap")
        router_pcap = os.path.join(s.out_dir, "router_capture.pcap")
        attacker_pcap = os.path.join(s.out_dir, "attacker_capture.pcap")
        scmc_pool = load_scmc_pool(s.exp_dir, ip)

        # Attacker fingerprinting of the nanogrid: average the saved ranking's
        # nanogrid_frac over the src_ips that belong to the nanogrid in this
        # experiment (SCMC pool + SEMP subnet). Cheap CSV read — always computed.
        s.nanogrid_detect, s.n_nanogrid_ips = ranking_nanogrid_detection(
            s.ranking_csv, scmc_pool
        )

        # Availability: match SCMC-sent packets against what reached the SEMP, then
        # decide the outcome — was the SCMC actually cut off after the attacker's
        # drop rule? (independent of whether detection ranked it first).
        if os.path.exists(scmc_pcap) and os.path.exists(router_pcap):
            print(f"[avail] {s.label!r}: matching {scmc_pcap} vs {router_pcap} "
                  f"(scmc pool={sorted(scmc_pool)})")
            s.delivered_epochs, s.sent_count, s.router_t_min, s.router_t_max = \
                compute_delivery(scmc_pcap, router_pcap, scmc_pool)
            if s.sent_count > 0:
                s.delivery_ratio = len(s.delivered_epochs) / s.sent_count
            block_epoch, s.blocked_ip, no_block = parse_block_event(
                os.path.join(s.out_dir, "run.log")
            )
            s.blocked_scmc = scmc_cut_off(
                s.delivered_epochs, s.router_t_max, block_epoch, no_block
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
            "nanogrid_detect_frac": round(s.nanogrid_detect, 3) if not np.isnan(s.nanogrid_detect) else None,
            "n_nanogrid_ips": s.n_nanogrid_ips or None,
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
    p.add_argument("--mtd-prefix", default="mtd", metavar="PREFIX",
                   help="Coordinator dir prefix under test: mtd (fixed timer), "
                        "mtdrl, or mtdrl-<tag> (default: mtd). Selects which "
                        "experiment dir the 3-scenario comparison reads.")
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

    # Detection now reads the held-out eval predictions (not the slow live re-score),
    # so it runs regardless of --no-detection.
    plot_detection(scenarios, os.path.join(plots_dir, "detection.pdf"))
    plot_availability(scenarios, os.path.join(plots_dir, "availability.pdf"))
    plot_topk_flows(scenarios, os.path.join(plots_dir, "topk_flows.pdf"), k=topk)
    plot_entropy_section(scenarios, plots_dir)


def discover_configs(root: str) -> list:
    """Find every experiment dir under root and build its (scenarios, plots_dir).

    Baseline dirs (baseline-mbps<M>/) get the standalone baseline figure set; MTD
    dirs (mtd-<slug>/) get the 3-scenario comparison. The replay rate and MTD slug
    are recovered from the directory name; mbps<M> may sit mid-slug (the slug now
    carries trailing -freqint<I>-freqs<N>), so the rate match allows a suffix.
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
        # mtd-<slug>, mtdrl-<slug> or mtdrl-<tag>-<slug>; the param slug always
        # starts with hop<N>, which anchors the prefix/slug split.
        m = re.fullmatch(r"(mtd(?:rl(?:-[a-z0-9]+)?)?)-(hop\d+-.*-mbps(\d+).*)", name)
        if m:
            prefix, slug, mbps = m.group(1), m.group(2), int(m.group(3))
            configs.append((default_scenarios(root, slug, mbps, prefix), path))
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
        default_dir = os.path.join(
            args.output_root, f"{args.mtd_prefix}-{args.mtd_params_slug}")
        scenarios = default_scenarios(
            args.output_root, args.mtd_params_slug, args.bg_replay_mbps,
            args.mtd_prefix,
        )
    plots_dir = args.plots_dir or default_dir
    generate_figures(scenarios, plots_dir, args.scmc_ip,
                     not args.no_detection, args.topk)


if __name__ == "__main__":
    main()
