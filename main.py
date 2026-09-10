#!/usr/bin/env python3
"""main.py — single-command reproduction of the paper's evaluation.

Runs the four configurations compared in the paper (§VI-G, Fig. 2/3):
baseline (no MTD), fixed-timer MTD, RL-cost, RL-entropy — training both RL
policies offline first if their .npz files are missing — and finishes with
the compare_coordinators.py step that renders the paper figures:

    Fig. 2a  availability over time        -> availability_comparison.pdf
    Fig. 2b  attacker confidence per config -> detection_comparison.pdf
    Fig. 2c  cumulative availability cost   -> availability_cost_comparison.pdf
    Fig. 3   per-field Shannon entropy      -> entropy_comparison.pdf

This is a Python transliteration of run_experiments.sh + run_single.sh (the
paper's own driver scripts), at MBPS=2 by default — the config the paper's
numbers were actually generated at (see the parameter table in the refactor
plan; run_experiments.sh's own MBPS=100 was an abandoned experiment, not the
one reported). Override with --mbps.

It shells out to `make` rather than reimplementing the pipeline: the Makefile
encodes non-trivial state (order-only prerequisites, "skip if already built"
reuse, the cross-model attack guard) that would otherwise be duplicated and
risk drifting from it. This script only sequences the same `make` invocations
run_single.sh does, plus the same reuse guard and sweep-manifest bookkeeping,
so the two stay in lockstep by construction — see tests/test_slug_consistency.py
and the "V5" dry-run comparison in the refactor plan for how that's checked.

Usage:
    .venv/bin/python main.py                  # run everything (paper config)
    .venv/bin/python main.py --mbps 5         # same, at a different replay rate
    .venv/bin/python main.py --dry-run        # print every command, run nothing
"""

import argparse
import csv
import os
import subprocess
import sys
from pathlib import Path

from network_scenario.slug import experiment_slug

REPO_ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable
MANIFEST = "output/sweep_manifest.csv"

# The paper's parameter configuration (run_experiments.sh's four env blocks),
# independent of the background replay rate (--mbps).
HOP = 4
IP_POOL = "10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6,10.1.0.7,10.1.0.8"
PORT_POOL = "8883,8884,8885,8886,8887,8888,8889"
SCMC_POOL = "10.0.0.2,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8"
PAD_BUCKETS = "128,256,384,512,640,768,1024"
PAD_INTERVAL = 3
FREQ_INTERVAL = 5
FREQ_POOL = "0.1,0.2,0.4,0.6,0.8,1"


def log(msg: str) -> None:
    print(f"[main] {msg}", flush=True)


def run(cmd: list, dry_run: bool) -> None:
    """Run one command, or print it (run_single.sh's `run()`)."""
    if dry_run:
        print("  DRY: " + " ".join(cmd))
        return
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)


def _slug(no_mtd: bool, mbps: int, hop: int = HOP, pad_interval: int = PAD_INTERVAL,
          ip_pool: str = IP_POOL, port_pool: str = PORT_POOL, scmc_pool: str = SCMC_POOL,
          pad_buckets: str = PAD_BUCKETS, freq_interval: int = FREQ_INTERVAL,
          freq_pool: str = FREQ_POOL, rl_policy: str = None, rl_tag: str = "") -> str:
    args = argparse.Namespace(
        no_mtd=no_mtd, bg_replay_mbps=mbps, mtd_hop_interval=hop,
        mtd_pad_interval=pad_interval, mtd_ip_pool=ip_pool, mtd_port_pool=port_pool,
        mtd_scmc_ip_pool=scmc_pool, mtd_pad_buckets=pad_buckets,
        mtd_freq_interval=freq_interval, mtd_freq_pool=freq_pool,
        rl_policy=rl_policy, rl_tag=rl_tag,
    )
    return experiment_slug(args)


def run_baseline(mbps: int, dry_run: bool) -> None:
    """Mirrors run_single.sh's run_baseline() (NO_MTD=1)."""
    log(f"baseline (no MTD, mbps={mbps})")
    base_vars = ["NO_MTD=1", f"BG_REPLAY_MBPS={mbps}"]
    run(["make", "datasets", *base_vars], dry_run)
    run(["make", "train", *base_vars], dry_run)
    run(["make", "evaluate", *base_vars], dry_run)
    run(["make", "attack", *base_vars], dry_run)
    run([
        PYTHON, "plot_results.py", "--baseline-only",
        "--bg-replay-mbps", str(mbps),
        "--plots-dir", f"output/baseline-mbps{mbps}",
    ], dry_run)


def run_config(experiment: str, mbps: int, rl_policy: str = None, rl_tag: str = "",
                rl_tick: float = 1.0, dry_run: bool = False) -> None:
    """Mirrors run_single.sh's run_config() for one MTD configuration (the
    paper's fixed HOP/pools; only mbps and the RL policy selection vary)."""
    prefix = "mtd"
    if rl_policy:
        prefix = f"mtdrl-{rl_tag}" if rl_tag else "mtdrl"
    # experiment_slug() returns the FULL directory name (prefix included) — the
    # same string run_experiment.py derives its own --datasets-dir/--results-dir
    # defaults from, so `exp` is guaranteed to match what `make` actually builds
    # on disk. plot_results.py instead wants the prefix and the hop/pool suffix
    # as two separate flags (--mtd-prefix / --mtd-params-slug, Makefile:105-129),
    # so strip the "<prefix>-" we just added back off to get the bare suffix.
    exp = _slug(no_mtd=False, mbps=mbps, rl_policy=rl_policy, rl_tag=rl_tag)
    slug = exp[len(prefix) + 1:]
    log(f"[{experiment}] {exp}")

    args = [
        f"MTD_HOP_INTERVAL={HOP}",
        f"MTD_IP_POOL={IP_POOL}",
        f"MTD_PORT_POOL={PORT_POOL}",
        f"MTD_SCMC_IP_POOL={SCMC_POOL}",
        f"MTD_SRC_HOP_INTERVAL={HOP}",
        f"MTD_PAD_BUCKETS={PAD_BUCKETS}",
        f"MTD_PAD_INTERVAL={PAD_INTERVAL}",
        f"BG_REPLAY_MBPS={mbps}",
        f"MTD_FREQ_INTERVAL={FREQ_INTERVAL}",
        f"MTD_FREQ_POOL={FREQ_POOL}",
    ]
    if rl_policy:
        args += ["RL=1", f"RL_POLICY={rl_policy}", f"RL_TICK={rl_tick}"]
        if rl_tag:
            args.append(f"RL_TAG={rl_tag}")
        # PPO training is lazy and stays here, not hoisted earlier: it reads
        # output/*/summary.csv to calibrate its reward (mtd_env.load_calibration),
        # and those summaries are written by the plot_results calls in the
        # preceding blocks — training earlier would calibrate against less data.
        train_target = "train-rl-entropy" if rl_tag == "entropy" else "train-rl"
        if not (REPO_ROOT / rl_policy).is_file():
            log(f"  RL policy {rl_policy} missing — training it first (make {train_target})")
            run(["make", train_target], dry_run)

    train_pcap = REPO_ROOT / f"output/{exp}/datasets/train.pcap"
    test_pcap = REPO_ROOT / f"output/{exp}/datasets/test.pcap"
    model_pt = REPO_ROOT / f"output/{exp}/model/model.pt"
    if train_pcap.is_file() and test_pcap.is_file() and model_pt.is_file():
        log("  datasets + model present — running attack only")
    else:
        log("  datasets/model missing — full rebuild")
        run(["rm", "-rf", f"output/{exp}"], dry_run)
        run(["make", "datasets", *args], dry_run)
        run(["make", "train", *args], dry_run)
        run(["make", "evaluate", *args], dry_run)
        run(["make", "evaluate", "MODEL_SRC=baseline", *args], dry_run)

    # Cross-model attack only (the own-model attack is intentionally skipped —
    # run_single.sh:163 leaves it commented out; the paper's Fig. 2 attack runs
    # the baseline-trained model against the MTD-morphed traffic).
    run(["make", "attack", "MODEL_SRC=baseline", *args], dry_run)
    run(["make", "entropy", *args], dry_run)
    run([
        PYTHON, "plot_results.py",
        "--mtd-params-slug", slug,
        "--mtd-prefix", prefix,
        "--bg-replay-mbps", str(mbps),
        "--plots-dir", f"output/{exp}",
    ], dry_run)

    if dry_run:
        return
    _append_manifest(experiment, mbps, exp)


def _append_manifest(experiment: str, mbps: int, exp: str) -> None:
    manifest_path = REPO_ROOT / MANIFEST
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    header = ["experiment", "hop", "n_ips", "n_ports", "n_pads", "n_src",
              "pad_interval", "bg_mbps", "freq_interval", "n_freqs", "slug"]
    if manifest_path.exists() and exp in manifest_path.read_text():
        return
    write_header = not manifest_path.exists()
    with manifest_path.open("a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(header)
        writer.writerow([
            experiment, HOP, len(IP_POOL.split(",")), len(PORT_POOL.split(",")),
            len(PAD_BUCKETS.split(",")), len(SCMC_POOL.split(",")), PAD_INTERVAL,
            mbps, FREQ_INTERVAL, len(FREQ_POOL.split(",")), exp,
        ])


def run_compare(mbps: int, dry_run: bool) -> list:
    """The paper-figure step run_single.sh never calls: compare_coordinators.py
    across the three MTD configs + baseline, tagged with the entropy RL policy
    so its bar appears alongside the fixed-timer and RL-cost ones."""
    # --slug wants the bare hop/pool suffix, same as plot_results.py's
    # --mtd-params-slug (Makefile:389 MTD_PARAMS_SLUG, no mtd-/mtdrl- prefix) —
    # strip the "mtd-" experiment_slug() adds for the fixed-timer config.
    full = _slug(no_mtd=False, mbps=mbps)
    slug = full[len("mtd-"):]
    out_dir = f"output/compare-{slug}"
    run([
        PYTHON, "compare_coordinators.py",
        "--slug", slug,
        "--bg-replay-mbps", str(mbps),
        "--output-root", "output",
        "--out-dir", out_dir,
        "--rl-tags", "entropy",
    ], dry_run)
    figures = [
        ("Fig. 2a — availability over time", f"{out_dir}/availability_comparison.pdf"),
        ("Fig. 2b — attacker confidence per config", f"{out_dir}/detection_comparison.pdf"),
        ("Fig. 2c — cumulative availability cost", f"{out_dir}/availability_cost_comparison.pdf"),
        ("Fig. 3 — per-field Shannon entropy", f"{out_dir}/entropy_comparison.pdf"),
    ]
    return figures


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mbps", type=int, default=2, metavar="MBPS",
                   help="Background trace replay rate in Mbit/s (default: 2, "
                        "the rate the paper's reported numbers were generated at).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print every command that would run, without running it.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    mbps = args.mbps
    dry_run = args.dry_run

    log("=== Block 1/5: baseline (no MTD) ===")
    run_baseline(mbps, dry_run)

    log("=== Block 2/5: fixed-timer MTD ===")
    run_config("fixed-timer", mbps, dry_run=dry_run)

    log("=== Block 3/5: RL-cost (blend reward) ===")
    run_config("rl-cost", mbps, rl_policy="output/rl/policy.npz", dry_run=dry_run)

    log("=== Block 4/5: RL-entropy (diffusion-only reward) ===")
    run_config("rl-entropy", mbps, rl_policy="output/rl-entropy/policy.npz",
               rl_tag="entropy", dry_run=dry_run)

    log("=== Block 5/5: paper figures (compare_coordinators) ===")
    figures = run_compare(mbps, dry_run)

    log("=== Done ===")
    if not dry_run:
        for label, path in figures:
            log(f"  {label} -> {path}")


if __name__ == "__main__":
    main()
