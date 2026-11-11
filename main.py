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

The evaluation is a campaign on the platform's campaign runner
(network_scenario/scenarios/mqtt_mtd/campaign.py): each configuration is a unit
of the same `make` steps run_single.sh uses, at MBPS=2 by default — the config
the paper's numbers were generated at. Its ledger and summary (per-config
metrics, mean [95% CI] across runs) are under output/campaigns/paper-mbps<M>/;
`make dashboard` follows it live.

Repeated runs: `--runs N` repeats the whole evaluation N times, run i under
output/run-<i>/ with make SEED=<seed-base + i> (each lab run derives its own
per-role seed from it). The RL policies are trained once (output/rl*/) and
shared by every run. Without --runs/--seed the layout and commands are the
single-run ones (output/<exp>/).

Lab steps (dataset generation, attack) are retried up to --retries times: a run
whose SCMC never published exits non-zero and deletes its capture. A failed
configuration does not stop the others; the ones that need it (every MTD
config needs its run's baseline model; the figures need all four) are skipped.

Usage:
    .venv/bin/python main.py                  # run everything (paper config)
    .venv/bin/python main.py --mbps 5         # same, at a different replay rate
    .venv/bin/python main.py --runs 10        # 10 seeded runs -> output/run-0..9/
    .venv/bin/python main.py --dry-run        # print every command, run nothing
"""

import argparse
import sys

from network_scenario.scenarios.mqtt_mtd.campaign import (
    FIGURES, build_campaign, compare_dir, say,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mbps", type=int, default=2, metavar="MBPS",
                   help="Background trace replay rate in Mbit/s (default: 2, "
                        "the rate the paper's reported numbers were generated at).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print every command that would run, without running it.")
    p.add_argument("--runs", type=int, default=1, metavar="N",
                   help="Repeat the evaluation N times, run i under output/run-<i>/ "
                        "with SEED=<seed-base>+i (default: 1, the single-run layout).")
    p.add_argument("--seed-base", type=int, default=None, metavar="S",
                   help="Seed of run 0 (default: 0 with --runs > 1; with a single run, "
                        "setting it seeds that run under output/run-0/).")
    p.add_argument("--first-run", type=int, default=0, metavar="I",
                   help="Index of the first run, to extend an existing set of runs "
                        "(default: 0). Run i always gets SEED=<seed-base>+i.")
    p.add_argument("--retries", type=int, default=2, metavar="K",
                   help="Retries for a failed lab step (dataset generation, attack); "
                        "default: 2.")
    p.add_argument("--resume", action="store_true",
                   help="Skip attacks that already have metrics.json (default: rerun them).")
    p.add_argument("--name", default=None,
                   help="campaign name (default paper-mbps<M>): ledger + summary under "
                        "output/campaigns/<name>/")
    args = p.parse_args()
    if args.runs < 1:
        p.error("--runs must be >= 1")
    return args


def main() -> None:
    args = parse_args()
    campaign, contexts = build_campaign(
        mbps=args.mbps, runs=args.runs, seed_base=args.seed_base, first_run=args.first_run,
        retries=args.retries, name=args.name, resume=args.resume,
        out=lambda line: print(line, flush=True))
    if args.dry_run:
        campaign.dry_run()
        print(say("=== Done (dry run) ==="))
        return
    from network_scenario.core import lifecycle
    try:
        lifecycle.preflight()          # every unit needs a lab: fail fast, not 3 retries each
    except lifecycle.LabUnavailable as e:
        print(say(f"cannot start: {e}"), flush=True)
        sys.exit(lifecycle.EXIT_NO_LAB)
    res = campaign.run()
    for ctx in contexts:
        for label, pdf in FIGURES:
            print(say(f"  {label} -> {compare_dir(args.mbps, ctx)}/{pdf}"))
    print(say(f"=== {res['status']} (ok={res['ok']} failed={res['failed']} "
              f"skipped={res['skipped']}) — summary: {campaign.root}/summary.md ==="))
    if res["failed_units"]:
        print(say(f"failed or blocked: {', '.join(res['failed_units'])}"))
    sys.exit(0 if res["status"] == "done" else 1)


if __name__ == "__main__":
    main()
