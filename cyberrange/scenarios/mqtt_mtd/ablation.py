"""ablation.py — the MTD parameter ablation as a campaign.

Where the paper campaign (campaign.py, `main.py`) compares four fixed
configurations, this walks a grid: which mechanism carries the hiding, how often
it has to move, and how much background noise it needs to hide in. Five groups,
fifteen configurations:

    E0  the defaults, the reference point every other group is read against
    E1  one mechanism at a time — the other pools collapsed to a single value,
        so "port hopping alone" means exactly that
    E2  how often the address hops (1, 5, 10, 30 s), broker and source together
    E3  how much background traffic there is to hide in (1, 5, 10 Mbit/s)
    E4  how often the publish frequency mutates (1, 5, 10 s)

Each configuration is a unit of the core campaign runner, so an ablation that
dies on the eleventh configuration resumes at the eleventh: runs already scored
are skipped, failed lab steps are retried, and `make dashboard` follows the
whole grid on one ledger.

Both attacks run per configuration. The scored one is the cross-model attack
(the baseline-trained model against MTD traffic); the own-model attack feeds the
second series of the figures (analysis/plot_sweep.py draws "MTD (MTD model)"
against "MTD (baseline model)").

Output:
    output/campaigns/<name>/        ledger, campaign.json, summary.md, ci.csv
    output/<slug>/                  one directory per configuration
    output/sweep_manifest.csv       one row per configuration: the grid axes
    output/sweep/e1..e4_*.pdf       the figures, written by the final step

Run:
    python -m cyberrange.scenarios.mqtt_mtd.ablation --dry-run
    python -m cyberrange.scenarios.mqtt_mtd.ablation --groups e1,e2
"""

import argparse
import os
import sys
from dataclasses import replace

from cyberrange.core.campaign import Campaign, Step, run_cli
from cyberrange.scenarios.mqtt_mtd.campaign import (
    DEFAULT_ROOT,
    PYTHON,
    MtdParams,
    RunCtx,
    append_manifest,
    baseline_unit,
    config_unit,
    say,
    slug,
)

# The ablation's reference point is the Makefile's own defaults, not the paper's
# tuned configuration: every group is read as a departure from "what the lab
# does out of the box".
DEFAULTS = MtdParams(
    hop=2,
    ip_pool="10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6",
    port_pool="8883,8884,8885,8886,8887",
    scmc_pool="10.0.0.2,10.0.0.4,10.0.0.5,10.0.0.6",
    pad_buckets="128,256,384,512,640,768,1024",
    pad_interval=3,
    freq_interval=30,
    freq_pool="0.1,0.2,0.4,0.6,0.8,1",
    mbps=2,
)

# A pool of one is a mechanism switched off: there is nowhere else to move to.
ONE_IP, ONE_PORT, ONE_SRC = "10.1.0.2", "8883", "10.0.0.2"


def groups():
    """{group: [(experiment, params)]} — the grid, as data."""
    off = dict(ip_pool=ONE_IP, port_pool=ONE_PORT, scmc_pool=ONE_SRC)
    return {
        "e0": [("E0-default", DEFAULTS)],
        "e1": [
            ("E1-no-hop", replace(DEFAULTS, **off)),
            ("E1-port-only", replace(DEFAULTS, ip_pool=ONE_IP, scmc_pool=ONE_SRC)),
            ("E1-ip-only", replace(DEFAULTS, port_pool=ONE_PORT, scmc_pool=ONE_SRC)),
            ("E1-src-only", replace(DEFAULTS, ip_pool=ONE_IP, port_pool=ONE_PORT)),
        ],
        "e2": [(f"E2-hop{h}", replace(DEFAULTS, hop=h)) for h in (1, 5, 10, 30)],
        "e3": [(f"E3-mbps{m}", replace(DEFAULTS, mbps=m)) for m in (1, 5, 10)],
        "e4": [(f"E4-freq{f}", replace(DEFAULTS, freq_interval=f)) for f in (1, 5, 10)],
    }


def build_campaign(selected, name=None, retries=0, resume=True, root=DEFAULT_ROOT, out=print):
    """The campaign for ``selected`` groups, plus the baselines they need."""
    grid = groups()
    unknown = [g for g in selected if g not in grid]
    if unknown:
        raise SystemExit(f"unknown group(s) {unknown}; known: {sorted(grid)}")

    configs = [(exp, p) for g in selected for exp, p in grid[g]]
    units, seen_baseline = [], set()
    for block, (experiment, params) in enumerate(configs, start=1):
        # Every noise level needs its own no-MTD reference, and E3 is the only
        # group that changes it — hence one baseline per distinct rate.
        if params.mbps not in seen_baseline:
            seen_baseline.add(params.mbps)
            units.append(baseline_unit(params.mbps, RunCtx(), retries))
        units.append(
            config_unit(
                experiment,
                f"{experiment} (hop {params.hop}s, {params.mbps} Mbit/s)",
                block,
                params.mbps,
                retries=retries,
                params=params,
                own_model_attack=True,
            )
        )

    name = name or "ablation"
    campaign = Campaign(
        name,
        os.path.join(root, "campaigns", name),
        units,
        params={"groups": list(selected), **{"defaults": DEFAULTS.hop}},
        resume=resume,
        out=out,
    )
    return campaign, configs


def write_manifest(configs, root=DEFAULT_ROOT):
    """One manifest row per configuration — the axes plot_sweep draws against."""
    for experiment, params in configs:
        exp = slug(no_mtd=False, mbps=params.mbps, params=params)
        append_manifest(experiment, params.mbps, exp, root=root, params=params)


def figures_step(root=DEFAULT_ROOT):
    return Step(
        "figures",
        cmd=[
            PYTHON,
            "-m",
            "cyberrange.scenarios.mqtt_mtd.analysis.plot_sweep",
            "--manifest",
            os.path.join(root, "sweep_manifest.csv"),
            "--plots-root",
            root,
        ],
    )


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument(
        "--groups",
        default="e0,e1,e2,e3,e4",
        help="comma-separated groups to run (default: all five)",
    )
    p.add_argument("--name", default=None, help="campaign name (default: ablation)")
    p.add_argument("--retries", type=int, default=1, help="retries for a failed lab step")
    p.add_argument(
        "--no-resume",
        action="store_true",
        help="rerun configurations that already have metrics (default: skip them)",
    )
    p.add_argument("--dry-run", action="store_true", help="print the commands, run nothing")
    p.add_argument("--output-root", default=DEFAULT_ROOT)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    selected = [g.strip().lower() for g in args.groups.split(",") if g.strip()]
    campaign, configs = build_campaign(
        selected,
        name=args.name,
        retries=args.retries,
        resume=not args.no_resume,
        root=args.output_root,
        out=lambda line: print(line, flush=True),
    )
    if args.dry_run:
        campaign.dry_run()
        print(say(f"=== Done (dry run): {len(configs)} configurations ==="))
        return
    # The manifest is written whatever the outcome: plot_sweep draws the
    # configurations that did finish.
    sys.exit(
        run_cli(
            campaign,
            out=lambda line: print(say(line), flush=True),
            epilogue=lambda res: write_manifest(configs, root=args.output_root) or [],
        )
    )


if __name__ == "__main__":
    main()
