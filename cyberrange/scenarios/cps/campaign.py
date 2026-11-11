"""cps_campaign.py — a campaign of cyber-physical runs on the core campaign
runner (cyberrange/core/campaign.py): a grid of attack modes x seeds
(plus attack-free "normal" runs), one Kathará lab at a time, scoring each run
as it finishes and keeping the aggregate up to date.

Everything goes onto one progress ledger at <out-root>/<name>/progress.jsonl,
which the dashboard follows live. The grid is seed-major (every mode of seed 1,
then seed 2, …) so a partial campaign already covers every mode. Re-running the
same --name resumes: runs whose metrics.json exists are skipped. A failed run
is retried --retries times, then recorded as failed and the campaign moves on.

Every option of the CPS scenario (python -m cyberrange.scenarios.cps.cli
--help) is accepted and applies to every run, e.g. --respond solver,
--it-telemetry. Grid modes are "normal", the scripted attack modes and
"planner:<profile>" (tree-guided attacker), so one campaign can compare them:
--modes normal,manual-hijack,planner:stealthy,planner:opportunistic. With
--attack-driver planner the scripted modes become one planner:<--attacker-profile>.

Layout:
    <out-root>/<name>/campaign.json        grid + parameters
                      progress.jsonl       the ledger
                      runs/<mode>-s<seed>/ one run's artifacts + metrics.{json,md}
                      summary.{md,csv}, impact.csv   aggregate (refreshed per run)

Run:
    python -m cyberrange.scenarios.cps.campaign --name smoke --seeds 1 \
        --modes normal,manual-hijack [--respond rules] [--dry-run]
"""

import argparse
import logging
import os
import sys
import time

from cyberrange.scenarios.cps.metrics import compute_metrics, format_report, write_aggregate
from cyberrange.core.campaign import Campaign, Step, Unit
from cyberrange.core.cli import build_parser, default_args

log = logging.getLogger("cps_campaign")

DEFAULT_MODES = ("normal", "setpoint-overvoltage", "breaker-open", "manual-hijack")
ATTACK_MODES = ("setpoint-overvoltage", "breaker-open", "manual-hijack")
# Set per run by the campaign, so not taken from the command line.
PER_RUN = ("out_dir", "run_id", "seed", "attack", "attack_mode", "progress_file")


def parse_seeds(spec):
    """ "1-3,7" -> [1, 2, 3, 7] (order kept, duplicates dropped)."""
    seeds = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if b < a:
                raise ValueError(f"bad seed range {part!r}")
            rng = range(a, b + 1)
        else:
            rng = [int(part)]
        for s in rng:
            if s not in seeds:
                seeds.append(s)
    if not seeds:
        raise ValueError("no seeds")
    return seeds


PROFILES = ("opportunistic", "targeted", "stealthy")


def parse_modes(spec):
    """Grid modes: "normal", a scripted attack mode, or "planner:<profile>"
    (the tree-guided attacker with that profile)."""
    modes = [m.strip() for m in str(spec).split(",") if m.strip()]
    ok = set(DEFAULT_MODES) | {f"planner:{p}" for p in PROFILES}
    bad = [m for m in modes if m not in ok]
    if bad or not modes:
        raise ValueError(
            f"unknown modes {bad}; choose from {', '.join(DEFAULT_MODES)} "
            f"or planner:<{'|'.join(PROFILES)}>"
        )
    return modes


def grid_modes(cfg):
    """The campaign's modes. With --attack-driver planner the scripted attack
    modes make no sense (the planner chooses its own impact): they are replaced
    by one planner entry with the campaign's --attacker-profile."""
    modes = parse_modes(cfg.modes)
    if getattr(cfg, "attack_driver", "scripted") != "planner":
        return modes
    out = []
    for m in modes:
        m = (
            m
            if m == "normal" or m.startswith("planner:")
            else f"planner:{getattr(cfg, 'attacker_profile', 'opportunistic')}"
        )
        if m not in out:
            out.append(m)
    return out


def build_grid(modes, seeds):
    """Seed-major list of runs: [{"run_id", "mode", "seed", "attack"}]."""
    return [
        {
            "run_id": f"{mode.replace(':', '-')}-s{seed}",
            "mode": mode,
            "seed": seed,
            "attack": mode != "normal",
        }
        for seed in seeds
        for mode in modes
    ]


def _scenario():
    from cyberrange.scenarios.cps.scenario import CpsScenario

    return CpsScenario()


def run_args(cfg, entry, out_dir):
    """The scenario's run namespace for one grid entry: every CPS option at its
    default, overridden by the campaign's value for that option (any scenario
    option the campaign was given), then by the entry (mode, seed, out dir)."""
    scenario = _scenario()
    base = default_args(scenario)
    overrides = {k: getattr(cfg, k) for k in vars(base) if hasattr(cfg, k) and k not in PER_RUN}
    mode = entry["mode"]
    overrides.update(
        out_dir=out_dir,
        run_id=entry["run_id"],
        seed=entry["seed"],
        attack=entry["attack"],
        progress_file=None,
        attack_mode=mode if mode in ATTACK_MODES else base.attack_mode,
    )
    if mode.startswith("planner:"):
        overrides.update(attack_driver="planner", attacker_profile=mode.split(":", 1)[1])
    elif entry["attack"]:
        overrides["attack_driver"] = "scripted"
    return default_args(scenario, **overrides)


def _default_run_fn(args, progress):
    from cyberrange.scenarios.cps import cli as cps_experiment  # Kathará import only when running

    cps_experiment.run(args, progress=progress)


def _validate(cfg):
    """Every grid entry's options, checked before anything runs."""
    scenario = _scenario()
    for e in build_grid(grid_modes(cfg), [None]):
        scenario.validate(run_args(cfg, e, ""))


def build_campaign(cfg, run_fn=None, metrics_fn=None, out=print):
    """The core Campaign of ``cfg``: one unit (one scored run) per grid entry."""
    run_fn = run_fn or _default_run_fn
    metrics_fn = metrics_fn or compute_metrics
    scenario = _scenario()
    root = os.path.join(cfg.out_root, cfg.name)
    units = []
    for e in build_grid(grid_modes(cfg), parse_seeds(cfg.seeds)):
        rdir = os.path.join(root, "runs", e["run_id"])
        args = run_args(cfg, e, rdir)
        units.append(
            Unit(
                e["run_id"],
                group=e["mode"],
                steps=[
                    Step(
                        e["run_id"],
                        run=lambda emit, a=args: run_fn(a, progress=emit),
                        retries=getattr(cfg, "retries", 1),
                        run_dir=rdir,
                        metrics=metrics_fn,
                        report=format_report,
                        planned_s=scenario.planned_s(args),
                        label={"run_id": e["run_id"], "mode": e["mode"], "seed": e["seed"]},
                        info={"attack": e["attack"]},
                    )
                ],
            )
        )
    common = run_args(cfg, {"run_id": "-", "mode": "normal", "seed": None, "attack": False}, "")
    params = {k: v for k, v in sorted(vars(common).items()) if k not in PER_RUN}
    params["retries"] = getattr(cfg, "retries", 1)
    return Campaign(
        cfg.name,
        root,
        units,
        params=params,
        resume=getattr(cfg, "resume", True),
        aggregate=write_aggregate,
        out=out,
        scenario=scenario.name,
    )


def run_campaign(cfg, run_fn=None, metrics_fn=None):
    """Run (or resume) the campaign described by ``cfg``. Returns a summary dict.
    ``run_fn(args, progress)`` / ``metrics_fn(out_dir)`` are injectable for tests."""
    _validate(cfg)
    if run_fn is None:  # real labs: fail fast if none can run
        from cyberrange.core import lifecycle

        lifecycle.preflight()
    return build_campaign(cfg, run_fn, metrics_fn).run()


def dry_run(cfg, out=print):
    _validate(cfg)
    c = build_campaign(cfg, out=out)
    out(f"campaign {cfg.name!r} -> {c.root}")
    total = 0.0
    for s in c.scored_steps():
        total += s.planned_s
        out(f"  {s.id:<28} attack={'yes' if s.info['attack'] else 'no ':<3} ~{s.planned_s:.0f}s")
    out(f"{len(c.scored_steps())} runs, ~{total / 60:.1f} min planned")
    return c.grid(), total


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Run a campaign of CPS experiments. Any option of the CPS scenario "
        "run (see `python -m cyberrange.scenarios.cps.cli --help`) is "
        "accepted and applies to every run."
    )
    ap.add_argument(
        "--name", default=time.strftime("%Y%m%d-%H%M%S"), help="campaign name; reuse it to resume"
    )
    ap.add_argument("--out-root", default="output/cps/campaigns")
    ap.add_argument("--modes", default=",".join(DEFAULT_MODES))
    ap.add_argument("--seeds", default="1-5", help='e.g. "1-5" or "1,3,7"')
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--no-resume", dest="resume", action="store_false")
    ap.add_argument("--dry-run", action="store_true")
    cfg, rest = ap.parse_known_args(argv)
    scenario_args = build_parser(_scenario()).parse_args(rest)
    for k, v in vars(scenario_args).items():
        if k not in PER_RUN:
            setattr(cfg, k, v)
    return cfg


def main(argv=None):
    cfg = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    if cfg.dry_run:
        dry_run(cfg)
        return
    from cyberrange.core import lifecycle

    try:
        res = run_campaign(cfg)
    except lifecycle.LabUnavailable as e:
        log.error("%s", e)
        sys.exit(lifecycle.EXIT_NO_LAB)
    log.info(
        "campaign %s: %s (ok=%d failed=%d skipped=%d) -> %s/summary.md",
        cfg.name,
        res["status"],
        res["ok"],
        res["failed"],
        res["skipped"],
        res["root"],
    )
    sys.exit(0 if res["status"] == "done" else 1)


if __name__ == "__main__":
    main()
