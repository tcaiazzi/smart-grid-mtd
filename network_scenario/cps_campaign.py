"""cps_campaign.py — runs a campaign of cyber-physical experiments: a grid of
attack modes x seeds (plus attack-free "normal" runs), one Kathará lab at a
time, scoring each run as it finishes and keeping an aggregate up to date.

Everything it does goes onto one progress ledger (monitor/progress.py) at
<out-root>/<name>/progress.jsonl, which the progress dashboard
(monitor/cps_dashboard.py) follows live:

    campaign_start → for each run: run_start, phase…, plant…, finding…,
    run_end, run_metrics, aggregate → campaign_end

The grid is ordered seed-major (every mode of seed 1, then seed 2, …) so a
partial campaign already covers every mode. Re-running the same --name resumes:
runs whose metrics.json exists are skipped (run_skipped). A failed run is
retried --retries times, then recorded as failed and the campaign moves on.

Layout:
    <out-root>/<name>/campaign.json        grid + parameters
                      progress.jsonl       the ledger
                      runs/<mode>-s<seed>/ one run's artifacts + metrics.{json,md}
                      summary.{md,csv}, impact.csv   aggregate (refreshed per run)

Run:
    python -m network_scenario.cps_campaign --name smoke --seeds 1 \
        --modes normal,manual-hijack [--dry-run]
"""

import argparse
import json
import logging
import os
import time
import types

from monitor.cps_metrics import compute_metrics, format_report, write_aggregate
from monitor.progress import ProgressLog

log = logging.getLogger("cps_campaign")

DEFAULT_MODES = ("normal", "setpoint-overvoltage", "breaker-open", "manual-hijack")
ATTACK_MODES = ("setpoint-overvoltage", "breaker-open", "manual-hijack")


def parse_seeds(spec):
    """"1-3,7" -> [1, 2, 3, 7] (order kept, duplicates dropped)."""
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


def parse_modes(spec):
    modes = [m.strip() for m in str(spec).split(",") if m.strip()]
    bad = [m for m in modes if m not in DEFAULT_MODES]
    if bad or not modes:
        raise ValueError(f"unknown modes {bad}; choose from {', '.join(DEFAULT_MODES)}")
    return modes


def build_grid(modes, seeds):
    """Seed-major list of runs: [{"run_id", "mode", "seed", "attack"}]."""
    return [{"run_id": f"{mode}-s{seed}", "mode": mode, "seed": seed,
             "attack": mode != "normal"}
            for seed in seeds for mode in modes]


def run_args(cfg, entry, out_dir):
    """The argparse-like namespace cps_experiment.run expects for one run."""
    return types.SimpleNamespace(
        out_dir=out_dir, run_id=entry["run_id"], seed=entry["seed"],
        step_interval=cfg.step_interval, normal_duration=cfg.normal_duration,
        learn_seconds=cfg.learn_seconds, detectors=cfg.detectors,
        attack=entry["attack"],
        attack_mode=entry["mode"] if entry["attack"] else "setpoint-overvoltage",
        attack_repeat=None, attack_interval=0.5,
        post_attack_duration=cfg.post_attack_duration,
        dashboard_port=cfg.dashboard_port, poll_interval=cfg.poll_interval,
        progress_file=None,
        # One response policy per campaign: compare policies across campaigns.
        respond=getattr(cfg, "respond", "off"),
        respond_interval=getattr(cfg, "respond_interval", 0.5),
        approval=getattr(cfg, "approval", "auto"),
        # Attack driver (scripted keeps the per-mode chain; planner is reactive).
        attack_driver=getattr(cfg, "attack_driver", "scripted"),
        attacker_profile=getattr(cfg, "attacker_profile", "opportunistic"),
        attack_goal=getattr(cfg, "attack_goal", None),
        dwell=getattr(cfg, "dwell", 0.0),
        max_steps=getattr(cfg, "max_steps", 12),
        it_telemetry=getattr(cfg, "it_telemetry", False))


def _default_run_fn(args, progress):
    from network_scenario import cps_experiment   # Kathará import only when running
    cps_experiment.run(args, progress=progress)


def _planned(cfg, entry):
    from network_scenario.cps_experiment import planned_run_s
    return planned_run_s(run_args(cfg, entry, ""))


def _validate(cfg):
    from network_scenario.cps_experiment import validate_args
    validate_args(types.SimpleNamespace(attack=True, normal_duration=cfg.normal_duration,
                                        learn_seconds=cfg.learn_seconds))


def run_campaign(cfg, run_fn=None, metrics_fn=None):
    """Run (or resume) the campaign described by `cfg`. Returns a summary dict.

    `run_fn(args, progress)` runs one experiment (default: cps_experiment.run);
    `metrics_fn(out_dir)` scores it (default: cps_metrics.compute_metrics).
    Both are injectable for tests."""
    run_fn = run_fn or _default_run_fn
    metrics_fn = metrics_fn or compute_metrics
    _validate(cfg)
    modes, seeds = parse_modes(cfg.modes), parse_seeds(cfg.seeds)
    grid = build_grid(modes, seeds)
    root = os.path.join(cfg.out_root, cfg.name)
    os.makedirs(os.path.join(root, "runs"), exist_ok=True)
    params = {k: getattr(cfg, k) for k in ("normal_duration", "learn_seconds",
                                           "post_attack_duration", "step_interval",
                                           "detectors", "poll_interval", "retries")}
    with open(os.path.join(root, "campaign.json"), "w") as f:
        json.dump({"name": cfg.name, "modes": modes, "seeds": seeds, "grid": grid,
                   "params": params}, f, indent=2)

    ledger = ProgressLog(os.path.join(root, "progress.jsonl"))
    planned = {e["run_id"]: _planned(cfg, e) for e in grid}
    ledger.emit("campaign_start", name=cfg.name, grid=grid, params=params,
                planned_run_s=planned, planned_total_s=round(sum(planned.values()), 1))
    rows, ok, failed, skipped = [], 0, 0, 0
    status = "interrupted"
    try:
        for entry in grid:
            rid = entry["run_id"]
            rdir = os.path.join(root, "runs", rid)
            mpath = os.path.join(rdir, "metrics.json")
            if cfg.resume and os.path.exists(mpath):
                try:
                    with open(mpath) as f:
                        m = json.load(f)
                    rows.append({"mode": entry["mode"], "seed": entry["seed"], "metrics": m})
                    skipped += 1
                    ledger.emit("run_skipped", run_id=rid, mode=entry["mode"],
                                seed=entry["seed"], metrics=m)
                    continue
                except (OSError, json.JSONDecodeError):
                    pass   # unreadable -> run it again

            done = False
            for attempt in range(1, cfg.retries + 2):
                bound = ledger.bind(run_id=rid, attempt=attempt)
                try:
                    run_fn(run_args(cfg, entry, rdir), progress=bound)
                    done = True
                    break
                except KeyboardInterrupt:
                    raise
                except Exception as e:   # noqa: BLE001 — record and move on
                    log.warning("run %s attempt %d failed: %s", rid, attempt, e)
                    if attempt <= cfg.retries:
                        ledger.emit("run_retry", run_id=rid, attempt=attempt, error=str(e)[:300])
            if not done:
                failed += 1
                ledger.emit("run_failed", run_id=rid, mode=entry["mode"], seed=entry["seed"])
                continue

            m = metrics_fn(rdir)
            m["run"] = {"run_id": rid, "mode": entry["mode"], "seed": entry["seed"]}
            with open(mpath, "w") as f:
                json.dump(m, f, indent=2)
            with open(os.path.join(rdir, "metrics.md"), "w") as f:
                f.write(format_report(m))
            rows.append({"mode": entry["mode"], "seed": entry["seed"], "metrics": m})
            ok += 1
            ledger.emit("run_metrics", run_id=rid, mode=entry["mode"], seed=entry["seed"],
                        metrics=m)
            ledger.emit("aggregate", **write_aggregate(root, rows))
        status = "done" if not failed else "done_with_failures"
    finally:
        if rows and skipped and not ok:
            ledger.emit("aggregate", **write_aggregate(root, rows))
        ledger.emit("campaign_end", status=status, ok=ok, failed=failed, skipped=skipped)
        ledger.close()
    return {"root": root, "status": status, "ok": ok, "failed": failed, "skipped": skipped}


def dry_run(cfg, out=print):
    modes, seeds = parse_modes(cfg.modes), parse_seeds(cfg.seeds)
    grid = build_grid(modes, seeds)
    total = 0.0
    out(f"campaign {cfg.name!r} -> {os.path.join(cfg.out_root, cfg.name)}")
    for e in grid:
        p = _planned(cfg, e)
        total += p
        out(f"  {e['run_id']:<28} attack={'yes' if e['attack'] else 'no ':<3} ~{p:.0f}s")
    out(f"{len(grid)} runs, ~{total / 60:.1f} min planned")
    return grid, total


def main():
    ap = argparse.ArgumentParser(description="Run a campaign of CPS experiments")
    ap.add_argument("--name", default=time.strftime("%Y%m%d-%H%M%S"),
                    help="campaign name; reuse it to resume")
    ap.add_argument("--out-root", default="output/cps/campaigns")
    ap.add_argument("--modes", default=",".join(DEFAULT_MODES))
    ap.add_argument("--seeds", default="1-5", help='e.g. "1-5" or "1,3,7"')
    ap.add_argument("--normal-duration", type=float, default=60.0)
    ap.add_argument("--learn-seconds", type=float, default=45.0)
    ap.add_argument("--post-attack-duration", type=float, default=30.0)
    ap.add_argument("--step-interval", type=float, default=1.0)
    ap.add_argument("--detectors", default="rules,model")
    ap.add_argument("--poll-interval", type=float, default=2.0)
    ap.add_argument("--dashboard-port", type=int, default=0)
    ap.add_argument("--respond", default="off", choices=("off", "rules", "solver"),
                    help="response policy for every run of the campaign (SOAR prototype)")
    ap.add_argument("--it-telemetry", dest="it_telemetry", action="store_true",
                    help="run the IT-side sensor on the HMI for every run")
    ap.add_argument("--attack-driver", default="scripted", choices=("scripted", "planner"))
    ap.add_argument("--attacker-profile", default="opportunistic",
                    choices=("opportunistic", "targeted", "stealthy"))
    ap.add_argument("--dwell", type=float, default=0.0)
    ap.add_argument("--respond-interval", type=float, default=0.5)
    ap.add_argument("--approval", default="auto", help="auto | deny | delay:<seconds>")
    ap.add_argument("--retries", type=int, default=1)
    ap.add_argument("--no-resume", dest="resume", action="store_false")
    ap.add_argument("--dry-run", action="store_true")
    cfg = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    if cfg.dry_run:
        dry_run(cfg)
        return
    res = run_campaign(cfg)
    log.info("campaign %s: %s (ok=%d failed=%d skipped=%d) -> %s/summary.md",
             cfg.name, res["status"], res["ok"], res["failed"], res["skipped"], res["root"])


if __name__ == "__main__":
    main()
