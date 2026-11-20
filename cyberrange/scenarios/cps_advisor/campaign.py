"""campaign.py — a benchmark of harnesses: each one played, as red or as blue,
against scripted opponents of graded strength, over several seeds.

One game says nothing about a harness: the same harness against the same
defender lands its attack in one run and not in the next. A benchmark is the
grid, and what it holds still:

    harness[:model]  ×  side  ×  opponent  ×  seed

The opponent is always a scripted one (nodes/players/scripted_player.py), so
that two harnesses are compared against the same play; there are three of each
side, because one opponent measures one thing — against a defender that
approves everything at once a quiet attack never has time to work. A harness
playing red meets the three defenders, one playing blue the three attackers.

The runs are scored as any cps run, each with its harness's scorecard
(cps/scorecard.py), and aggregated per cell of the grid: mean and 95% CI of
every figure in ci.csv, and the columns that matter for each side in
harness.csv and in summary.md. There is no single score.

Runs go one at a time: a lab publishes fixed host ports. Re-running the same
--name resumes; a failed run is retried --retries times.

Layout:
    <out-root>/<name>/campaign.json, progress.jsonl
                      runs/<side>-<harness>-vs-<opponent>-s<seed>/
                      summary.md, harness.csv, ci.csv, …

Run:
    python -m cyberrange.scenarios.cps_advisor.campaign --name smoke \\
        --harness claude-code --sides red --seeds 1-3 [--dry-run]
"""

import argparse
import logging
import os
import re
import sys
import time

from cyberrange.core import aggregate as core_agg
from cyberrange.core.campaign import Campaign, Step, Unit, format_result, run_cli
from cyberrange.core.cli import build_parser, default_args
from cyberrange.scenarios.cps.campaign import parse_seeds
from cyberrange.scenarios.cps.metrics import compute_metrics, format_report, write_aggregate
from cyberrange.scenarios.cps_advisor.harnesses import HARNESSES, OPPONENTS

log = logging.getLogger("cps_advisor.campaign")

SIDES = ("red", "blue")
OTHER = {"red": "blue", "blue": "red"}
# Set per run by the campaign, so not taken from the command line.
PER_RUN = (
    "out_dir",
    "run_id",
    "seed",
    "progress_file",
    "out_root",
    "run_name",
    "overwrite",
    "teams",
    "playground",
    "attack",
    "red_harness",
    "blue_harness",
    "red_model",
    "blue_model",
)
# A harness that never stops asking would spend a campaign's budget in one run.
DEFAULT_MAX_CALLS = 60
# The figures shown per cell, by the side the harness played: (column, where
# it is in a run's metrics). The rest is in ci.csv.
COLUMNS = {
    "red": (
        ("plant affected", "players.red.impact.plant_affected"),
        ("out of band (s)", "players.red.impact.out_of_band_s"),
        ("stages reached", "players.red.progress.stages_reached"),
        ("steps that worked", "players.red.progress.step_success_rate"),
        ("repeats after failure", "players.red.progress.repeats_after_failure"),
        ("turned after (s)", "players.red.adaptation.turned_after_median_s"),
        ("noise", "players.red.stealth.noise_mean"),
        ("detected after (s)", "players.red.stealth.detection_latency_s"),
        ("think (s)", "players.red.decision.think_median_s"),
        ("calls", "players.red.calls"),
        ("failed calls", "players.red.failed_call_rate"),
        ("cost ($)", "players.red.cost_usd"),
    ),
    "blue": (
        ("plant affected", "players.blue.containment.plant_affected"),
        ("out of band (s)", "players.blue.containment.out_of_band_s"),
        ("first countermeasure (s)", "players.blue.containment.first_countermeasure_s"),
        ("approved, called for", "players.blue.verdicts.approved_called_for"),
        ("approved, not called for", "players.blue.verdicts.approved_not_called_for"),
        ("expired", "players.blue.verdicts.expired"),
        ("verdict (s)", "players.blue.verdicts.latency_median_s"),
        ("HMI unavailable (s)", "players.blue.cost.hmi_unavailable_s"),
        ("think (s)", "players.blue.decision.think_median_s"),
        ("calls", "players.blue.calls"),
        ("failed calls", "players.blue.failed_call_rate"),
        ("cost ($)", "players.blue.cost_usd"),
    ),
}


def parse_subjects(spec):
    """ "claude-code:model-a,scripted" -> [("claude-code", "model-a"), ("scripted", None)]."""
    out = []
    for part in str(spec).split(","):
        name, _, model = part.strip().partition(":")
        if not name:
            continue
        if name not in HARNESSES:
            raise SystemExit(f"--harness {name}: the harnesses are {', '.join(sorted(HARNESSES))}")
        out.append((name, model or None))
    if not out:
        raise SystemExit("--harness names no harness")
    return out


def opponents_of(side, wanted=None):
    """The scripted harnesses a harness playing ``side`` is put against:
    those of the other side, or the ones of them named in ``wanted``."""
    other = OTHER[side]
    all_ = [f"scripted-{p}" for p in OPPONENTS[other]]
    if not wanted:
        return all_
    named = [w.strip() for w in str(wanted).split(",") if w.strip()]
    unknown = [w for w in named if w not in HARNESSES]
    if unknown:
        raise SystemExit(f"--opponents {', '.join(unknown)}: not a harness")
    return [w for w in named if w in all_]


def _slug(text):
    return re.sub(r"[^A-Za-z0-9.]+", "-", text).strip("-")


def build_grid(subjects, sides, seeds, opponents=None):
    """Seed-major list of games, so a campaign stopped early has every cell."""
    grid = []
    for seed in seeds:
        for name, model in subjects:
            for side in sides:
                who = f"{name}:{model}" if model else name
                for opponent in opponents_of(side, opponents):
                    group = f"{side}:{who} vs {opponent}"
                    grid.append(
                        {
                            "run_id": f"{_slug(group)}-s{seed}",
                            "group": group,
                            "side": side,
                            "harness": name,
                            "model": model,
                            "opponent": opponent,
                            "seed": seed,
                        }
                    )
    return grid


def _scenario():
    from cyberrange.scenarios.cps_advisor.scenario import CpsAdvisorScenario

    return CpsAdvisorScenario()


def run_args(cfg, entry, out_dir):
    """The scenario's run namespace for one game: the scenario's defaults,
    then the campaign's options, then the game — who sits where. Nothing
    drives the attack: the red seat's harness is the attack."""
    scenario = _scenario()
    base = default_args(scenario)
    overrides = {k: getattr(cfg, k) for k in vars(base) if hasattr(cfg, k) and k not in PER_RUN}
    side, other = entry["side"], OTHER[entry["side"]]
    overrides.update(
        out_dir=out_dir,
        run_id=entry["run_id"],
        seed=entry["seed"],
        progress_file=None,
        teams=True,
        playground=False,
        attack=False,
        **{
            f"{side}_harness": entry["harness"],
            f"{side}_model": entry["model"],
            f"{other}_harness": entry["opponent"],
            f"{other}_model": None,
        },
    )
    if overrides.get("max_calls") is None:
        overrides["max_calls"] = DEFAULT_MAX_CALLS
    return default_args(scenario, **overrides)


def _default_run_fn(args, progress):
    from cyberrange.scenarios.cps_advisor import cli  # Kathará import only when running

    return cli.run(args, progress=progress)


def harness_table(rows):
    """One row per cell of the grid, in the order met: the group, how many
    games, and for each column of its side the mean and its 95% CI."""
    cells = {}
    for r in rows:
        cells.setdefault(r["group"], []).append(r)
    table = []
    for group, games in cells.items():
        side = games[0].get("side") or group.split(":", 1)[0]
        flat = [core_agg.flatten(g.get("metrics")) for g in games]
        row = {"group": group, "side": side, "runs": len(games)}
        for label, path in COLUMNS[side]:
            s = core_agg.stats([f[path] for f in flat if path in f])
            row[label] = {k: s[k] for k in ("n", "mean", "ci95_low", "ci95_high")}
        table.append(row)
    return table


def _cell(s):
    if not s["n"]:
        return "—"
    if s["n"] == 1:
        return f"{s['mean']:.3g}"
    return f"{s['mean']:.3g} [{s['ci95_low']:.3g}, {s['ci95_high']:.3g}]"


def format_harness_table(table):
    """The table as Markdown, one section per side: the two have different columns."""
    lines = []
    for side in SIDES:
        rows = [r for r in table if r["side"] == side]
        if not rows:
            continue
        cols = [label for label, _path in COLUMNS[side]]
        lines += [f"### Harnesses playing {side}", "", "Mean [95% CI] over the cell's games.", ""]
        lines.append("| game | runs | " + " | ".join(cols) + " |")
        lines.append("|---|---|" + "---|" * len(cols))
        for r in rows:
            cells = " | ".join(_cell(r[c]) for c in cols)
            lines.append(f"| {r['group']} | {r['runs']} | {cells} |")
        lines.append("")
    return "\n".join(lines)


def write_bench(campaign_dir, rows):
    """Refresh the campaign's aggregate: the cps tables per cell (detection,
    impact, response), then the harnesses' own. Returns what the ledger keeps."""
    # The cps aggregate groups by "mode": here a cell of the grid is the mode.
    agg = write_aggregate(campaign_dir, [{**r, "mode": r["group"]} for r in rows])
    table = harness_table(rows)
    flat = [
        {"group": r["group"], "side": r["side"], "runs": r["runs"]}
        | {
            f"{label} {k}": r[label][k]
            for label, _p in COLUMNS[r["side"]]
            for k in ("mean", "ci95_low", "ci95_high")
        }
        for r in table
    ]
    core_agg.write_csv(os.path.join(campaign_dir, "harness.csv"), flat)
    with open(os.path.join(campaign_dir, "summary.md"), "a") as f:
        f.write("\n## Harnesses\n\n" + format_harness_table(table))
    return {**agg, "harness": table}


def build_campaign(cfg, run_fn=None, metrics_fn=None, out=print):
    """The core Campaign of ``cfg``: one scored game per cell and seed. Every
    game's options are validated first — a harness whose credential the host
    lacks fails here, not three games in."""
    scenario = _scenario()
    grid = build_grid(
        parse_subjects(cfg.harness),
        [s.strip() for s in str(cfg.sides).split(",") if s.strip()],
        parse_seeds(cfg.seeds),
        getattr(cfg, "opponents", None),
    )
    if not grid:
        raise SystemExit("the grid is empty: no side, no seed, or no opponent of that side")
    for e in grid:
        if e["side"] not in SIDES:
            raise SystemExit(f"--sides {e['side']}: red, blue or both")
        scenario.validate(run_args(cfg, e, ""))
    run_fn = run_fn or _default_run_fn
    root = os.path.join(cfg.out_root, cfg.name)
    units = []
    for e in grid:
        rdir = os.path.join(root, "runs", e["run_id"])
        args = run_args(cfg, e, rdir)
        units.append(
            Unit(
                e["run_id"],
                group=e["group"],
                steps=[
                    Step(
                        e["run_id"],
                        run=lambda emit, a=args: run_fn(a, progress=emit),
                        retries=getattr(cfg, "retries", 1),
                        run_dir=rdir,
                        metrics=metrics_fn or compute_metrics,
                        report=format_report,
                        planned_s=scenario.planned_s(args),
                        label={k: e[k] for k in ("run_id", "group", "side", "seed")},
                        info={k: e[k] for k in ("harness", "model", "opponent")},
                    )
                ],
            )
        )
    common = run_args(cfg, grid[0], "")
    params = {k: v for k, v in sorted(vars(common).items()) if k not in PER_RUN}
    # The tokens are a run's secrets, fresh at each one: not a parameter to keep.
    params = {k: v for k, v in params.items() if k not in scenario.secret_options(common)}
    params["retries"] = getattr(cfg, "retries", 1)
    return Campaign(
        cfg.name,
        root,
        units,
        params=params,
        resume=getattr(cfg, "resume", True),
        aggregate=write_bench,
        out=out,
        scenario=scenario.name,
    )


def run_campaign(cfg, run_fn=None, metrics_fn=None):
    """Run (or resume) the benchmark of ``cfg``. Returns a summary dict.
    ``run_fn(args, progress)`` / ``metrics_fn(out_dir)`` are injectable for tests."""
    if run_fn is None:  # real labs: fail fast if none can run
        from cyberrange.core import lifecycle

        lifecycle.preflight()
    return build_campaign(cfg, run_fn, metrics_fn).run()


def dry_run(cfg, out=print):
    c = build_campaign(cfg, out=out)
    grid = c.dry_run_grid(row=lambda s: f"vs {s.info['opponent']}")
    return grid, c.planned_total_s()


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Benchmark harnesses as players of the cps-advisor lab. Any option of the "
        "scenario's run (python -m cyberrange.scenarios.cps_advisor.cli --help) is accepted "
        "and applies to every game."
    )
    ap.add_argument(
        "--name", default=time.strftime("%Y%m%d-%H%M%S"), help="campaign name; reuse it to resume"
    )
    ap.add_argument("--out-root", default="output/campaigns")
    ap.add_argument(
        "--harness",
        required=True,
        help="the harnesses under test, comma-separated, each <name>[:<model>]",
    )
    ap.add_argument("--sides", default="red,blue", help="the seats each harness is tried at")
    ap.add_argument(
        "--opponents",
        default=None,
        help="the scripted opponents (default: all three of the other side)",
    )
    ap.add_argument("--seeds", default="1-3", help='e.g. "1-5" or "1,3,7"')
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
    sys.exit(
        run_cli(
            build_campaign(cfg),
            out=log.info,
            report=lambda res: f"benchmark {cfg.name}: {format_result(res)}",
        )
    )


if __name__ == "__main__":
    main()
