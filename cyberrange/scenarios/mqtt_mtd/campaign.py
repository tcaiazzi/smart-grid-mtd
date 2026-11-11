"""campaign.py — the workshop paper's evaluation as a campaign on the core
runner: baseline (no MTD), fixed-timer MTD, RL-cost, RL-entropy, then the
compare_coordinators step that renders the paper figures, repeated per run
(output/run-<i>/ with SEED=<seed-base + i>).

Each configuration is a unit whose steps are the same `make` targets
scripts/run_single.sh uses: the Makefile stays the single place that composes the
flags of every stage (order-only prerequisites, reuse guards, cross-model
attack). The units add what make cannot see: retries for lab steps, the
reuse guard of a configuration (datasets + model present -> attack only), the
lazy RL training, the dependency of the cross-model attacks on the run's
baseline model, per-run metrics of every attack (cyberrange/scenarios/mqtt_mtd/metrics.py) and
the 95%-CI aggregate across runs.
"""

import argparse
import csv
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cyberrange.core import aggregate as core_agg, paths
from cyberrange.core.campaign import Campaign, Step, Unit
from cyberrange.scenarios.mqtt_mtd.slug import experiment_slug

REPO_ROOT = paths.REPO_ROOT
PYTHON = sys.executable
DEFAULT_ROOT = "output"
MANIFEST_NAME = "sweep_manifest.csv"

# The paper's parameter configuration (scripts/run_experiments.sh's four env blocks),
# independent of the background replay rate (--mbps).
HOP = 4
IP_POOL = "10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6,10.1.0.7,10.1.0.8"
PORT_POOL = "8883,8884,8885,8886,8887,8888,8889"
SCMC_POOL = "10.0.0.2,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8"
PAD_BUCKETS = "128,256,384,512,640,768,1024"
PAD_INTERVAL = 3
FREQ_INTERVAL = 5
FREQ_POOL = "0.1,0.2,0.4,0.6,0.8,1"

# (experiment, block title, rl_policy, rl_tag)
CONFIGS = [
    ("fixed-timer", "fixed-timer MTD", None, ""),
    ("rl-cost", "RL-cost (blend reward)", "output/rl/policy.npz", ""),
    ("rl-entropy", "RL-entropy (diffusion-only reward)", "output/rl-entropy/policy.npz",
     "entropy"),
]
# Headline per-run metrics in the campaign summary.
HEADLINE = ("nanogrid_detect", "availability_cost", "blocked_is_nanogrid", "data_gaps",
            "publishes")


def say(msg: str) -> str:
    return f"[main] {msg}"


@dataclass(frozen=True)
class RunCtx:
    """Where one repetition of the evaluation writes, and its seed.

    The default (output/, unseeded) adds nothing to any command, so a plain
    run stays command-for-command identical to scripts/run_single.sh.
    """
    root: str = DEFAULT_ROOT
    seed: Optional[int] = None
    index: int = 0

    @property
    def make_vars(self) -> list:
        out = [] if self.root == DEFAULT_ROOT else [f"OUTPUT_ROOT={self.root}"]
        return out + ([] if self.seed is None else [f"SEED={self.seed}"])

    @property
    def root_flag(self) -> list:
        return [] if self.root == DEFAULT_ROOT else ["--output-root", self.root]


def run_contexts(runs: int, seed_base: Optional[int], first_run: int = 0) -> list:
    """The RunCtx of every repetition: the legacy single unseeded run, or
    output/run-<i>/ with SEED=<seed_base>+i."""
    if runs == 1 and seed_base is None and first_run == 0:
        return [RunCtx()]
    base = 0 if seed_base is None else seed_base
    return [RunCtx(f"{DEFAULT_ROOT}/run-{i}", base + i, i)
            for i in range(first_run, first_run + runs)]


def slug(no_mtd: bool, mbps: int, rl_policy: str = None, rl_tag: str = "") -> str:
    args = argparse.Namespace(
        no_mtd=no_mtd, bg_replay_mbps=mbps, mtd_hop_interval=HOP,
        mtd_pad_interval=PAD_INTERVAL, mtd_ip_pool=IP_POOL, mtd_port_pool=PORT_POOL,
        mtd_scmc_ip_pool=SCMC_POOL, mtd_pad_buckets=PAD_BUCKETS,
        mtd_freq_interval=FREQ_INTERVAL, mtd_freq_pool=FREQ_POOL,
        rl_policy=rl_policy, rl_tag=rl_tag,
    )
    return experiment_slug(args)


def _exists(*paths):
    return lambda: all((REPO_ROOT / p).is_file() for p in paths)


def _once(check):
    """``check`` evaluated on its first call only, then remembered."""
    memo = []

    def f():
        if not memo:
            memo.append(check())
        return memo[0]
    return f


def _metrics(run_dir):
    from cyberrange.scenarios.mqtt_mtd.metrics import compute_metrics
    return compute_metrics(run_dir)


def _report(m):
    from cyberrange.scenarios.mqtt_mtd.metrics import format_report
    return format_report(m)


def _label(ctx, experiment, exp):
    return {"run_id": f"{experiment}@{ctx.root}", "group": experiment, "run": ctx.index,
            "seed": ctx.seed, "exp": exp}


def baseline_unit(mbps: int, ctx: RunCtx, retries: int, banner: str = None) -> Unit:
    """Mirrors scripts/run_single.sh's run_baseline() (NO_MTD=1)."""
    exp = f"baseline-mbps{mbps}"
    v = ["NO_MTD=1", f"BG_REPLAY_MBPS={mbps}", *ctx.make_vars]
    attack_dir = f"{ctx.root}/{exp}/attack/model-baseline"
    header = "\n".join(x for x in (banner, say("=== Block 1/5: baseline (no MTD) ==="),
                                   say(f"baseline (no MTD, mbps={mbps})")) if x)
    return Unit(f"baseline@{ctx.root}", group="baseline", header=header, steps=[
        Step("datasets", cmd=["make", "datasets", *v], retries=retries),
        Step("train", cmd=["make", "train", *v]),
        Step("evaluate", cmd=["make", "evaluate", *v]),
        Step("attack", cmd=["make", "attack", *v], retries=retries, run_dir=attack_dir,
             metrics=_metrics, report=_report, label=_label(ctx, "baseline", exp)),
        Step("plot", cmd=[PYTHON, "-m", "cyberrange.scenarios.mqtt_mtd.analysis.plot_results", "--baseline-only",
                          "--bg-replay-mbps", str(mbps), *ctx.root_flag,
                          "--plots-dir", f"{ctx.root}/{exp}"]),
    ])


def config_unit(experiment: str, title: str, block: int, mbps: int, rl_policy: str = None,
                rl_tag: str = "", rl_tick: float = 1.0, ctx: RunCtx = RunCtx(),
                retries: int = 0) -> Unit:
    """Mirrors scripts/run_single.sh's run_config() for one MTD configuration (the
    paper's fixed HOP/pools; only mbps and the RL policy selection vary)."""
    prefix = "mtd"
    if rl_policy:
        prefix = f"mtdrl-{rl_tag}" if rl_tag else "mtdrl"
    # slug() returns the FULL directory name (prefix included) — what make builds
    # on disk; plot_results wants the prefix and the bare hop/pool suffix apart.
    exp = slug(no_mtd=False, mbps=mbps, rl_policy=rl_policy, rl_tag=rl_tag)
    suffix = exp[len(prefix) + 1:]
    v = [f"MTD_HOP_INTERVAL={HOP}", f"MTD_IP_POOL={IP_POOL}", f"MTD_PORT_POOL={PORT_POOL}",
         f"MTD_SCMC_IP_POOL={SCMC_POOL}", f"MTD_SRC_HOP_INTERVAL={HOP}",
         f"MTD_PAD_BUCKETS={PAD_BUCKETS}", f"MTD_PAD_INTERVAL={PAD_INTERVAL}",
         f"BG_REPLAY_MBPS={mbps}", f"MTD_FREQ_INTERVAL={FREQ_INTERVAL}",
         f"MTD_FREQ_POOL={FREQ_POOL}", *ctx.make_vars]
    steps = []
    if rl_policy:
        v += ["RL=1", f"RL_POLICY={rl_policy}", f"RL_TICK={rl_tick}"]
        if rl_tag:
            v.append(f"RL_TAG={rl_tag}")
        # PPO training is lazy: it reads output/**/summary.csv to calibrate its
        # reward (mtd_env.load_calibration), written by the preceding blocks'
        # plot_results — training earlier would calibrate against less data.
        # With --runs it happens once, in run 0; later runs reuse the policy.
        target = "train-rl-entropy" if rl_tag == "entropy" else "train-rl"
        steps.append(Step(f"train-rl:{rl_tag or 'cost'}", cmd=["make", target],
                          skip_if=_exists(rl_policy)))

    exp_dir = f"{ctx.root}/{exp}"
    # The reuse guard is decided ONCE, when the unit starts (as scripts/run_single.sh
    # does): re-checking it per step would see the model `train` just built and
    # wrongly skip the evaluations. Each evaluation is also redone on its own
    # when its predictions are missing (so a rerun completes an older run).
    built = _once(_exists(f"{exp_dir}/datasets/train.pcap", f"{exp_dir}/datasets/test.pcap",
                          f"{exp_dir}/model/model.pt"))
    steps += [
        Step("clean", cmd=["rm", "-rf", exp_dir], skip_if=built),
        Step("datasets", cmd=["make", "datasets", *v], retries=retries, skip_if=built),
        Step("train", cmd=["make", "train", *v], skip_if=built),
        Step("evaluate", cmd=["make", "evaluate", *v],
             skip_if=lambda: built() and _exists(f"{exp_dir}/eval/model-mtd/predictions.csv")()),
        Step("evaluate-baseline-model", cmd=["make", "evaluate", "MODEL_SRC=baseline", *v],
             skip_if=lambda: built() and _exists(
                 f"{exp_dir}/eval/model-baseline/predictions.csv")()),
        # Cross-model attack only (the paper's Fig. 2 attack runs the baseline-trained
        # model against the MTD-morphed traffic; the own-model attack is skipped).
        Step("attack", cmd=["make", "attack", "MODEL_SRC=baseline", *v], retries=retries,
             run_dir=f"{exp_dir}/attack/model-baseline", metrics=_metrics, report=_report,
             label=_label(ctx, experiment, exp)),
        Step("entropy", cmd=["make", "entropy", *v]),
        Step("plot", cmd=[PYTHON, "-m", "cyberrange.scenarios.mqtt_mtd.analysis.plot_results", "--mtd-params-slug", suffix,
                          "--mtd-prefix", prefix, "--bg-replay-mbps", str(mbps),
                          *ctx.root_flag, "--plots-dir", exp_dir]),
        Step("manifest", run=lambda _emit: append_manifest(experiment, mbps, exp, ctx.root)),
    ]

    def header():
        lines = [say(f"=== Block {block}/5: {title} ==="), say(f"[{experiment}] {exp}")]
        if rl_policy and not (REPO_ROOT / rl_policy).is_file():
            lines.append(say(f"  RL policy {rl_policy} missing — training it first"))
        lines.append(say("  datasets + model present — running attack only") if built()
                     else say("  datasets/model missing — full rebuild"))
        return "\n".join(lines)

    return Unit(f"{experiment}@{ctx.root}", group=experiment, header=header,
                needs=[f"baseline@{ctx.root}"], steps=steps)


def append_manifest(experiment: str, mbps: int, exp: str, root: str = DEFAULT_ROOT) -> None:
    # One manifest per run root, so the slug dedup below is per run.
    manifest_path = REPO_ROOT / root / MANIFEST_NAME
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


def compare_dir(mbps: int, ctx: RunCtx) -> str:
    return f"{ctx.root}/compare-{slug(no_mtd=False, mbps=mbps)[len('mtd-'):]}"


def compare_unit(mbps: int, ctx: RunCtx) -> Unit:
    """The paper-figure step: compare_coordinators.py across the three MTD
    configs + baseline, tagged with the entropy RL policy."""
    suffix = slug(no_mtd=False, mbps=mbps)[len("mtd-"):]
    return Unit(f"compare@{ctx.root}", group="compare",
                header=say("=== Block 5/5: paper figures (compare_coordinators) ==="),
                needs=[f"baseline@{ctx.root}"] + [f"{e}@{ctx.root}" for e, *_ in CONFIGS],
                steps=[Step("compare", cmd=[
                    PYTHON, "-m", "cyberrange.scenarios.mqtt_mtd.analysis.compare_coordinators", "--slug", suffix,
                    "--bg-replay-mbps", str(mbps), "--output-root", ctx.root,
                    "--out-dir", compare_dir(mbps, ctx), "--rl-tags", "entropy"])])


FIGURES = [
    ("Fig. 2a — availability over time", "availability_comparison.pdf"),
    ("Fig. 2b — attacker confidence per config", "detection_comparison.pdf"),
    ("Fig. 2c — cumulative availability cost", "availability_cost_comparison.pdf"),
    ("Fig. 3 — per-field Shannon entropy", "entropy_comparison.pdf"),
]


def write_aggregate(root, rows):
    """Per-configuration mean [95% CI] across runs of every per-run metric."""
    table = core_agg.summarize(rows, by=("group",))
    core_agg.write_csv(os.path.join(root, "ci.csv"), table)
    with open(os.path.join(root, "summary.md"), "w") as f:
        f.write("# Paper evaluation — per configuration, mean [95% CI] (runs)\n\n")
        f.write(core_agg.format_markdown(
            table, by=("group",),
            metrics=[m for m in HEADLINE if any(r["metric"] == m for r in table)]))
    return {"ci": [r for r in table if r["metric"] in HEADLINE]}


def build_campaign(mbps=2, runs=1, seed_base=None, first_run=0, retries=2, name=None,
                   resume=False, out=print):
    """The whole paper evaluation as one campaign (ledger under output/campaigns/)."""
    contexts = run_contexts(runs, seed_base, first_run)
    units = []
    for ctx in contexts:
        banner = (say(f"##### run {ctx.root} (SEED={ctx.seed}) #####")
                  if len(contexts) > 1 or ctx.root != DEFAULT_ROOT else None)
        units.append(baseline_unit(mbps, ctx, retries, banner))
        for block, (experiment, title, policy, tag) in enumerate(CONFIGS, start=2):
            units.append(config_unit(experiment, title, block, mbps, rl_policy=policy,
                                     rl_tag=tag, ctx=ctx, retries=retries))
        units.append(compare_unit(mbps, ctx))
    name = name or f"paper-mbps{mbps}"
    params = {"mbps": mbps, "runs": runs, "seed_base": seed_base, "first_run": first_run,
              "retries": retries, "hop": HOP, "ip_pool": IP_POOL, "port_pool": PORT_POOL,
              "scmc_pool": SCMC_POOL, "pad_buckets": PAD_BUCKETS,
              "pad_interval": PAD_INTERVAL, "freq_interval": FREQ_INTERVAL,
              "freq_pool": FREQ_POOL}
    return Campaign(name, os.path.join(DEFAULT_ROOT, "campaigns", name), units,
                    params=params, resume=resume, aggregate=write_aggregate, out=out,
                    scenario="mqtt-mtd"), contexts
