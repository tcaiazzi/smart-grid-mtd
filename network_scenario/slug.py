"""Compact per-configuration directory-name slug.

Single source of truth for run_experiment.py and main.py — both need to derive
the same output/<slug>/ directory a given parameter configuration lands in.
The Makefile computes the identical string independently as MTD_PARAMS_SLUG
(Makefile:82-129) and run_single.sh/run_sweep.sh do the same in bash
(make_slug()); that triplication cannot be collapsed without changing the
Makefile, which is out of scope here — see tests/test_slug_consistency.py for
the check that keeps the three formulas honest.
"""


def experiment_slug(args) -> str:
    """Compact directory name for one parameter configuration.

    Mirrors the Makefile's EXP_SLUG / MTD_PARAMS_SLUG exactly so a standalone run
    lands in the same output/<slug>/ directory the Makefile expects:
        baseline -> baseline-mbps<M>
        mtd      -> mtd-hop<H>-padint<PI>-ips<NI>-ports<NP>-pads<NB>-mbps<M>
    """
    if args.no_mtd:
        return f"baseline-mbps{args.bg_replay_mbps}"
    n_ips = len(args.mtd_ip_pool.split(","))
    n_ports = len(args.mtd_port_pool.split(","))
    n_pads = len(args.mtd_pad_buckets.split(","))
    n_scmc_ips = len(args.mtd_scmc_ip_pool.split(","))
    n_freqs = len(args.mtd_freq_pool.split(","))
    # An RL-coordinated run uses a distinct prefix so its artifacts sit beside the
    # fixed-timer run's instead of overwriting them (enables the RL-vs-fixed compare).
    # --rl-tag further separates competing RL policies (e.g. mtdrl-entropy-<slug>).
    if args.rl_policy:
        prefix = f"mtdrl-{args.rl_tag}" if args.rl_tag else "mtdrl"
    else:
        prefix = "mtd"
    return (
        f"{prefix}-hop{args.mtd_hop_interval}-padint{args.mtd_pad_interval}"
        f"-ips{n_ips}-ports{n_ports}-pads{n_pads}-srcips{n_scmc_ips}"
        f"-mbps{args.bg_replay_mbps}"
        f"-freqint{args.mtd_freq_interval}-freqs{n_freqs}"
    )
