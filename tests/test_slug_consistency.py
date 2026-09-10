"""Regression test for the triplicated experiment-slug formula.

The compact output/<slug>/ directory name for one parameter configuration is
computed independently in three places that cannot be collapsed into one
without touching the Makefile (out of scope for this refactor — see the
project's refactor plan, item (e)):

  1. network_scenario.slug.experiment_slug()   — Python, used by
     run_experiment.py and main.py.
  2. Makefile's MTD_PARAMS_SLUG / EXP_SLUG     — GNU Make string substitution
     (Makefile:82-129).
  3. run_single.sh / run_sweep.sh's make_slug() — bash (same formula, split
     into a suffix-only helper + a prefix assembled by the caller).

This test keeps that triplication *checked* rather than silently drifting: for
a matrix of representative configurations, it asserts all three formulas
produce byte-identical slugs.
"""

import argparse
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from network_scenario.slug import experiment_slug  # noqa: E402

# (label, no_mtd, mbps, hop, pad_interval, ip_pool, port_pool, scmc_pool,
#  pad_buckets, freq_interval, freq_pool, rl_policy, rl_tag)
# Covers: baseline, a single-entry (hop-disabled) MTD config, the paper's
# 6/7-entry config, an RL-blend config, and an RL-entropy (tagged) config.
CONFIGS = [
    ("baseline-mbps2", True, 2, 2, 3, "10.1.0.2", "8883,8884,8885,8886,8887",
     "10.0.0.2", "128,256,384,512,640,768,1024", 30, "1.0", None, ""),
    ("baseline-mbps100", True, 100, 2, 3, "10.1.0.2", "8883,8884,8885,8886,8887",
     "10.0.0.2", "128,256,384,512,640,768,1024", 30, "1.0", None, ""),
    ("mtd-defaults", False, 2, 2, 3, "10.1.0.2", "8883,8884,8885,8886,8887",
     "10.0.0.2", "128,256,384,512,640,768,1024", 30, "1.0", None, ""),
    ("mtd-paper", False, 2, 4, 3,
     "10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6,10.1.0.7,10.1.0.8",
     "8883,8884,8885,8886,8887,8888,8889",
     "10.0.0.2,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8",
     "128,256,384,512,640,768,1024", 5, "0.1,0.2,0.4,0.6,0.8,1", None, ""),
    ("mtdrl-blend-paper", False, 2, 4, 3,
     "10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6,10.1.0.7,10.1.0.8",
     "8883,8884,8885,8886,8887,8888,8889",
     "10.0.0.2,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8",
     "128,256,384,512,640,768,1024", 5, "0.1,0.2,0.4,0.6,0.8,1",
     "output/rl/policy.npz", ""),
    ("mtdrl-entropy-paper", False, 2, 4, 3,
     "10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6,10.1.0.7,10.1.0.8",
     "8883,8884,8885,8886,8887,8888,8889",
     "10.0.0.2,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8",
     "128,256,384,512,640,768,1024", 5, "0.1,0.2,0.4,0.6,0.8,1",
     "output/rl-entropy/policy.npz", "entropy"),
    ("mtd-odd-pools", False, 7, 9, 5, "10.1.0.2,10.1.0.4", "8883,8884,8885",
     "10.0.0.2,10.0.0.4,10.0.0.5", "128,256", 11, "1.0,2.0", None, ""),
]


def _python_slug(cfg) -> str:
    (_label, no_mtd, mbps, hop, pad_interval, ip_pool, port_pool, scmc_pool,
     pad_buckets, freq_interval, freq_pool, rl_policy, rl_tag) = cfg
    args = argparse.Namespace(
        no_mtd=no_mtd,
        bg_replay_mbps=mbps,
        mtd_hop_interval=hop,
        mtd_pad_interval=pad_interval,
        mtd_ip_pool=ip_pool,
        mtd_port_pool=port_pool,
        mtd_scmc_ip_pool=scmc_pool,
        mtd_pad_buckets=pad_buckets,
        mtd_freq_interval=freq_interval,
        mtd_freq_pool=freq_pool,
        rl_policy=rl_policy,
        rl_tag=rl_tag,
    )
    return experiment_slug(args)


def _makefile_slug(cfg) -> str:
    """The Makefile's own EXP_SLUG, read back via `make help` (side-effect-free:
    the target only echoes, see Makefile:159-211) so this test can never
    silently duplicate the Make formula in Python — it asks Make itself."""
    (_label, no_mtd, mbps, hop, pad_interval, ip_pool, port_pool, scmc_pool,
     pad_buckets, freq_interval, freq_pool, rl_policy, rl_tag) = cfg
    make_vars = [
        f"NO_MTD={1 if no_mtd else 0}",
        f"BG_REPLAY_MBPS={mbps}",
        f"MTD_HOP_INTERVAL={hop}",
        f"MTD_PAD_INTERVAL={pad_interval}",
        f"MTD_IP_POOL={ip_pool}",
        f"MTD_PORT_POOL={port_pool}",
        f"MTD_SCMC_IP_POOL={scmc_pool}",
        f"MTD_PAD_BUCKETS={pad_buckets}",
        f"MTD_FREQ_INTERVAL={freq_interval}",
        f"MTD_FREQ_POOL={freq_pool}",
    ]
    if rl_policy:
        make_vars += ["RL=1", f"RL_POLICY={rl_policy}"]
        if rl_tag:
            make_vars.append(f"RL_TAG={rl_tag}")
    result = subprocess.run(
        ["make", "help", *make_vars],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=True,
    )
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Experiment dir: output/"):
            return line[len("Experiment dir: output/"):]
    raise AssertionError(f"could not find 'Experiment dir:' line in `make help` output:\n{result.stdout}")


# The exact make_slug()/count_items() bash source, extracted once from
# run_single.sh with an awk state machine (mirrors the extraction the
# project's refactor plan specifies) so this test tracks the real
# implementation instead of a hand-copied snapshot of it.
_AWK_EXTRACT = (
    r'/^count_items\(\)/{print; next} '
    r'/^make_slug\(\)/{f=1} f{print; if(/^}/){f=0}}'
)


def _bash_slug(cfg) -> str:
    """run_single.sh's make_slug() (suffix) + the prefix its callers assemble
    around it (run_baseline / run_config), run as a real bash function call —
    never by sourcing run_single.sh itself, which would kick off a lab run."""
    (_label, no_mtd, mbps, hop, pad_interval, ip_pool, port_pool, scmc_pool,
     pad_buckets, freq_interval, freq_pool, rl_policy, rl_tag) = cfg
    if no_mtd:
        return f"baseline-mbps{mbps}"
    prefix = "mtd"
    if rl_policy:
        prefix = f"mtdrl-{rl_tag}" if rl_tag else "mtdrl"
    script = f'''
set -euo pipefail
eval "$(awk '{_AWK_EXTRACT}' run_single.sh)"
suffix=$(make_slug {hop} {pad_interval} "{ip_pool}" "{port_pool}" "{scmc_pool}" "{pad_buckets}" {mbps} {freq_interval} "{freq_pool}")
printf '%s-%s' "{prefix}" "$suffix"
'''
    result = subprocess.run(
        ["bash", "-c", script], cwd=REPO_ROOT,
        capture_output=True, text=True, timeout=15, check=True,
    )
    return result.stdout.strip()


class SlugConsistency(unittest.TestCase):
    def test_all_three_formulas_agree(self) -> None:
        for cfg in CONFIGS:
            label = cfg[0]
            with self.subTest(config=label):
                py = _python_slug(cfg)
                mk = _makefile_slug(cfg)
                self.assertEqual(py, mk, f"[{label}] python={py!r} != makefile={mk!r}")
                bs = _bash_slug(cfg)
                self.assertEqual(py, bs, f"[{label}] python={py!r} != bash={bs!r}")


if __name__ == "__main__":
    unittest.main()
