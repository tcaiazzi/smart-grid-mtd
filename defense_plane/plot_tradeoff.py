#!/usr/bin/env python3
"""
plot_tradeoff.py — visualise "lower hop cost at equal security".

The headline RL result is that the learned coordinator matches the fixed timer's
security while paying far fewer reconnecting hops. That is a 2-D tradeoff, so we
plot it as one:

    x = attacker detection      (↓ = better security)
    y = reconnecting hops / step (↓ = better availability — each port/IP/src hop
                                  drops telemetry during the reconnect)

Every coordinator is a point; bottom-left is best (secure AND cheap). We sweep the
fixed-timer policy across hop intervals to draw its security–cost frontier, then
drop the trained RL policy on top — it lands at the same security but well below
the frontier (less cost), which is the dominance claim made visual.

This runs entirely in the simulation env (mtd_env), the only place with a real
hop-cost axis (the lab entropy comparison measures diffusion, not cost). No lab
run needed.

Usage:
  .venv/bin/python plot_tradeoff.py --policy output/rl/policy.npz --out-dir output/rl
"""

import argparse
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["axes.labelsize"] = 12  # axis (x/y) label font size
plt.rcParams["xtick.labelsize"] = 12  # x tick-label font size
plt.rcParams["ytick.labelsize"] = 12  # y tick-label font size
import pandas as pd

from defense_plane.mtd_env import MTDCoordinatorEnv, load_calibration
from defense_plane.rl_policy import NumpyMLPPolicy
from defense_plane.train_rl_coordinator import evaluate, fixed_timer_action


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Plot the security vs hop-cost tradeoff")
    p.add_argument("--policy", default="output/rl/policy.npz",
                   help="Distilled RL policy to place on the frontier.")
    p.add_argument("--out-dir", default="output/rl")
    p.add_argument("--output-root", default="output",
                   help="Scanned to calibrate the env reward (summary.csv).")
    p.add_argument("--episodes", type=int, default=30)
    p.add_argument("--hop-intervals", default="1,2,4,8,16,30",
                   help="Fixed-timer hop intervals (ticks) to sweep for the frontier.")
    p.add_argument("--pool-sizes", default="7,6,6,7,6",
                   help="Action-space sizes (port,ip,src,pad,freq) — match the lab config.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    cal = load_calibration(args.output_root)
    pools = [int(x) for x in args.pool_sizes.split(",")]

    # One fixed env (no pool randomisation) so every policy is judged identically.
    def make_env():
        return MTDCoordinatorEnv(pool_sizes=pools, calibration=cal,
                                 randomize_pools=False, seed=0)

    env = make_env()
    rows = []

    # Fixed-timer frontier: vary the reconnecting-knob interval; keep pad/freq lively.
    for h in [int(x) for x in args.hop_intervals.split(",")]:
        intervals = [h, h, h, 3, 5]
        s = evaluate(env, lambda obs, e, iv=intervals: fixed_timer_action(e.dwell, e.pools, iv),
                     episodes=args.episodes)
        rows.append({"policy": f"fixed (hop={h})", "kind": "fixed",
                     "detection": s["detection"], "reconnect_rate": s["reconnect_rate"],
                     "reward": s["reward"]})

    # The trained RL policy.
    npp = NumpyMLPPolicy.load(args.policy)
    s = evaluate(env, lambda obs, e: npp.predict(obs), episodes=args.episodes)
    rows.append({"policy": "RL (learned)", "kind": "rl",
                 "detection": s["detection"], "reconnect_rate": s["reconnect_rate"],
                 "reward": s["reward"]})

    df = pd.DataFrame(rows)
    print(df.to_string(index=False))
    csv_path = os.path.join(args.out_dir, "tradeoff.csv")
    df.to_csv(csv_path, index=False)
    print(f"[tradeoff] table -> {csv_path}")

    # ── Plot ──
    fixed = df[df["kind"] == "fixed"].sort_values("detection")
    rl = df[df["kind"] == "rl"].iloc[0]

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fixed["detection"], fixed["reconnect_rate"], "s--", color="#2980b9",
            lw=2, ms=8, label="fixed timer (hop-interval sweep)", zorder=3)
    for _, r in fixed.iterrows():
        ax.annotate(r["policy"].replace("fixed ", ""), (r["detection"], r["reconnect_rate"]),
                    textcoords="offset points", xytext=(6, 4), fontsize=8, color="#2980b9")

    ax.scatter([rl["detection"]], [rl["reconnect_rate"]], color="#27ae60", marker="*",
               s=420, edgecolor="black", zorder=5, label="RL (learned)")
    ax.annotate("RL", (rl["detection"], rl["reconnect_rate"]),
                textcoords="offset points", xytext=(8, 6), fontsize=11, fontweight="bold",
                color="#1e8449")

    # "Equal security" guide: drop a vertical line at the RL detection level so the
    # cost gap to the fixed timer at the same security is unmistakable.
    ax.axvline(rl["detection"], ls=":", color="gray", lw=1.2,
               label="RL security level")

    ax.set_xlabel("attacker detection  (↓ = better security)")
    ax.set_ylabel("reconnecting hops per step  (↓ = better availability)")
    ax.set_title("Security vs hop cost — RL matches fixed security at far lower cost")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper left", fontsize=9)
    ax.annotate("better\n(secure & cheap)", (0.02, 0.02), xycoords="axes fraction",
                fontsize=9, color="gray", ha="left", va="bottom")
    fig.tight_layout()
    out = os.path.join(args.out_dir, "tradeoff.pdf")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"[tradeoff] figure -> {out}")


if __name__ == "__main__":
    main()
