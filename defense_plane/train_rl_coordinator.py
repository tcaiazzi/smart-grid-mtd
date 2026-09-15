#!/usr/bin/env python3
"""
train_rl_coordinator.py — train the RL MTD coordinator policy (offline).

Trains a PPO agent on mtd_env.MTDCoordinatorEnv and writes two artifacts:

  output/rl/policy.zip   full SB3 model (for re-training / inspection on the host)
  output/rl/policy.npz   distilled numpy weights the lab coordinator loads
                         (assets/mtd_rl_coordinator.py — torch-free container)

PPO (not DQN) because the action space is MultiDiscrete (one sub-action per knob);
DQN only supports a single Discrete space. The default MlpPolicy is [64,64] with
tanh, which is exactly what rl_policy.export_sb3_policy / NumpyMLPPolicy replay.

After training it runs a sanity gate: it evaluates the learned policy and a
fixed-timer baseline policy (the behaviour of the current mtd_coordinator.py) in
the SAME env and prints their blended reward. A useful policy should match or beat
the fixed timer on the availability+security blend.

Usage:
  .venv/bin/python train_rl_coordinator.py --timesteps 200000 \
      --w-sec 1.0 --w-avail 1.0 --out-dir output/rl
"""

import argparse
import os

import numpy as np

from defense_plane.mtd_env import MTDCoordinatorEnv, load_calibration
from defense_plane.rl_policy import (
    K_FREQ,
    K_PAD,
    KNOBS,
    N_RECONNECT,
    NumpyMLPPolicy,
    export_sb3_policy,
)


def fixed_timer_action(dwell, pools, intervals):
    """The current coordinator's behaviour as a policy: fire a knob once its dwell
    reaches that knob's fixed interval. Used only as the evaluation baseline."""
    action = [0, 0, 0, 0, 0]
    for k in range(N_RECONNECT):                 # port, ip, src
        if pools[k] > 1 and dwell[k] >= intervals[k]:
            action[k] = 1
    if pools[3] > 1 and dwell[3] >= intervals[3]:        # padding → mid diversity
        action[3] = K_PAD // 2
    if pools[4] > 1 and dwell[4] >= intervals[4]:        # frequency → mid diversity
        action[4] = K_FREQ // 2
    return np.array(action, dtype=np.int64)


def evaluate(env, act_fn, episodes: int = 20) -> dict:
    """Mean blended reward / detection / reconnect rate over fresh episodes."""
    rewards, dets, recon = [], [], []
    for ep in range(episodes):
        obs, _ = env.reset(seed=1000 + ep)
        ep_r, n = 0.0, 0
        truncated = False
        while not truncated:
            action = act_fn(obs, env)
            obs, r, _term, truncated, info = env.step(action)
            ep_r += r
            dets.append(info["detection"])
            recon.append(info["n_reconnect"])
            n += 1
        rewards.append(ep_r / max(n, 1))
    return {
        "reward": float(np.mean(rewards)),
        "detection": float(np.mean(dets)),
        "reconnect_rate": float(np.mean(recon)),
    }


def parse_args():
    p = argparse.ArgumentParser(description="Train the RL MTD coordinator policy")
    p.add_argument("--timesteps", type=int, default=200_000)
    p.add_argument("--w-sec", type=float, default=1.0, help="security reward weight")
    p.add_argument("--w-avail", type=float, default=1.0, help="availability cost weight")
    p.add_argument("--reward-mode", choices=["blend", "entropy"], default="blend",
                   help="'blend' = security vs availability cost (default); "
                        "'entropy' = maximize diffusion only, no cost.")
    p.add_argument("--episode-len", type=int, default=256)
    p.add_argument("--out-dir", default="output/rl")
    p.add_argument("--output-root", default="output",
                   help="Scanned for summary.csv/entropy.csv to calibrate the reward.")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--fixed-intervals", default="2,2,2,3,30",
                   help="Baseline fixed-timer intervals (ticks) for the sanity gate: "
                        "port,ip,src,pad,freq.")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    cal = load_calibration(args.output_root)
    print(f"[train] calibration: detection_max={cal.detection_max:.3f} "
          f"detection_min={cal.detection_min:.3f}")

    def make_env():
        return MTDCoordinatorEnv(
            w_sec=args.w_sec, w_avail=args.w_avail, reward_mode=args.reward_mode,
            episode_len=args.episode_len, calibration=cal, seed=args.seed,
        )

    print(f"[train] reward_mode={args.reward_mode} w_sec={args.w_sec} w_avail={args.w_avail}")

    from stable_baselines3 import PPO

    env = make_env()
    model = PPO("MlpPolicy", env, seed=args.seed, verbose=1,
                policy_kwargs=dict(net_arch=[64, 64]))
    print(f"[train] PPO for {args.timesteps} timesteps...")
    model.learn(total_timesteps=args.timesteps)

    zip_path = os.path.join(args.out_dir, "policy")
    model.save(zip_path)
    npz_path = os.path.join(args.out_dir, "policy.npz")
    export_sb3_policy(model, npz_path)
    print(f"[train] saved {zip_path}.zip and {npz_path}")

    # ── Sanity gate: learned policy vs fixed-timer baseline in the same env ──
    eval_env = make_env()
    np_policy = NumpyMLPPolicy.load(npz_path)
    intervals = [float(x) for x in args.fixed_intervals.split(",")]

    rl_stats = evaluate(eval_env, lambda obs, e: np_policy.predict(obs))
    fixed_stats = evaluate(
        eval_env, lambda obs, e: fixed_timer_action(e.dwell, e.pools, intervals)
    )

    print("\n=== Sanity gate (mean per-step blended reward) ===")
    print(f"  {'policy':<14}{'reward':>10}{'detection':>12}{'reconnect/step':>16}")
    for name, s in (("RL (learned)", rl_stats), ("fixed-timer", fixed_stats)):
        print(f"  {name:<14}{s['reward']:>10.4f}{s['detection']:>12.4f}"
              f"{s['reconnect_rate']:>16.3f}")
    verdict = ("PASS — RL ≥ fixed" if rl_stats["reward"] >= fixed_stats["reward"]
               else "WARN — RL < fixed (tune weights / timesteps)")
    print(f"  verdict: {verdict}\n")


if __name__ == "__main__":
    main()
