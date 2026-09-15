#!/usr/bin/env python3
"""
mtd_env.py — offline training environment for the RL MTD coordinator.

A fast, pure-python gymnasium.Env that models the moving-target-defense vs passive
fingerprinting game at the timescale of one coordinator decision tick. We train
here (seconds–minutes) instead of in the Kathará lab because the lab attacker is
passive: its fingerprint accuracy is only measurable post-hoc by scoring a captured
pcap, and each live run takes minutes and retrains the CNN — so per-step online RL
in the lab is infeasible. The learned policy is then deployed unchanged
(assets/mtd_rl_coordinator.py), which is why the observation/action layout lives in
the shared, dependency-free rl_policy module.

The agent actuates the same five MTD knobs the real coordinator drives
(rl_policy.KNOBS): broker port hop, broker IP hop, SCMC source-IP hop, payload
padding, publish-frequency. Reward blends:

  security_gain      ↑ as the traffic the attacker sees gets more diverse
                       (driven by how often each knob fires; saturating)
  availability_cost  ↑ per reconnecting hop (port/IP/src each drop publishes;
                       padding/frequency are essentially free)

  reward = w_sec · security_gain − w_avail · availability_cost

so the optimum is a non-trivial schedule: hop the cheap/high-value knobs enough to
suppress fingerprinting, but stop short of the point where extra reconnects only
cost telemetry. Reward constants are calibrated from whatever real runs already
exist under output/<slug>/ (summary.csv detection scores + entropy.csv), falling
back to anchors measured from the runs present at design time.

This module imports gymnasium/numpy and is host-only — it is never copied into the
lab containers.
"""

import glob
import os
from dataclasses import dataclass, field

import gymnasium as gym
import numpy as np
import pandas as pd
from gymnasium import spaces

from defense_plane.rl_policy import (
    ACTION_DIMS,
    DWELL_INIT,
    EWMA_ALPHA,
    K_PAD,
    KNOB_COST,
    N_KNOBS,
    N_RECONNECT,
    OBS_DIM,
    build_observation,
    decode_action,
)


# ── Reward calibration ─────────────────────────────────────────────────────────

@dataclass
class Calibration:
    """Constants grounding the reward in measured lab behaviour.

    detection_max / detection_min bracket the attacker's fingerprint score
    (nanogrid_frac): ~detection_max for a static target, ~detection_min for an
    actively hopping one. The reconnect costs are the fraction of publishes lost
    per hop of each address knob (IP/src cost more than a port NAT swap). beta/gamma
    shape how fast diversity saturates and how strongly it suppresses detection.
    """
    detection_max: float = 0.93       # static / no-MTD fingerprint score (measured)
    detection_min: float = 0.55       # best achievable under heavy MTD
    # per-knob saturation rate of the diversity each knob contributes
    beta: tuple = (4.0, 4.0, 4.0, 3.0, 3.0)        # port, ip, src, pad, freq
    # weight of each knob's diversity in suppressing detection. freq actuation now
    # rotates the publish interval (timing variety), so it earns a real weight.
    sec_weight: tuple = (1.0, 1.0, 1.2, 0.5, 0.8)  # port, ip, src, pad, freq
    gamma: float = 2.5                # detection suppression strength
    # availability cost per actuation (reconnecting knobs only). Single source
    # of truth: rl_policy.KNOB_COST (also read by monitor.compare_coordinators
    # to bill the actuations observed in a live run against the same weights).
    cost: tuple = KNOB_COST


def load_calibration(output_root: str = "output") -> Calibration:
    """Best-effort calibration from existing experiment outputs.

    Scans output/*/summary.csv for the baseline (no-MTD) and best MTD detection
    scores to set detection_max/min. Silent fallback to the dataclass defaults
    (anchored to the runs present at design time) when nothing is found — so
    training never depends on a sweep having been run.
    """
    cal = Calibration()
    try:
        fracs_static, fracs_mtd = [], []
        for path in glob.glob(os.path.join(output_root, "*", "summary.csv")):
            df = pd.read_csv(path)
            if "scmc_nanogrid_frac" not in df.columns:
                continue
            for _, row in df.iterrows():
                frac = row.get("scmc_nanogrid_frac")
                if pd.isna(frac):
                    continue
                label = str(row.get("scenario", "")).lower()
                (fracs_static if "baseline" in label or "no mtd" in label
                 else fracs_mtd).append(float(frac))
        if fracs_static:
            cal.detection_max = max(fracs_static)
        if fracs_mtd:
            cal.detection_min = min(fracs_mtd)
        if cal.detection_min >= cal.detection_max:      # guard degenerate data
            cal.detection_min = max(0.0, cal.detection_max - 0.2)
    except Exception:
        pass
    return cal


# ── Environment ────────────────────────────────────────────────────────────────

class MTDCoordinatorEnv(gym.Env):
    """Single-agent env over the five MTD knobs (see module docstring)."""

    metadata = {"render_modes": []}

    def __init__(self, pool_sizes=None, w_sec: float = 1.0, w_avail: float = 1.0,
                 episode_len: int = 256, ewma_alpha: float = EWMA_ALPHA,
                 calibration: Calibration = None, randomize_pools: bool = True,
                 reward_mode: str = "blend", seed: int = None):
        super().__init__()
        # "blend"   = w_sec·security_gain − w_avail·availability_cost (the default).
        # "entropy" = maximize diffusion only: mean per-knob diversity, NO cost — a
        #             pure security/entropy objective that ignores reconnect cost.
        assert reward_mode in ("blend", "entropy"), reward_mode
        self.reward_mode = reward_mode
        # Default pool sizes mirror a typical run_single.sh config (port, ip, src,
        # pad buckets, freq). A knob with size <= 1 is unusable and forced to noop.
        self.base_pools = np.array(pool_sizes if pool_sizes is not None
                                   else [7, 6, 6, 7, 6], dtype=np.float32)
        self.w_sec = w_sec
        self.w_avail = w_avail
        self.episode_len = episode_len
        self.alpha = ewma_alpha
        self.cal = calibration or Calibration()
        self.randomize_pools = randomize_pools
        self._rng = np.random.default_rng(seed)

        self.action_space = spaces.MultiDiscrete(ACTION_DIMS)
        self.observation_space = spaces.Box(0.0, 1.0, shape=(OBS_DIM,), dtype=np.float32)

        self._reset_state()

    # ── state helpers ──

    def _reset_state(self):
        self.dwell = np.full(N_KNOBS, DWELL_INIT, dtype=np.float32)
        self.rate = np.zeros(N_KNOBS, dtype=np.float32)
        self.pad_level = 0
        self.t = 0
        if self.randomize_pools:
            # Vary pools each episode so one policy generalises across configs;
            # occasionally disable a knob (size 1) so the policy handles that too.
            jitter = self._rng.integers(-2, 3, size=N_KNOBS)
            self.pools = np.clip(self.base_pools + jitter, 1, 12).astype(np.float32)
        else:
            self.pools = self.base_pools.copy()

    def _obs(self) -> np.ndarray:
        return build_observation(self.dwell, self.rate, self.pools)

    # ── gym API ──

    def reset(self, *, seed=None, options=None):
        if seed is not None:
            self._rng = np.random.default_rng(seed)
        self._reset_state()
        return self._obs(), {}

    def step(self, action):
        cmd = decode_action(action)
        # Which knobs actually fired this tick (a knob with <=1 option can't).
        fired = np.zeros(N_KNOBS, dtype=np.float32)
        usable = self.pools > 1
        if cmd["port"] and usable[0]:
            fired[0] = 1.0
        if cmd["ip"] and usable[1]:
            fired[1] = 1.0
        if cmd["src"] and usable[2]:
            fired[2] = 1.0
        if cmd["pad_level"] is not None and usable[3]:
            fired[3] = 1.0
            self.pad_level = cmd["pad_level"]
        if cmd["freq_rotate"] and usable[4]:
            # each actuation rotates to a different interval → real timing variety
            fired[4] = 1.0

        # Update dwell (reset on fire, else age) and EWMA hop rate.
        self.dwell = np.where(fired > 0, 0.0, self.dwell + 1.0)
        self.rate = (1.0 - self.alpha) * self.rate + self.alpha * fired

        reward = self._reward(fired)

        self.t += 1
        terminated = False
        truncated = self.t >= self.episode_len
        return self._obs(), float(reward), terminated, truncated, self._reward_info(fired)

    # ── reward model ──

    def _diversity(self) -> np.ndarray:
        """Per-knob diversity contributed at the current hop rates (saturating).

        A knob seen on the wire becomes diverse the more often it changes; the
        regime knobs (pad/freq) additionally scale with the chosen diversity level.
        """
        beta = np.asarray(self.cal.beta, dtype=np.float32)
        div = 1.0 - np.exp(-beta * self.rate)
        # padding scales with how many buckets the current regime spreads over;
        # freq is keep/rotate, so its variety is fully captured by the rate term.
        div[3] *= (self.pad_level + 1) / K_PAD
        # a disabled knob contributes nothing
        div = np.where(self.pools > 1, div, 0.0)
        return div

    def _detection(self) -> float:
        div = self._diversity()
        w = np.asarray(self.cal.sec_weight, dtype=np.float32)
        suppression = float(np.dot(w, div))
        span = self.cal.detection_max - self.cal.detection_min
        return self.cal.detection_min + span * np.exp(-self.cal.gamma * suppression)

    def _reward(self, fired: np.ndarray) -> float:
        if self.reward_mode == "entropy":
            # Pure diffusion: maximize mean per-knob diversity over the usable knobs,
            # with NO availability cost. The agent uses every action it has to push
            # each wire field's entropy up (it will hop maximally, like the timer).
            div = self._diversity()
            usable = self.pools > 1
            return float(div[usable].mean()) if usable.any() else 0.0

        det = self._detection()
        span = max(self.cal.detection_max - self.cal.detection_min, 1e-6)
        security_gain = (self.cal.detection_max - det) / span        # [0, 1]
        avail_cost = float(np.dot(np.asarray(self.cal.cost, dtype=np.float32), fired))
        return self.w_sec * security_gain - self.w_avail * avail_cost

    def _reward_info(self, fired: np.ndarray) -> dict:
        det = self._detection()
        return {
            "detection": det,
            "n_reconnect": float(fired[:N_RECONNECT].sum()),
            "fired": fired.copy(),
        }
