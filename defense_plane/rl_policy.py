#!/usr/bin/env python3
"""
rl_policy.py — shared, dependency-free spec for the RL MTD coordinator.

This module is the single source of truth for two things the training side
(mtd_env.py / train_rl_coordinator.py, on the host) and the deployment side
(assets/mtd_rl_coordinator.py, inside the semp container) MUST agree on:

  • the observation layout  (build_observation)
  • the action layout       (ACTION_DIMS + decode_action)

Keeping them here guarantees the policy sees the same features in simulation and
in the live lab, so a policy trained against mtd_env transfers unchanged.

It also carries a tiny numpy-only MLP runner (NumpyMLPPolicy). The container
image has numpy but NOT torch / gymnasium / stable-baselines3, so the coordinator
cannot load an SB3 .zip. Instead, training distills the learned PPO policy network
into a flat .npz of weights (export_sb3_policy) that NumpyMLPPolicy replays with a
handful of matmuls. numpy is the only import here, on purpose — do not add others.
"""

import numpy as np

# ── Knob / action layout ───────────────────────────────────────────────────────
# Fixed knob order, shared everywhere. The first N_RECONNECT knobs force a TCP
# reconnect when actuated (broker port hop, broker IP hop, SCMC source-IP hop) and
# so carry an availability cost; padding and frequency are cheap (no reconnect).
KNOBS = ["port", "ip", "src", "pad", "freq"]
N_KNOBS = len(KNOBS)
N_RECONNECT = 3                       # port, ip, src
PAD_IDX = KNOBS.index("pad")
FREQ_IDX = KNOBS.index("freq")

# Availability cost charged per actuation, same order as KNOBS: the fraction of
# publishes disrupted by that knob firing (port/ip/src force a TCP reconnect;
# pad/freq are essentially free). Single source of truth for two consumers:
# mtd_env.Calibration.cost charges it in the RL reward, and monitor's
# compare_coordinators bills the *observed* actuations against it — both need
# the same five floats, and this module (numpy-only, host- and guest-importable)
# is where KNOBS itself already lives.
KNOB_COST = (0.15, 0.30, 0.30, 0.01, 0.01)   # port, ip, src, pad, freq

# Padding is a "regime" knob: sub-action 0 = keep the current regime, 1..K_PAD-1
# select a diversity level (more buckets = wider packet-size spread).
K_PAD = 4
# Frequency is a keep/rotate knob (like the address knobs): 0 = keep, 1 = rotate to
# a different publish interval. The value is chosen by the coordinator on actuation
# (round-robin over the pool), NOT encoded here — so the agent only decides *when*
# to retime, and actuating always yields a genuinely different interval.
K_FREQ = 2

# MultiDiscrete action: [port_hop, ip_hop, src_hop, pad_regime, freq_rotate].
ACTION_DIMS = [2, 2, 2, K_PAD, K_FREQ]

# ── Observation layout ─────────────────────────────────────────────────────────
# 15-dim float vector, all roughly in [0, 1]:
#   [0:5]   per-knob dwell      (ticks since the knob last fired, normalised)
#   [5:10]  per-knob hop rate   (EWMA of how often the knob fires, already [0,1])
#   [10:15] per-knob pool size  (number of options, normalised; <=1 ⇒ knob unusable)
OBS_DIM = 3 * N_KNOBS
DWELL_NORM = 30.0                     # dwell saturates at ~30 ticks
POOL_NORM = 8.0                       # pool size saturates at ~8 options

# Initial/decay constants for the dwell + EWMA-rate state, shared by the training
# env and the live coordinator so the policy sees identically-derived features.
DWELL_INIT = 30.0                     # start each knob "stale" (no recent hop)
EWMA_ALPHA = 0.1                      # hop-rate EWMA smoothing


def build_observation(dwell, rate, pool_sizes) -> np.ndarray:
    """Assemble the policy observation from live-observable state.

    Args:
        dwell:       len-5 array, ticks since each knob last fired.
        rate:        len-5 array, EWMA actuation rate per knob in [0, 1].
        pool_sizes:  len-5 array, number of options available per knob.

    Every input is computable both in the simulator and by the live coordinator,
    so the trained policy needs no information it cannot get in deployment.
    """
    dwell = np.asarray(dwell, dtype=np.float32)
    rate = np.asarray(rate, dtype=np.float32)
    pool = np.asarray(pool_sizes, dtype=np.float32)
    obs = np.concatenate([
        np.clip(dwell / DWELL_NORM, 0.0, 1.0),
        np.clip(rate, 0.0, 1.0),
        np.clip(pool / POOL_NORM, 0.0, 1.0),
    ]).astype(np.float32)
    return obs


def decode_action(action) -> dict:
    """Turn a MultiDiscrete action vector into an explicit knob command.

    Returns a dict:
        port, ip, src : bool   — actuate this reconnecting knob this tick
        pad_level     : int|None — new padding diversity level, or None to keep
        freq_rotate   : bool   — rotate to a different publish interval this tick
    """
    a = [int(x) for x in np.asarray(action).ravel()]
    pad_raw = a[PAD_IDX]
    return {
        "port": bool(a[0]),
        "ip": bool(a[1]),
        "src": bool(a[2]),
        # padding regime 0 = keep; 1..K_PAD-1 map to diversity levels 0..K_PAD-2
        "pad_level": (pad_raw - 1) if pad_raw > 0 else None,
        "freq_rotate": bool(a[FREQ_IDX]),
    }


# ── Numpy MLP policy (deployment-side inference) ────────────────────────────────

class NumpyMLPPolicy:
    """Replays an SB3 PPO MlpPolicy actor with numpy only (no torch).

    Loads the .npz produced by export_sb3_policy: a list of (W, b) hidden layers
    with tanh activations followed by a linear action head. predict() returns the
    greedy (argmax-per-subaction) MultiDiscrete action — deterministic, which is
    what we want for a deployed defender.
    """

    def __init__(self, hidden, out_w, out_b, action_dims):
        self.hidden = hidden          # list of (W, b) for the shared policy MLP
        self.out_w = out_w            # action head weight
        self.out_b = out_b            # action head bias
        self.action_dims = list(action_dims)

    @classmethod
    def load(cls, path: str) -> "NumpyMLPPolicy":
        data = np.load(path, allow_pickle=False)
        n_hidden = int(data["n_hidden"])
        hidden = [(data[f"h{i}_w"], data[f"h{i}_b"]) for i in range(n_hidden)]
        action_dims = [int(x) for x in data["action_dims"]]
        return cls(hidden, data["out_w"], data["out_b"], action_dims)

    def _forward(self, obs: np.ndarray) -> np.ndarray:
        x = np.asarray(obs, dtype=np.float32)
        for w, b in self.hidden:
            x = np.tanh(x @ w.T + b)
        return x @ self.out_w.T + self.out_b      # raw logits

    def predict(self, obs: np.ndarray) -> np.ndarray:
        """Greedy action: argmax within each MultiDiscrete sub-action's logits."""
        logits = self._forward(obs)
        action, off = [], 0
        for dim in self.action_dims:
            action.append(int(np.argmax(logits[off:off + dim])))
            off += dim
        return np.array(action, dtype=np.int64)


def export_sb3_policy(model, path: str) -> None:
    """Distil a trained SB3 PPO model's actor into a numpy .npz.

    Extracts the shared policy MLP (mlp_extractor.policy_net, Linear+Tanh stack)
    and the action head (action_net) from the torch state dict and stores them as
    plain arrays NumpyMLPPolicy can replay. Assumes the default tanh activation
    (set net_arch with activation_fn=Tanh in training, which is SB3's default).
    """
    import torch  # host-side only; never imported in the container

    sd = model.policy.state_dict()
    hidden_w, hidden_b = [], []
    i = 0
    # policy_net is a Sequential of (Linear, Tanh) pairs; collect each Linear.
    while f"mlp_extractor.policy_net.{i}.weight" in sd:
        hidden_w.append(sd[f"mlp_extractor.policy_net.{i}.weight"].cpu().numpy())
        hidden_b.append(sd[f"mlp_extractor.policy_net.{i}.bias"].cpu().numpy())
        i += 2  # skip the Tanh module between Linears

    out = {
        "n_hidden": np.int64(len(hidden_w)),
        "out_w": sd["action_net.weight"].cpu().numpy(),
        "out_b": sd["action_net.bias"].cpu().numpy(),
        "action_dims": np.array(ACTION_DIMS, dtype=np.int64),
    }
    for j, (w, b) in enumerate(zip(hidden_w, hidden_b)):
        out[f"h{j}_w"] = w
        out[f"h{j}_b"] = b
    np.savez(path, **out)
