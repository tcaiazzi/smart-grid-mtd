#!/usr/bin/env python3
"""
mtd_rl_coordinator.py — RL-driven MTD coordinator, runs on SEMP.

A drop-in alternative to mtd_coordinator.py that decides MTD actions with a trained
RL policy instead of fixed timers. It SUBCLASSES SEMPCoordinator and overrides only
the decision logic — every piece of hard-won machinery (iptables NAT management,
make-before-break port vacating, the hop watchdog + rollback / HOP_FAILED handling,
the ACK/DONE bookkeeping, the control TCP server) is inherited unchanged. The
executors and the wire protocol are identical, so the same SCMC executor works with
either coordinator.

Where the base coordinator runs five independent fixed-timer loops, this runs ONE
policy loop: every base tick it builds the same observation the training env used
(rl_policy.build_observation), asks the policy for an action, and emits the
corresponding control messages (SCHEDULE_HOP / SCHEDULE_SRC_HOP / SET_PADDING /
SET_INTERVAL) — or nothing, when the policy chooses to hold.

Inference is numpy-only (rl_policy.NumpyMLPPolicy over a distilled policy.npz): the
lab container image has numpy but not torch/gymnasium/stable-baselines3, so it never
loads the SB3 .zip. Train + export with train_rl_coordinator.py on the host.

Usage:
  python3 mtd_rl_coordinator.py --policy policy.npz \\
      --control-port 9998 --ip-pool 10.1.0.2,10.1.0.4 \\
      --port-pool 8883,8884,8885 --real-port 18883 \\
      --scmc-ip-pool 10.0.0.2,10.0.0.4 \\
      --pad-buckets 128,256,512,1024 --freq-pool 0.2,0.5,1.0 --tick 1.0
  # add --no-nat for host testing without iptables
"""

import argparse
import random
import threading
import time

import numpy as np

from mtd_coordinator import SEMPCoordinator
from rl_policy import (
    DWELL_INIT,
    EWMA_ALPHA,
    K_PAD,
    N_KNOBS,
    NumpyMLPPolicy,
    build_observation,
    decode_action,
)


class RLSEMPCoordinator(SEMPCoordinator):
    """SEMPCoordinator whose schedule is set by a trained policy, not timers."""

    def __init__(self, *args, policy_path: str, tick_interval: float = 1.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.policy = NumpyMLPPolicy.load(policy_path)
        self.tick_interval = tick_interval

        # Per-knob decision state, derived exactly as in mtd_env so the policy sees
        # the features it was trained on. Order: port, ip, src, pad, freq.
        self._dwell = np.full(N_KNOBS, DWELL_INIT, dtype=np.float32)
        self._rate = np.zeros(N_KNOBS, dtype=np.float32)
        self._pool_sizes = np.array([
            len(self.port_pool),
            len(self.ip_pool),
            max(len(self.scmc_ip_pool), 1),
            max(len(self.pad_buckets), 1),
            max(len(self.freq_pool), 1),
        ], dtype=np.float32)
        self._freq_idx = 0       # current publish-interval index (round-robin)
        print(f"[rl-coordinator] loaded policy {policy_path}  pools={self._pool_sizes.astype(int).tolist()}",
              flush=True)

    # ── action emitters (mirror the base coordinator's loop bodies) ──
    # Each returns whether it actually emitted, so dwell/rate only update on a real
    # actuation (a knob skipped due to an in-flight action or single-option pool is
    # treated as "did not fire").

    def _emit_broker_hop(self, do_port: bool, do_ip: bool) -> tuple:
        """Emit one SCHEDULE_HOP advancing port and/or broker IP. Returns
        (port_fired, ip_fired)."""
        with self._lock:
            if not self._clients or self._pending_done:
                return (False, False)          # no clients, or a hop is in flight
            new_ip, new_port = self.current_ip, self.current_port
            if do_ip and len(self.ip_pool) > 1:
                idx = (self.ip_pool.index(self.current_ip) + 1) % len(self.ip_pool)
                new_ip = self.ip_pool[idx]
            if do_port and len(self.port_pool) > 1:
                idx = (self.port_pool.index(self.current_port) + 1) % len(self.port_pool)
                new_port = self.port_pool[idx]

            ip_changed = new_ip != self.current_ip
            port_changed = new_port != self.current_port
            if not (ip_changed or port_changed):
                return (False, False)
            action = ("both" if ip_changed and port_changed else
                      "ip_hop" if ip_changed else "port_hop")

            self._seq += 1
            seq = self._seq
            in_messages = random.randint(5, 15)
            self._pending_done[seq] = set(self._clients.keys())
            self._hop_old_port[seq] = self.current_port
            self._hop_new_port[seq] = new_port
            self._hop_succeeded[seq] = set()
            self._hop_endpoints[seq] = (self.current_ip, self.current_port, new_ip, new_port)
            self._hop_deadline[seq] = time.monotonic() + self.hop_timeout + in_messages
            self.current_ip, self.current_port = new_ip, new_port

        self._nat_add(new_port)              # open new port before clients migrate
        self._broadcast({
            "type": "SCHEDULE_HOP", "seq": seq, "action": action,
            "new_ip": new_ip, "new_port": new_port, "in_messages": in_messages,
        })
        print(f"[rl-coordinator] SCHEDULE_HOP seq={seq} action={action} "
              f"→ {new_ip}:{new_port} in {in_messages} msgs", flush=True)
        return (port_changed, ip_changed)

    def _emit_src_hop(self) -> bool:
        with self._lock:
            if not self._clients or self._pending_src_done:
                return False
            if len(self.scmc_ip_pool) < 2:
                return False
            idx = (self.scmc_ip_pool.index(self.current_src_ip) + 1) % len(self.scmc_ip_pool)
            new_src_ip = self.scmc_ip_pool[idx]
            self.current_src_ip = new_src_ip
            self._seq += 1
            seq = self._seq
            in_messages = random.randint(5, 15)
            self._pending_src_done[seq] = set(self._clients.keys())

        self._broadcast({
            "type": "SCHEDULE_SRC_HOP", "seq": seq,
            "new_src_ip": new_src_ip, "in_messages": in_messages,
        })
        print(f"[rl-coordinator] SCHEDULE_SRC_HOP seq={seq} → src {new_src_ip} "
              f"in {in_messages} msgs", flush=True)
        return True

    def _emit_padding(self, level: int) -> bool:
        """Announce a padding regime whose bucket count scales with `level`
        (0..K_PAD-2): higher level = more buckets = more packet-size diversity."""
        with self._lock:
            if not self._clients or self._pending_pad_done:
                return False
            if not self.pad_buckets:
                return False
            frac = (level + 1) / (K_PAD - 1)
            k = max(1, min(len(self.pad_buckets), round(frac * len(self.pad_buckets))))
            buckets = sorted(random.sample(self.pad_buckets, k))
            self._seq += 1
            seq = self._seq
            in_messages = random.randint(5, 15)
            self._pending_pad_done[seq] = set(self._clients.keys())

        self._broadcast({
            "type": "SET_PADDING", "seq": seq,
            "buckets": buckets, "in_messages": in_messages,
        })
        print(f"[rl-coordinator] SET_PADDING seq={seq} buckets={buckets} "
              f"in {in_messages} msgs", flush=True)
        return True

    def _emit_interval(self) -> bool:
        """Rotate the publish interval to the NEXT value in freq_pool (round-robin).

        Like the address knobs, actuating freq always moves to a different value, so
        the agent only decides *when* to retime; this is what gives the inter-arrival
        timing real on-wire variety (a fixed level→value map would freeze it)."""
        with self._lock:
            if not self._clients or self._pending_freq_done:
                return False
            if len(self.freq_pool) < 2:
                return False
            self._freq_idx = (self._freq_idx + 1) % len(self.freq_pool)
            new_interval = self.freq_pool[self._freq_idx]
            self._seq += 1
            seq = self._seq
            in_messages = random.randint(5, 15)
            self._pending_freq_done[seq] = set(self._clients.keys())

        self._broadcast({
            "type": "SET_INTERVAL", "seq": seq,
            "interval": new_interval, "in_messages": in_messages,
        })
        print(f"[rl-coordinator] SET_INTERVAL seq={seq} interval={new_interval}s "
              f"in {in_messages} msgs", flush=True)
        return True

    # ── policy decision loop (replaces the five fixed-timer loops) ──

    def _policy_loop(self) -> None:
        while True:
            time.sleep(self.tick_interval)

            with self._lock:
                has_clients = bool(self._clients)
            if not has_clients:
                print("[rl-coordinator] no clients — idle", flush=True)
                continue

            obs = build_observation(self._dwell, self._rate, self._pool_sizes)
            cmd = decode_action(self.policy.predict(obs))

            fired = np.zeros(N_KNOBS, dtype=np.float32)
            if cmd["port"] or cmd["ip"]:
                pf, iff = self._emit_broker_hop(cmd["port"], cmd["ip"])
                fired[0] = 1.0 if pf else 0.0
                fired[1] = 1.0 if iff else 0.0
            if cmd["src"] and self._emit_src_hop():
                fired[2] = 1.0
            if cmd["pad_level"] is not None and self._emit_padding(cmd["pad_level"]):
                fired[3] = 1.0
            if cmd["freq_rotate"] and self._emit_interval():
                fired[4] = 1.0

            self._dwell = np.where(fired > 0, 0.0, self._dwell + 1.0)
            self._rate = (1.0 - EWMA_ALPHA) * self._rate + EWMA_ALPHA * fired

    def run(self) -> None:
        # Same bring-up as the base coordinator, but the decision driver is the
        # policy loop instead of the timer loops. The watchdog is still essential.
        self._nat_add(self.current_port)
        threading.Thread(target=self._serve, daemon=True).start()
        threading.Thread(target=self._hop_watchdog_loop, daemon=True).start()
        try:
            self._policy_loop()
        finally:
            for port in list(self._active_nat):
                self._nat_del(port)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="RL-driven MTD coordinator — runs on SEMP")
    parser.add_argument("--policy", required=True,
                        help="Path to the distilled numpy policy (.npz)")
    parser.add_argument("--tick", type=float, default=1.0,
                        help="Seconds between policy decisions (default: 1.0)")
    parser.add_argument("--control-port", type=int, default=9998)
    parser.add_argument("--ip-pool", default="10.1.0.2")
    parser.add_argument("--port-pool", default="8883,8884,8885")
    parser.add_argument("--real-port", type=int, default=18883)
    parser.add_argument("--hop-timeout", type=float, default=10.0)
    parser.add_argument("--no-nat", action="store_true")
    parser.add_argument("--pad-buckets", default="256,512,1024")
    parser.add_argument("--scmc-ip-pool", default="")
    parser.add_argument("--freq-pool", default="1.0")
    # Accepted for CLI compatibility with mtd_coordinator.py but unused here: the
    # policy decides timing, so the fixed per-knob intervals do not apply.
    parser.add_argument("--hop-interval", type=float, default=30.0)
    parser.add_argument("--pad-interval", type=float, default=30.0)
    parser.add_argument("--src-hop-interval", type=float, default=30.0)
    parser.add_argument("--freq-interval", type=float, default=30.0)
    args = parser.parse_args()

    ip_pool = [x.strip() for x in args.ip_pool.split(",") if x.strip()]
    port_pool = [int(x.strip()) for x in args.port_pool.split(",") if x.strip()]
    pad_buckets = [int(x) for x in args.pad_buckets.split(",") if x.strip()]
    scmc_ip_pool = [x.strip() for x in args.scmc_ip_pool.split(",") if x.strip()]
    freq_pool = [float(x) for x in args.freq_pool.split(",") if x.strip()]

    RLSEMPCoordinator(
        args.control_port, ip_pool, port_pool, args.hop_interval,
        real_port=args.real_port, no_nat=args.no_nat,
        pad_buckets=pad_buckets, pad_interval=args.pad_interval,
        scmc_ip_pool=scmc_ip_pool, src_hop_interval=args.src_hop_interval,
        freq_pool=freq_pool, freq_interval=args.freq_interval,
        hop_timeout=args.hop_timeout,
        policy_path=args.policy, tick_interval=args.tick,
    ).run()


if __name__ == "__main__":
    main()
