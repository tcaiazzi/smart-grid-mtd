"""Regression test for experiment seeding (--seed / make SEED=...).

A seeded run must reproduce every random draw the platform controls: the MTD
coordinators' per-knob draws (announce delays, padding subsets, frequency
choice), the SCMC executor's padding and publish jitter, the microgrid sensor
noise, and the attacker CNN's weight init + batch shuffling. TLS, the
QKD-simulated key and container timing stay random by design and are not
covered here.

The coordinators draw from several threads at once, so they hold one RNG per
knob: the per-knob sequence must not depend on how those threads interleave.
That is checked directly below by drawing in two different orders.

Runs on the host without Docker (guest modules are imported from their source
dirs, as test_guest_imports does from a staged copy). Run with
`.venv/bin/python -m unittest tests.test_seeding` or `python -m unittest`.
"""

import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "defense_plane" / "agents"))
sys.path.insert(0, str(REPO_ROOT / "traffic_generator" / "agents"))

from mtd_coordinator import SEMPCoordinator  # noqa: E402
from mtd_executor import SCMCExecutor  # noqa: E402
from microgrid_sim import build_microgrid, sensor_rng, step_microgrid  # noqa: E402

from network_scenario.run_experiment import role_seed, seed_arg  # noqa: E402

KNOBS = ("hop", "pad", "src", "freq")


def _coordinator(seed):
    return SEMPCoordinator(
        9998, ["10.1.0.2", "10.1.0.4"], [8883, 8884], 2.0, no_nat=True,
        pad_buckets=[128, 256, 384, 512], scmc_ip_pool=["10.0.0.2", "10.0.0.4"],
        freq_pool=[0.2, 0.5, 1.0], seed=seed,
    )


def _executor(seed):
    return SCMCExecutor("scmc1", "10.1.0.2", 8883, "10.1.0.2", 9998,
                        pad_buckets=[128, 256, 384, 512, 1024], seed=seed)


def _draw(rng, knob, n=20):
    return [rng[knob].randint(5, 15) for _ in range(n)]


class RoleSeedTest(unittest.TestCase):
    def test_stable_and_distinct_per_role(self):
        seeds = {r: role_seed(7, r) for r in ("train", "test", "attack")}
        self.assertEqual(seeds, {r: role_seed(7, r) for r in seeds})
        self.assertEqual(len(set(seeds.values())), 3)
        self.assertNotEqual(role_seed(7, "train"), role_seed(8, "train"))

    def test_unseeded(self):
        self.assertIsNone(role_seed(None, "train"))
        self.assertEqual(seed_arg(None), "")
        self.assertEqual(seed_arg(42), " --seed 42")


class CoordinatorSeedTest(unittest.TestCase):
    def test_per_knob_sequence_ignores_draw_order(self):
        a, b = _coordinator(7), _coordinator(7)
        seq_a = {k: _draw(a._rng, k) for k in KNOBS}
        seq_b = {k: _draw(b._rng, k) for k in reversed(KNOBS)}
        self.assertEqual(seq_a, seq_b)

    def test_knobs_and_seeds_differ(self):
        a = _coordinator(7)
        self.assertNotEqual(_draw(a._rng, "pad"), _draw(a._rng, "freq"))
        self.assertNotEqual(_draw(_coordinator(7)._rng, "hop"),
                            _draw(_coordinator(8)._rng, "hop"))


class ExecutorSeedTest(unittest.TestCase):
    def _trace(self, ex, n=30):
        obj = {"value": 1.0}
        sizes = [len(ex._pad_payload(obj)) for _ in range(n)]
        jitter = [ex._rng.uniform(-0.05, 0.05) for _ in range(n)]
        values = [{k: v for k, v in step_microgrid(ex.mg, "scmc1", ex._noise_rng).items()
                   if k != "timestamp"} for _ in range(n)]
        return sizes, jitter, values

    def test_same_seed_same_trace(self):
        self.assertEqual(self._trace(_executor(7)), self._trace(_executor(7)))

    def test_different_seed_different_trace(self):
        self.assertNotEqual(self._trace(_executor(7)), self._trace(_executor(8)))

    def test_sensor_noise(self):
        def run(seed):
            mg, rng = build_microgrid(), sensor_rng(seed)
            return [(r["frequency"], r["voltage"])
                    for r in (step_microgrid(mg, "scmc1", rng) for _ in range(20))]
        self.assertEqual(run(3), run(3))
        self.assertNotEqual(run(3), run(4))


class ClassifierSeedTest(unittest.TestCase):
    @staticmethod
    def _frame():
        from attack_plane.classify import FEATURE_COLS
        rng = np.random.default_rng(0)
        n = 400
        df = pd.DataFrame(rng.normal(size=(n, len(FEATURE_COLS))), columns=FEATURE_COLS)
        df["is_nanogrid"] = (np.arange(n) % 4 == 0).astype(int)
        df["flow_key"] = [f"f{i % 8}" for i in range(n)]
        df["src_ip"] = [f"10.0.0.{i % 8}" for i in range(n)]
        df["timestamp"] = np.arange(n, dtype=float)
        return df

    def _weights(self, seed):
        import torch
        from attack_plane.classify import train_classifier
        model, _ = train_classifier(self._frame(), window_size=8, epochs=2,
                                    device=torch.device("cpu"), seed=seed)
        return np.concatenate([p.detach().numpy().ravel() for p in model.parameters()])

    def test_same_seed_same_weights(self):
        np.testing.assert_array_equal(self._weights(5), self._weights(5))

    def test_different_seed_different_weights(self):
        self.assertFalse(np.array_equal(self._weights(5), self._weights(6)))


if __name__ == "__main__":
    unittest.main()
