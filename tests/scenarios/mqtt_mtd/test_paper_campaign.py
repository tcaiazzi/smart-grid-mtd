"""The paper campaign's reuse guard (cyberrange/scenarios/mqtt_mtd/campaign.py).

Regression: the "datasets + model present -> attack only" guard used to be
re-checked before every step, so once `train` had built the model the two
evaluations were skipped as if already done (and compare_coordinators lost
fingerprint_auc / nanogrid_recall). The guard is decided once per unit; each
evaluation is redone on its own when its predictions are missing.

Run: `.venv/bin/python -m unittest tests.test_paper_campaign`.
"""

import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.scenarios.mqtt_mtd import campaign as C   # noqa: E402


class ReuseGuard(unittest.TestCase):
    def setUp(self):
        self._root = C.REPO_ROOT
        C.REPO_ROOT = Path(tempfile.mkdtemp(prefix="paper-guard-"))
        self.ctx = C.RunCtx("output/run-0", 1, 0)
        self.unit = C.config_unit("fixed-timer", "fixed-timer MTD", 2, 2, ctx=self.ctx)
        self.exp = C.REPO_ROOT / "output/run-0" / C.slug(no_mtd=False, mbps=2)

    def tearDown(self):
        C.REPO_ROOT = self._root

    def step(self, sid):
        return next(s for s in self.unit.steps if s.id == sid)

    def touch(self, *rel):
        for r in rel:
            p = self.exp / r
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x")

    def test_fresh_build_runs_the_evaluations(self):
        self.unit.announce(lambda _line: None)          # unit start: nothing built yet
        self.assertFalse(self.step("datasets").skip_if())
        # ... datasets and train have now run:
        self.touch("datasets/train.pcap", "datasets/test.pcap", "model/model.pt")
        self.assertFalse(self.step("train").skip_if())
        self.assertFalse(self.step("evaluate").skip_if())
        self.assertFalse(self.step("evaluate-baseline-model").skip_if())

    def test_built_config_reruns_only_missing_evaluations(self):
        self.touch("datasets/train.pcap", "datasets/test.pcap", "model/model.pt",
                   "eval/model-mtd/predictions.csv")
        self.unit.announce(lambda _line: None)
        for sid in ("clean", "datasets", "train", "evaluate"):
            self.assertTrue(self.step(sid).skip_if(), sid)
        self.assertFalse(self.step("evaluate-baseline-model").skip_if())


if __name__ == "__main__":
    unittest.main()
