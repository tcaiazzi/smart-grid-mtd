"""Regression test for run_experiment's "did the SCMC publish?" gate.

A lab run whose SCMC publisher dies at startup still produces a capture (the
background replay alone), and Make's order-only rules would then keep and train
on it. run_experiment therefore counts the publishes in the downloaded client
log and, if there are none, deletes the run's capture and exits non-zero (so
main.py retries it). The log lines below are verbatim formats of the two
publishers (mtd_executor, simple_client).

Run with `.venv/bin/python -m unittest tests.test_run_validation`.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from network_scenario.run_experiment import (  # noqa: E402
    check_published,
    count_publishes,
    with_console_log,
)

EXECUTOR_LOG = """\
2026-10-08T11:26:39  [scmc1] Building microgrid simulator...
2026-10-08T11:26:39  [scmc1] ctrl → 10.1.0.2:9998
2026-10-08T11:26:39  [scmc1] MQTT → 10.1.0.2:8883 (ok)
2026-10-08T11:26:39  [scmc1] #1 → 10.1.0.2:8883  power=  84.6 kW  freq=49.6003 Hz  volt=229.03 V  pad=[off]
2026-10-08T11:26:40  [scmc1] SET_PADDING seq=1  buckets=[128, 256]  in 10 msgs
2026-10-08T11:26:40  [scmc1] #2 → 10.1.0.2:8883  power=  64.4 kW  freq=49.8552 Hz  volt=225.71 V  pad=[off]
"""
SIMPLE_CLIENT_LOG = """\
2026-06-26 10:00:00,000  [scmc1] Connected to broker
2026-06-26 10:00:01,000  [scmc1] power=  84.6 kW  freq=49.6003 Hz  volt=229.03 V
"""
DEAD_EXECUTOR_LOG = """\
2026-10-08T11:28:11  [scmc1] Building microgrid simulator...
2026-10-08T11:28:11  [scmc1] ctrl → 10.1.0.2:9998
"""


class PublishGateTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_counts_both_publishers(self):
        self.assertEqual(count_publishes(self._write("e.log", EXECUTOR_LOG)), 2)
        self.assertEqual(count_publishes(self._write("s.log", SIMPLE_CLIENT_LOG)), 1)

    def test_dead_or_missing_log_counts_zero(self):
        self.assertEqual(count_publishes(self._write("d.log", DEAD_EXECUTOR_LOG)), 0)
        self.assertEqual(count_publishes(os.path.join(self.dir, "missing.log")), 0)

    def test_failed_run_discards_capture(self):
        pcap = self._write("train.pcap", "x")
        self.assertFalse(check_published(self._write("d.log", DEAD_EXECUTOR_LOG), [pcap]))
        self.assertFalse(os.path.exists(pcap))

    def test_good_run_keeps_capture(self):
        pcap = self._write("train.pcap", "x")
        self.assertTrue(check_published(self._write("e.log", EXECUTOR_LOG), [pcap]))
        self.assertTrue(os.path.exists(pcap))


class ConsoleLogTest(unittest.TestCase):
    def test_wraps_and_redirects(self):
        cmd = with_console_log("timeout 30 python3 mtd_executor.py --seed 1", "client.console.log")
        self.assertEqual(
            cmd,
            'bash -c "PYTHONUNBUFFERED=1 timeout 30 python3 mtd_executor.py --seed 1 '
            '> client.console.log 2>&1"',
        )


if __name__ == "__main__":
    unittest.main()
