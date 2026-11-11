"""run_cli, the command-line wrapper every campaign shares.

The three campaign entry points (main.py, the CPS campaign, the MQTT ablation)
all exit through it, and campaigns chain on those exit codes: a wrong one
either stops a sweep that should go on, or lets one go on into a missing lab.
Nothing here deploys anything; the preflight is replaced where it would run.

Run: `.venv/bin/python -m pytest tests/core/test_campaign_cli.py`
"""

import tempfile
import unittest
from unittest import mock

from cyberrange.core import lifecycle
from cyberrange.core.campaign import Campaign, Step, Unit, format_result, run_cli


def campaign(fail=False, lines=None):
    def run(emit):
        if fail:
            raise RuntimeError("step failed")

    root = tempfile.mkdtemp(prefix="core-cli-")
    units = [Unit("u", [Step("a", run=run)])]
    return Campaign("t", root, units, out=(lines.append if lines is not None else print))


class RunCli(unittest.TestCase):
    def test_exit_codes_follow_the_outcome(self):
        self.assertEqual(0, run_cli(campaign(), preflight=False, out=lambda _: None))
        self.assertEqual(1, run_cli(campaign(fail=True), preflight=False, out=lambda _: None))

    def test_no_lab_stops_before_any_unit(self):
        ran = []
        c = campaign()
        c.units[0].steps[0].run = lambda emit: ran.append(1)
        lines = []
        boom = lifecycle.LabUnavailable("docker is not running")
        with mock.patch.object(lifecycle, "preflight", side_effect=boom):
            code = run_cli(c, out=lines.append)
        self.assertEqual(lifecycle.EXIT_NO_LAB, code, "a script cannot tell 'no lab' apart")
        self.assertEqual([], ran, "a unit ran although no lab could start")
        self.assertEqual(["cannot start: docker is not running"], lines)

    def test_preflight_false_never_checks_for_a_lab(self):
        with mock.patch.object(lifecycle, "preflight", side_effect=AssertionError) as pf:
            run_cli(campaign(), preflight=False, out=lambda _: None)
        pf.assert_not_called()

    def test_epilogue_is_said_before_the_verdict(self):
        lines = []
        run_cli(
            campaign(),
            preflight=False,
            out=lines.append,
            epilogue=lambda res: [f"figure for {res['status']}"],
        )
        self.assertEqual("figure for done", lines[0])
        self.assertTrue(lines[1].startswith("=== done (ok=1 failed=0 skipped=0)"), lines)

    def test_a_custom_report_replaces_the_verdict(self):
        lines = []
        run_cli(campaign(), preflight=False, out=lines.append, report=lambda res: "custom")
        self.assertEqual(["custom"], lines)

    def test_every_report_line_goes_through_out(self):
        lines = []
        run_cli(campaign(fail=True), preflight=False, out=lambda line: lines.append(f"[p] {line}"))
        self.assertEqual(2, len(lines), "a multi-line verdict reached out() as one call")
        self.assertEqual("[p] failed or blocked: u", lines[1])

    def test_failed_units_are_named(self):
        res = {"status": "done_with_failures", "ok": 0, "failed": 1, "skipped": 0}
        text = format_result({**res, "root": "r", "failed_units": ["u"]})
        self.assertIn("failed or blocked: u", text)


class DryRunGrid(unittest.TestCase):
    def test_rows_and_total(self):
        lines = []
        root = tempfile.mkdtemp(prefix="core-cli-")
        steps = [
            Step(f"s{i}", run=lambda emit: None, run_dir=root, metrics=dict, planned_s=60.0)
            for i in range(3)
        ]
        c = Campaign("t", root, [Unit("u", steps)], out=lines.append)
        grid = c.dry_run_grid(row=lambda s: f"<{s.id}>")
        self.assertEqual(3, len(grid))
        self.assertTrue(lines[1].startswith("  s0") and "<s0> ~60s" in lines[1], lines[1])
        self.assertEqual("3 runs, ~3.0 min planned", lines[-1])
        self.assertEqual(180.0, c.planned_total_s())


if __name__ == "__main__":
    unittest.main()
