"""run_cli, the command-line wrapper every campaign shares.

The three campaign entry points (main.py, the CPS campaign, the MQTT ablation)
all exit through it, and campaigns chain on those exit codes: a wrong one
either stops a sweep that should go on, or lets one go on into a missing lab.
Nothing here deploys anything; the preflight is replaced where it would run.

Run: `.venv/bin/python -m pytest tests/core/test_campaign_cli.py`
"""

import json
import os
import tempfile
import time
import unittest
from unittest import mock

from cyberrange.core import campaign as campaign_mod
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


def scored_campaign(metrics, steps_before=(), retries=0, aggregate=None, resume=False, root=None):
    """One scored step (a run that leaves nothing behind) after ``steps_before``."""
    root = root or tempfile.mkdtemp(prefix="core-score-")
    scored = Step(
        "run",
        run=lambda emit: None,
        run_dir=os.path.join(root, "runs", "r1"),
        metrics=metrics,
        retries=retries,
        label={"run_id": "r1"},
    )
    units = [Unit("u1", [*steps_before, scored]), Unit("u2", [Step("after", run=lambda e: None)])]
    return Campaign("t", root, units, out=lambda _line: None, aggregate=aggregate, resume=resume)


class Scoring(unittest.TestCase):
    def test_a_run_that_cannot_be_scored_fails_alone(self):
        def broken(run_dir):
            raise ValueError("no telemetry in the run directory")

        res = scored_campaign(broken).run()
        self.assertEqual(
            (res["status"], res["failed"], res["failed_units"]),
            ("done_with_failures", 1, ["u1"]),
            "an unreadable run directory ended the campaign instead of failing its own run",
        )
        self.assertEqual(res["ok"], 1, "the unit after the broken run did not run")

    def test_a_failing_summary_does_not_end_the_campaign(self):
        def broken(root, rows):
            raise OSError("disk full")

        res = scored_campaign(lambda d: {"x": 1}, aggregate=broken).run()
        self.assertEqual(res["status"], "done", "a summary that cannot be written lost the runs")

    def test_negative_retries_still_run_the_step(self):
        ran = []
        root = tempfile.mkdtemp(prefix="core-retry-")
        step = Step("a", run=lambda emit: ran.append(1), retries=-1)
        Campaign("t", root, [Unit("u", [step])], out=lambda _line: None).run()
        self.assertEqual(ran, [1], "a negative retry count reported a step that never ran as ok")

    def test_a_nonzero_exit_code_from_a_run_fails_the_step(self):
        root = tempfile.mkdtemp(prefix="core-rc-")
        res = Campaign(
            "t", root, [Unit("u", [Step("a", run=lambda emit: 1)])], out=lambda _line: None
        ).run()
        self.assertEqual(res["failed"], 1, "an invalid run (exit code 1) was counted as ok")

    def test_reused_runs_are_summarised_even_next_to_fresh_steps(self):
        """A resumed campaign whose runs are all scored still has plot and
        manifest steps that succeed; they must not suppress the summary."""
        root = tempfile.mkdtemp(prefix="core-resume-")
        scored_campaign(lambda d: {"x": 1}, root=root).run()
        seen = []

        def aggregate(root, rows):
            seen.append([r["run_id"] for r in rows])
            return {}

        scored_campaign(
            lambda d: {"x": 1},
            steps_before=[Step("plot", run=lambda e: None)],
            aggregate=aggregate,
            resume=True,
            root=root,
        ).run()
        self.assertEqual(seen, [["r1"]], "the summary was not refreshed from the reused runs")


class CommandTimeout(unittest.TestCase):
    def test_a_hung_command_is_stopped_with_its_children_and_retried(self):
        root = tempfile.mkdtemp(prefix="core-timeout-")
        marker = os.path.join(root, "child-survived")
        # A shell that starts a child and waits: the child writes the marker
        # only if it outlives the timeout.
        hung = ["sh", "-c", f"(sleep 3; touch {marker}) & wait"]
        step = Step("lab", cmd=hung, timeout=0.5, retries=1)
        t0 = time.time()
        # Short graces: the child of a non-interactive shell ignores SIGINT, so
        # this also walks the escalation to SIGTERM.
        fast = tuple((sig, 0.3) for sig, _grace in campaign_mod.STOP_SIGNALS)
        with mock.patch.object(campaign_mod, "STOP_SIGNALS", fast):
            res = Campaign("t", root, [Unit("u", [step])], out=lambda _line: None).run()
        self.assertLess(time.time() - t0, 3, "the campaign waited for the hung command")
        self.assertEqual((res["ok"], res["failed"]), (0, 1))
        with open(os.path.join(root, "progress.jsonl")) as f:
            kinds = [json.loads(line)["kind"] for line in f]
        self.assertEqual(
            1, kinds.count("step_retry"), "a timed-out step was not retried like any failed one"
        )
        time.sleep(3)
        self.assertFalse(
            os.path.exists(marker),
            "the command was stopped but what it started kept running: a make target "
            "killed alone leaves its lab run behind",
        )

    def test_a_command_within_its_time_is_untouched(self):
        root = tempfile.mkdtemp(prefix="core-timeout-")
        res = Campaign(
            "t", root, [Unit("u", [Step("a", cmd=["true"], timeout=30)])], out=lambda _line: None
        ).run()
        self.assertEqual((res["status"], res["ok"]), ("done", 1))
