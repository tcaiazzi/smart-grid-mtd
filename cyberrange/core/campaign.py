"""campaign.py — a campaign is units of steps, run in order, on one ledger.

    Unit   one configuration x one repetition (e.g. "manual-hijack, seed 3", or
           "fixed-timer MTD, run 2"); its steps run in order, and a failed step
           stops the rest of its unit. ``needs`` names units that must have
           succeeded first (e.g. the cross-model attack needs the baseline model).
    Step   one thing to do, either
             - in-process: ``run(emit)`` (a scenario run gets the ledger emitter
               bound to its run id), or
             - a command: ``cmd`` run from the repository root (e.g. a make target),
               killed with everything it spawned after ``timeout`` seconds;
           ``skip_if()`` -> True reuses earlier results (nothing to do);
           a *scored* step (``run_dir`` + ``metrics``) is a lab run whose metrics
           are computed when it ends, kept in <run_dir>/metrics.json (also what
           a resumed campaign skips on) and folded into the aggregate.

Ledger events (on <root>/progress.jsonl; the dashboard follows it live):

    campaign_start{name, scenario, grid, params, planned_run_s, planned_total_s, units}
    unit_start{unit, group} / unit_blocked{unit, needs}
    scored steps   run_skipped{metrics} | run_start..run_end (from the run) ->
                   run_retry{attempt, error} -> run_failed | run_metrics{metrics}
                   -> aggregate{...} | aggregate_failed{error}
    other steps    step_start / step_end{ok, duration_s} / step_skipped /
                   step_retry / step_failed
    campaign_end{status=done|done_with_failures|interrupted, ok, failed, skipped}
"""

import json
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from cyberrange.core.progress import ProgressLog
from cyberrange.core import lifecycle, paths

log = logging.getLogger("core.campaign")

REPO_ROOT = paths.REPO_ROOT
# How a timed-out command is stopped: each signal, then the seconds it is given.
STOP_SIGNALS = ((signal.SIGINT, 60.0), (signal.SIGTERM, 10.0), (signal.SIGKILL, 10.0))


class StepFailed(RuntimeError):
    pass


@dataclass
class Step:
    id: str
    run: Optional[Callable] = None  # run(emit) in-process
    cmd: Optional[List[str]] = None  # or a command, from the repo root
    skip_if: Optional[Callable[[], bool]] = None
    retries: int = 0
    timeout: Optional[float] = None  # s a command may take (None = no limit)
    run_dir: Optional[str] = None  # scored step: metrics land here
    metrics: Optional[Callable[[str], dict]] = None
    report: Optional[Callable[[dict], str]] = None  # metrics.md
    label: dict = field(default_factory=dict)  # mode, seed, ... on every event
    info: dict = field(default_factory=dict)  # extra grid fields (not on events)
    planned_s: float = 0.0
    dry: bool = True  # print/do in a dry run (cmd steps only)

    @property
    def scored(self):
        return self.run_dir is not None and self.metrics is not None

    def describe(self):
        return " ".join(self.cmd) if self.cmd else f"<{self.id}>"


@dataclass
class Unit:
    id: str
    steps: List[Step]
    needs: List[str] = field(default_factory=list)
    group: Optional[str] = None
    header: object = None  # str, or callable -> str, announced first

    def announce(self, out):
        h = self.header() if callable(self.header) else self.header
        if h:
            out(h)


class Campaign:
    def __init__(
        self, name, root, units, params=None, resume=True, aggregate=None, out=print, scenario=None
    ):
        """``aggregate(root, rows) -> dict`` refreshes the campaign's summary
        files from the scored rows ({"run_id", "metrics", **label}) and returns
        what the ``aggregate`` ledger event carries."""
        self.name, self.root, self.units = name, root, list(units)
        self.params = dict(params or {})
        self.resume, self.aggregate_fn, self.out = resume, aggregate, out
        self.scenario = scenario

    # ── description ──────────────────────────────────────────────────────────
    def scored_steps(self):
        return [s for u in self.units for s in u.steps if s.scored]

    def grid(self):
        return [{**s.label, **s.info} for s in self.scored_steps()]

    def planned(self):
        return {s.label.get("run_id", s.id): s.planned_s for s in self.scored_steps()}

    def planned_total_s(self):
        return sum(s.planned_s for s in self.scored_steps())

    def dry_run_grid(self, row=None, out=None):
        """Print the grid and the time it is expected to take, without the
        commands: for a campaign of in-process runs there are no command lines
        to show, only what will run and for how long.

        ``row(step) -> str`` is the scenario's own column — what distinguishes
        one entry of its grid from another. The core has no opinion on it.
        """
        out = out or self.out
        steps = self.scored_steps()
        out(f"campaign {self.name!r} -> {self.root}")
        for s in steps:
            extra = f"{row(s)} " if row else ""
            out(f"  {s.id:<28} {extra}~{s.planned_s:.0f}s")
        out(f"{len(steps)} runs, ~{self.planned_total_s() / 60:.1f} min planned")
        return self.grid()

    def dry_run(self):
        """Print what would run (steps whose reuse check says "done" are left
        out, as a real run would skip them). Creates nothing."""
        for u in self.units:
            u.announce(self.out)
            for s in u.steps:
                if s.cmd is None or not s.dry or (s.skip_if and s.skip_if()):
                    continue
                if s.scored and self.resume and _load_metrics(s.run_dir) is not None:
                    continue
                self.out("  DRY: " + s.describe())
        return self.grid()

    # ── execution ────────────────────────────────────────────────────────────
    def run(self):
        os.makedirs(self.root, exist_ok=True)
        with open(os.path.join(self.root, "campaign.json"), "w") as f:
            json.dump(
                {
                    "name": self.name,
                    "grid": self.grid(),
                    "params": self.params,
                    "units": [
                        {
                            "id": u.id,
                            "group": u.group,
                            "needs": u.needs,
                            "steps": [s.id for s in u.steps],
                        }
                        for u in self.units
                    ],
                },
                f,
                indent=2,
                default=str,
            )
        ledger = ProgressLog(os.path.join(self.root, "progress.jsonl"))
        planned = self.planned()
        ledger.emit(
            "campaign_start",
            name=self.name,
            scenario=self.scenario,
            grid=self.grid(),
            params=self.params,
            planned_run_s=planned,
            planned_total_s=round(sum(planned.values()), 1),
            units=[u.id for u in self.units],
        )
        rows, done_units, failed_units = [], set(), set()
        counts = {"ok": 0, "failed": 0, "skipped": 0}
        status = "interrupted"
        self._aggregate_stale = False
        try:
            for u in self.units:
                missing = [n for n in u.needs if n not in done_units]
                if missing:
                    ledger.emit("unit_blocked", unit=u.id, needs=missing)
                    failed_units.add(u.id)
                    continue
                u.announce(self.out)
                ledger.emit("unit_start", unit=u.id, group=u.group)
                ok = all(self._step(ledger, u, s, rows, counts) for s in u.steps)
                (done_units if ok else failed_units).add(u.id)
            status = "done" if not failed_units else "done_with_failures"
        finally:
            # Rows reused from an earlier campaign have not been folded in yet.
            if self._aggregate_stale:
                self._aggregate(ledger, rows)
            ledger.emit("campaign_end", status=status, **counts)
            ledger.close()
        return {"root": self.root, "status": status, **counts, "failed_units": sorted(failed_units)}

    def _step(self, ledger, unit, s, rows, counts):
        """Run one step; True when the unit may go on."""
        rid = s.label.get("run_id", s.id)
        if s.scored and self.resume:
            m = _load_metrics(s.run_dir)
            if m is not None:
                rows.append({**s.label, "run_id": rid, "metrics": m})
                self._aggregate_stale = True
                counts["skipped"] += 1
                ledger.emit("run_skipped", run_id=rid, metrics=m, **_lbl(s))
                return True
        if s.skip_if and s.skip_if():
            counts["skipped"] += 1
            ledger.emit("step_skipped", step=s.id, unit=unit.id)
            return True
        kind = "run" if s.scored else "step"
        # A command is always a visible step (a scored one runs its own ledger).
        visible = s.cmd is not None or not s.scored
        retries = max(0, s.retries)  # a negative count must not skip the step itself
        for attempt in range(1, retries + 2):
            t0 = time.time()
            if visible:
                ledger.emit(
                    "step_start", step=s.id, unit=unit.id, attempt=attempt, cmd=s.describe()
                )
            try:
                self._execute(ledger, s, rid, attempt)
                if visible:
                    ledger.emit(
                        "step_end",
                        step=s.id,
                        unit=unit.id,
                        ok=True,
                        duration_s=round(time.time() - t0, 3),
                    )
                break
            except KeyboardInterrupt:
                raise
            # SystemExit too: a scenario's validate() raises it, and one bad grid
            # entry must fail its own unit, not end the campaign.
            except (Exception, SystemExit) as e:  # noqa: BLE001 — recorded, retried, moved on
                log.warning("%s %s attempt %d failed: %s", kind, rid, attempt, e)
                if visible:
                    ledger.emit(
                        "step_end",
                        step=s.id,
                        unit=unit.id,
                        ok=False,
                        duration_s=round(time.time() - t0, 3),
                        error=str(e)[:300],
                    )
                if attempt <= retries:
                    ledger.emit(
                        f"{kind}_retry",
                        **({"run_id": rid} if s.scored else {"step": s.id}),
                        attempt=attempt,
                        error=str(e)[:300],
                    )
                    continue
                counts["failed"] += 1
                if s.scored:
                    ledger.emit("run_failed", run_id=rid, **_lbl(s))
                else:
                    ledger.emit("step_failed", step=s.id, unit=unit.id, error=str(e)[:300])
                return False
        if s.scored:
            # Scoring reads what the run left behind; one unreadable run
            # directory fails that run, not every unit after it.
            try:
                m = s.metrics(s.run_dir)
                m["run"] = {"run_id": rid, **_lbl(s)}
                os.makedirs(s.run_dir, exist_ok=True)
                with open(os.path.join(s.run_dir, "metrics.json"), "w") as f:
                    json.dump(m, f, indent=2, default=str)
                if s.report:
                    with open(os.path.join(s.run_dir, "metrics.md"), "w") as f:
                        f.write(s.report(m))
            except Exception as e:  # noqa: BLE001 — recorded as a failed run
                log.warning("run %s could not be scored: %s", rid, e)
                counts["failed"] += 1
                ledger.emit("run_failed", run_id=rid, error=str(e)[:300], **_lbl(s))
                return False
            rows.append({**s.label, "run_id": rid, "metrics": m})
            ledger.emit("run_metrics", run_id=rid, metrics=m, **_lbl(s))
            self._aggregate(ledger, rows)
        counts["ok"] += 1
        return True

    def _aggregate(self, ledger, rows):
        """Refresh the summary files. A summary that cannot be written is
        reported, never raised: the runs behind it are already on disk."""
        self._aggregate_stale = False
        if not (rows and self.aggregate_fn):
            return
        try:
            ledger.emit("aggregate", **self.aggregate_fn(self.root, rows))
        except Exception as e:  # noqa: BLE001
            log.warning("could not refresh the campaign summary: %s", e)
            ledger.emit("aggregate_failed", error=str(e)[:300])

    def _execute(self, ledger, s, rid, attempt):
        if s.run is not None:
            emit = (
                ledger.bind(run_id=rid, attempt=attempt)
                if s.scored
                else ledger.bind(step=s.id, attempt=attempt)
            )
            rc = s.run(emit)
            # A run function returns the scenario's exit code; other steps None.
            if isinstance(rc, int) and not isinstance(rc, bool) and rc != 0:
                raise StepFailed(f"exit {rc}: {s.describe()}")
            return
        rc = _run_command(s.cmd, s.timeout)
        if rc is None:
            raise StepFailed(f"timed out after {s.timeout:g}s: {s.describe()}")
        if rc != 0:
            raise StepFailed(f"exit {rc}: {s.describe()}")


def _run_command(cmd, timeout=None):
    """Run ``cmd`` from the repository root; its exit code, or None on timeout.

    A command with a timeout leads its own process group, so that the whole
    group can be stopped: a make target killed alone would leave the Python it
    started running, still holding the lab the retry is about to deploy. One
    without a timeout stays in ours, where Ctrl-C reaches it as it always did."""
    if timeout is None:
        return subprocess.run(cmd, cwd=REPO_ROOT).returncode
    proc = subprocess.Popen(cmd, cwd=REPO_ROOT, start_new_session=True)
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_group(proc)
        return None
    except BaseException:  # Ctrl-C does not reach another session by itself
        _stop_group(proc)
        raise


def _stop_group(proc):
    """Interrupt first: a run that gets SIGINT undeploys its lab on the way out,
    one that is killed outright leaves it up. The group is done when it is
    empty, not when its leader exits — what the leader started may ignore the
    signal the leader obeyed."""
    for sig, grace in STOP_SIGNALS:
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            proc.poll()  # reap the leader, or its zombie keeps the group alive
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)


def _lbl(s):
    return {k: v for k, v in s.label.items() if k != "run_id"}


def format_result(res):
    """The one-line verdict of a finished campaign."""
    line = (
        f"=== {res['status']} (ok={res['ok']} failed={res['failed']} "
        f"skipped={res['skipped']}) — summary: {res['root']}/summary.md ==="
    )
    if res.get("failed_units"):
        line += f"\nfailed or blocked: {', '.join(res['failed_units'])}"
    return line


def run_cli(campaign, *, out=None, report=format_result, epilogue=None, preflight=True):
    """Run a campaign the way a command line wants it, and return an exit code.

    Around `Campaign.run()` every campaign needs the same three things: a lab
    checked once before the first unit (otherwise each unit retries its way to
    the same failure), a verdict, and an exit code a script can branch on —
    0 when every unit finished, 1 when one failed, `EXIT_NO_LAB` when nothing
    could start.

    ``preflight=False`` skips the lab check, for a campaign whose steps run
    no lab (a test's injected run function). ``epilogue(res) -> [str]`` is
    what a scenario says before the verdict, such as the figures it wrote.
    The dry run stays with the caller, whose message differs every time.
    """
    out = out or campaign.out
    if preflight:
        try:
            lifecycle.preflight()
        except lifecycle.LabUnavailable as e:
            out(f"cannot start: {e}")
            return lifecycle.EXIT_NO_LAB
    res = campaign.run()
    for line in epilogue(res) if epilogue else ():
        out(line)
    # One call per line, so a prefixing ``out`` (main.py's say) marks every line.
    for line in report(res).splitlines() if report else ():
        out(line)
    return 0 if res["status"] == "done" else 1


def _load_metrics(run_dir):
    path = os.path.join(run_dir, "metrics.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None  # unreadable -> run it again
