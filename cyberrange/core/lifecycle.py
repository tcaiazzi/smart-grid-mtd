"""lifecycle.py — one run of any scenario, the same way every time.

    run_start → build lab → structure → deploy → episode → [open, until Ctrl-C,
              with --playground] → stop components
              → download artifacts (also of a failed episode) → undeploy (always)
              → check_run → run_end

The ledger (progress.jsonl) is the run's own at <out_dir>/progress.jsonl
unless a campaign hands in a bound emitter. ``run`` returns the scenario's
exit code (0 = valid run) and re-raises any failure after recording it.
"""

import json
import logging
import os
import shutil
import time
import traceback

from cyberrange.core import paths, runcard
from cyberrange.core.progress import ProgressLog
from cyberrange.core.context import RunContext
from cyberrange.core.scenario import OPEN_PHASE
from cyberrange.core.streams import PROGRESS
from cyberrange.core.topology import build_lab, write_json

log = logging.getLogger("core.lifecycle")

NETWORK_PLUGIN = "kathara/katharanp_vde"


EXIT_NO_LAB = 4  # exit code when the container engine is not reachable


class LabUnavailable(RuntimeError):
    """The labs cannot run at all here (e.g. the Docker daemon is down):
    retrying a run will not help."""


def get_manager():
    """The Kathará manager, with the network plugin every lab here uses.
    Raises LabUnavailable when the Docker daemon cannot be reached."""
    from Kathara.manager.Kathara import Kathara
    from Kathara.setting.Setting import Setting

    try:
        manager = Kathara.get_instance()
    except Exception as e:
        if type(e).__name__ == "DockerDaemonConnectionError":
            raise LabUnavailable(
                "the Docker daemon is not reachable, so no lab can be deployed. Start it "
                "(WSL: `sudo service docker start`, or open Docker Desktop) and check "
                "`docker ps`, then run again."
            ) from e
        raise
    Setting.get_instance().load_from_dict({"network_plugin": NETWORK_PLUGIN})
    return manager


def preflight():
    """Fail fast, before a campaign starts, when no lab can run here."""
    get_manager()


class ComponentDown(RuntimeError):
    """A component the run cannot do without is not running: what the run
    measured is not what it was meant to."""


class RunDirTaken(SystemExit):
    """The run was told to write where another run already has."""


def write_metrics(run_dir, metrics, report=None, **run):
    """Keep a run's score with the run: metrics.json, and metrics.md when the
    scenario has a ``report`` for it. ``run`` is who the run is (its id, a
    campaign's labels), put with what its card says it was made with — so a
    row of an aggregate still says which code and lab it comes from."""
    metrics["run"] = {**run, "card": runcard.summary(runcard.read(run_dir))}
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    try:
        text = report(metrics) if report else None
    except Exception as e:  # noqa: BLE001 — the score is kept; only its prose is missing
        log.warning("could not write the report of the run in %s: %s", run_dir, e)
        text = None
    if text:
        with open(os.path.join(run_dir, "metrics.md"), "w") as f:
            f.write(text)
    return metrics


def _score(scenario, out_dir, emit, run_id):
    """Score a standalone run: on its own ledger, so the dashboard shows it as
    it shows a campaign's, and in metrics.json next to its artifacts, as a
    campaign's runs have it. A campaign scores its runs itself. A score that
    cannot be computed is a missing view, never a failed run."""
    try:
        metrics = scenario.metrics(out_dir)
        if metrics:
            write_metrics(out_dir, metrics, scenario.report, run_id=run_id)
    except Exception as e:  # noqa: BLE001 — the run itself succeeded
        log.warning("could not score the run in %s: %s", out_dir, e)
        return
    if metrics:
        emit("run_metrics", metrics=metrics)


def claim_run_dir(scenario, args):
    """The directory a standalone run writes to, made its own. Without
    --out-dir it is a new one. A given one that already holds a run is refused
    — two runs in one directory share a ledger and overwrite each other's
    artifacts — unless --overwrite, which empties it first."""
    out_dir = scenario.out_dir(args)
    if not scenario.one_run_per_dir:
        return out_dir
    if not out_dir:
        root = getattr(args, "out_root", None) or "output"
        args.out_dir = paths.new_run_dir(root, scenario.name, getattr(args, "run_name", None))
        return scenario.out_dir(args)
    if os.path.exists(os.path.join(out_dir, PROGRESS)):
        if not getattr(args, "overwrite", False):
            raise RunDirTaken(
                f"{out_dir} already holds a run: its ledger and artifacts would be mixed with "
                "this one's. Leave --out-dir out for a new directory, name another, or pass "
                "--overwrite to empty this one first."
            )
        shutil.rmtree(out_dir)
    return out_dir


def run(scenario, args, progress=None, manager=None):
    """Run one episode of ``scenario`` with ``args``. Returns the exit code."""
    scenario.validate(args)
    own = progress is None
    out_dir = claim_run_dir(scenario, args) if own else scenario.out_dir(args)
    scenario.prepare(args)
    run_id = scenario.run_id(args)
    card = runcard.start(out_dir, scenario, args, run_id)
    if own:
        ledger = ProgressLog(
            getattr(args, "progress_file", None) or os.path.join(out_dir, PROGRESS)
        )
        emit = ledger.bind(run_id=run_id)
    else:
        emit = progress
    phases = scenario.phases(args)
    playground = bool(getattr(args, "playground", False))
    emit(
        "run_start",
        scenario=scenario.name,
        out_dir=out_dir,
        phases=[p.to_dict() for p in phases],
        planned_s=scenario.planned_s(args),
        poll_s=getattr(args, "poll_interval", 0),
        playground=playground,
        **scenario.run_info(args),
    )

    t0 = time.time()
    status, error, rc = "failed", None, None
    ctx, down = None, []
    try:
        os.makedirs(out_dir, exist_ok=True)
        manager = manager or get_manager()
        topo = scenario.topology(args)
        lab, machines, _startups = build_lab(topo)
        ctx = RunContext(manager, lab, machines, args, out_dir, emit, scenario, topo)
        write_json(topo, os.path.join(out_dir, "topology.json"))
        try:
            scenario.write_structure(ctx)
        except Exception as e:  # dashboard extras never fail a run
            log.warning("could not write the run structure: %s", e)
        runcard.lab(card, out_dir, topo, scenario.structure_files)
        # The deploy is inside the undeploy guard: a deploy that dies halfway
        # would otherwise leave its containers and networks up.
        try:
            with ctx.phase("deploy"):
                log.info("Undeploying any existing lab named %r", topo.name)
                manager.undeploy_lab(lab=lab)
                log.info("Deploying lab %r", topo.name)
                manager.deploy_lab(lab=lab)
            episode_ok = False
            try:
                scenario.episode(ctx)
                if playground:
                    log.info("Playground: lab %r stays up, Ctrl-C to close it", topo.name)
                    with ctx.phase(OPEN_PHASE):
                        ctx.hold()
                # Before anything is stopped: a service that died during the
                # episode left a run that measured something else.
                down = ctx.down()
                if down:
                    raise ComponentDown(
                        f"not running at the end of the episode: {', '.join(down)}. "
                        "Their console logs are with the run's artifacts."
                    )
                episode_ok = True
            finally:
                ctx.stop_all()
                ctx.close_ground_truth()
                # A failed episode is when the console logs matter most, so the
                # artifacts come down either way; a download that fails on top
                # of a failed episode must not hide the episode's own error.
                try:
                    with ctx.phase("download"):
                        ctx.download_artifacts()
                except Exception as e:
                    if episode_ok:
                        raise
                    log.warning("could not download the artifacts of the failed run: %s", e)
        finally:
            with ctx.phase("undeploy"):
                log.info("Undeploying lab %r", topo.name)
                manager.undeploy_lab(lab=lab)
        rc = scenario.check_run(ctx)
        status = "ok" if rc == 0 else "invalid"
        if own and rc == 0:
            _score(scenario, out_dir, emit, run_id)
        return rc
    except KeyboardInterrupt:
        status, error = "interrupted", "KeyboardInterrupt"
        raise
    except BaseException:
        error = traceback.format_exc()[-2000:]
        raise
    finally:
        duration = round(time.time() - t0, 3)
        # Whatever was found dead, wherever in the run it was found.
        down = sorted(ctx.reported_down) if ctx is not None else down
        runcard.finish(card, out_dir, status, duration, down, error)
        emit("run_end", status=status, duration_s=duration, error=error, rc=rc)
        if own:
            ledger.close()
