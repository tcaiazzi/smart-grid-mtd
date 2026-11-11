"""lifecycle.py — one run of any scenario, the same way every time.

    run_start → build lab → structure → deploy → episode → stop components
              → download artifacts → undeploy (always) → check_run → run_end

The ledger (progress.jsonl) is the run's own at <out_dir>/progress.jsonl
unless a campaign hands in a bound emitter. ``run`` returns the scenario's
exit code (0 = valid run) and re-raises any failure after recording it.
"""

import logging
import os
import time
import traceback

from monitor.progress import ProgressLog
from network_scenario.core.context import RunContext
from network_scenario.core.streams import PROGRESS
from network_scenario.core.topology import build_lab, write_json

log = logging.getLogger("core.lifecycle")

NETWORK_PLUGIN = "kathara/katharanp_vde"


EXIT_NO_LAB = 4    # exit code when the container engine is not reachable


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
                "`docker ps`, then run again.") from e
        raise
    Setting.get_instance().load_from_dict({"network_plugin": NETWORK_PLUGIN})
    return manager


def preflight():
    """Fail fast, before a campaign starts, when no lab can run here."""
    get_manager()


def run(scenario, args, progress=None, manager=None):
    """Run one episode of ``scenario`` with ``args``. Returns the exit code."""
    scenario.validate(args)
    out_dir = scenario.out_dir(args)
    scenario.prepare(args)
    own = progress is None
    if own:
        ledger = ProgressLog(getattr(args, "progress_file", None)
                             or os.path.join(out_dir, PROGRESS))
        emit = ledger.bind(run_id=scenario.run_id(args))
    else:
        emit = progress
    phases = scenario.phases(args)
    emit("run_start", scenario=scenario.name, out_dir=out_dir,
         phases=[p.to_dict() for p in phases], planned_s=scenario.planned_s(args),
         poll_s=getattr(args, "poll_interval", 0), **scenario.run_info(args))

    t0 = time.time()
    status, error, rc = "failed", None, None
    ctx = None
    try:
        os.makedirs(out_dir, exist_ok=True)
        manager = manager or get_manager()
        topo = scenario.topology(args)
        lab, machines, _startups = build_lab(topo)
        ctx = RunContext(manager, lab, machines, args, out_dir, emit, scenario, topo)
        write_json(topo, os.path.join(out_dir, "topology.json"))
        try:
            scenario.write_structure(ctx)
        except Exception as e:      # dashboard extras never fail a run
            log.warning("could not write the run structure: %s", e)
        with ctx.phase("deploy"):
            log.info("Undeploying any existing lab named %r", topo.name)
            manager.undeploy_lab(lab=lab)
            log.info("Deploying lab %r", topo.name)
            manager.deploy_lab(lab=lab)
        try:
            try:
                scenario.episode(ctx)
            finally:
                ctx.stop_all()
                ctx.close_ground_truth()
            with ctx.phase("download"):
                ctx.download_artifacts()
        finally:
            with ctx.phase("undeploy"):
                log.info("Undeploying lab %r", topo.name)
                manager.undeploy_lab(lab=lab)
        rc = scenario.check_run(ctx)
        status = "ok" if rc == 0 else "invalid"
        return rc
    except KeyboardInterrupt:
        status, error = "interrupted", "KeyboardInterrupt"
        raise
    except BaseException:
        error = traceback.format_exc()[-2000:]
        raise
    finally:
        emit("run_end", status=status, duration_s=round(time.time() - t0, 3), error=error,
             rc=rc)
        if own:
            ledger.close()
