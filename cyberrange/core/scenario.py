"""scenario.py — the contract every scenario implements.

A scenario declares its topology, its options and its episode; the core
(lifecycle.run) does the rest: ledger, deploy, artifacts, undeploy, exit code.

    name / lab_name         registry key / Kathará lab name (one lab per name)
    add_arguments(ap)       the scenario's own command-line options
    validate(args)          fail fast (raise SystemExit) before anything deploys
    topology(args)          core.topology.Topology
    phases(args)            [PhaseSpec] in run order, with planned durations (ETA);
                            the core emits deploy / download / undeploy itself
    run_info(args)          extra fields for the run_start ledger event
    out_dir(args)           where the run writes (default: args.out_dir)
    run_id(args)            ledger id of the run (default: basename of out_dir)
    prepare(args)           before the lab is built (e.g. tee the run log)
    write_structure(ctx)    optional structural files for the dashboard (kg/tree)
    episode(ctx)            start components, drive the phases
    check_run(ctx) -> int   0 = a valid run; anything else is the process exit code
    metrics(run_dir)        per-run metrics dict (campaigns, dashboard)
"""

import os
from dataclasses import asdict, dataclass

DEFAULT_OVERHEAD_S = {"deploy": 3.0, "download": 0.5, "undeploy": 1.0}


@dataclass
class PhaseSpec:
    name: str
    planned_s: float
    timed: bool = False     # a fixed-length observation phase (vs best-effort setup)

    def to_dict(self):
        return asdict(self)


class Scenario:
    name = "scenario"
    lab_name = "lab"
    overhead_s = DEFAULT_OVERHEAD_S

    def add_arguments(self, ap):
        pass

    def validate(self, args):
        pass

    def topology(self, args):
        raise NotImplementedError

    def episode_phases(self, args):
        """The scenario's own phases, between deploy and download."""
        return []

    def phases(self, args):
        o = self.overhead_s
        return ([PhaseSpec("deploy", o["deploy"])] + list(self.episode_phases(args))
                + [PhaseSpec("download", o["download"]), PhaseSpec("undeploy", o["undeploy"])])

    def planned_s(self, args):
        return round(sum(p.planned_s for p in self.phases(args)), 3)

    def run_info(self, args):
        return {"seed": getattr(args, "seed", None)}

    def out_dir(self, args):
        return args.out_dir

    def run_id(self, args):
        return getattr(args, "run_id", None) or os.path.basename(
            os.path.normpath(self.out_dir(args)))

    def prepare(self, args):
        pass

    def write_structure(self, ctx):
        pass

    # ── dashboard hooks ──────────────────────────────────────────────────────
    # The dashboard is platform code and must not know which scenarios exist:
    # a scenario that wants a panel of its own declares it here, and the
    # dashboard asks the registry. A scenario without one is still fully shown
    # (ledger, phases, runs, aggregate) — it just has nothing extra to draw.

    def panel_js(self):
        """Path to a JavaScript file drawing this scenario's own panel, or None."""
        return None

    def structure(self):
        """``{"kg": ..., "tree": ...}`` rebuilt from the declared topology, for
        runs recorded before the scenario wrote its structure to disk. None when
        the scenario has no such structure."""
        return None

    def episode(self, ctx):
        raise NotImplementedError

    def check_run(self, ctx):
        return 0

    def metrics(self, run_dir):
        return {}
