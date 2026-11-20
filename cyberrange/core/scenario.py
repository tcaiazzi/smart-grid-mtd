"""scenario.py — the contract every scenario implements.

A scenario declares its topology, its options and its episode; the core
(lifecycle.run) does the rest: ledger, deploy, artifacts, undeploy, exit code.

    name / lab_name         registry key / Kathará lab name (one lab per name)
    add_arguments(ap)       the scenario's own command-line options
    validate(args)          fail fast (raise SystemExit) before anything deploys
    topology(args)          core.topology.Topology
    phases(args)            [PhaseSpec] in run order, with planned durations (ETA);
                            the core emits deploy / download / undeploy itself,
                            and "open" for a run held up with --playground
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
OPEN_PHASE = "open"  # a playground run, held up after its episode until Ctrl-C


@dataclass
class PhaseSpec:
    name: str
    planned_s: float
    timed: bool = False  # a fixed-length observation phase (vs best-effort setup)

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
        # A playground run stays up after its episode, for as long as it is left
        # open: a phase with no planned length, so it adds nothing to the ETA.
        held = [PhaseSpec(OPEN_PHASE, 0.0)] if getattr(args, "playground", False) else []
        return (
            [PhaseSpec("deploy", o["deploy"])]
            + list(self.episode_phases(args))
            + held
            + [PhaseSpec("download", o["download"]), PhaseSpec("undeploy", o["undeploy"])]
        )

    def planned_s(self, args):
        return round(sum(p.planned_s for p in self.phases(args)), 3)

    def run_info(self, args):
        return {"seed": getattr(args, "seed", None)}

    # ── the run's record ─────────────────────────────────────────────────────
    #: True for a scenario whose run owns its output directory. A standalone
    #: run is then given a new one unless told where to go, and refuses one
    #: that already holds a run. False for a scenario that puts several runs
    #: in one directory on purpose (mqtt-mtd, each under its own prefix).
    one_run_per_dir = False
    #: Files the scenario writes into the run directory that describe the lab
    #: (write_structure): fingerprinted on the run's card.
    structure_files = ()

    def run_card(self, args):
        """What this scenario adds to the run's card (core/runcard.py): flat
        values that tell whether two runs ran the same thing."""
        return {}

    def secret_options(self, args):
        """Names of the options whose value must not be kept with the run."""
        return ()

    def report(self, metrics):
        """The run's metrics as text (metrics.md), or None for none."""
        return None

    def headline(self, card, metrics):
        """One line on how a finished run went, for a list of runs
        (``python -m cyberrange.core runs``); "" for nothing to say."""
        return ""

    def out_dir(self, args):
        return args.out_dir

    def run_id(self, args):
        given = getattr(args, "run_id", None)
        if given:
            return given
        # Before a run has claimed its directory there is none to name it by.
        out_dir = self.out_dir(args)
        return os.path.basename(os.path.normpath(out_dir)) if out_dir else self.name

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
