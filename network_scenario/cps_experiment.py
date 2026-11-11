"""cps_experiment.py — command line of one cyber-physical scenario run.

The scenario itself lives in network_scenario/scenarios/cps (topology +
episode); the run lifecycle in network_scenario/core.

Run:
    python -m network_scenario.cps_experiment --normal-duration 60 --attack \
        --attack-mode manual-hijack --out-dir output/cps/run-1 --seed 1
"""

from network_scenario.core import cli, lifecycle
from network_scenario.scenarios.cps.scenario import CpsScenario


def run(args, progress=None, manager=None):
    """One CPS run (see core.lifecycle.run); ``progress`` is a campaign's
    bound ledger emitter, or None for the run's own <out_dir>/progress.jsonl."""
    return lifecycle.run(CpsScenario(), args, progress=progress, manager=manager)


def main(argv=None):
    cli.main(CpsScenario(), argv, description="Cyber-physical OT/Modbus Kathará scenario")


if __name__ == "__main__":
    main()
