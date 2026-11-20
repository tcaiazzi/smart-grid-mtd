"""cli.py — command line of one cps-recon run.

The scenario lives in cyberrange/scenarios/cps_recon (the cps episode with an
attacker that derives its own attack tree by reconnaissance); the run lifecycle
in cyberrange/core.

Run:
    python -m cyberrange.scenarios.cps_recon.cli --attack \
        --attacker-profile opportunistic --out-dir output/cps-recon/run-1 --seed 1
"""

from cyberrange.core import cli, lifecycle
from cyberrange.scenarios.cps_recon.scenario import CpsReconScenario


def run(args, progress=None, manager=None):
    """One cps-recon run (see core.lifecycle.run); ``progress`` is a bound
    ledger emitter, or None for the run's own <out_dir>/progress.jsonl."""
    return lifecycle.run(CpsReconScenario(), args, progress=progress, manager=manager)


def main(argv=None):
    cli.main(
        CpsReconScenario(), argv, description="Cyber-physical scenario with a recon-driven attacker"
    )


if __name__ == "__main__":
    main()
