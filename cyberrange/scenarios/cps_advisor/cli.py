"""cli.py — command line of one cps-advisor run.

The scenario lives in cyberrange/scenarios/cps_advisor (the cps episode with a
SOC that advises); the run lifecycle in cyberrange/core.

Run:
    python -m cyberrange.scenarios.cps_advisor.cli --attack --attack-mode breaker-open \
        --out-dir output/cps-advisor/run-1 --seed 1 --playground
"""

from cyberrange.core import cli, lifecycle
from cyberrange.scenarios.cps_advisor.scenario import CpsAdvisorScenario


def run(args, progress=None, manager=None):
    """One cps-advisor run (see core.lifecycle.run); ``progress`` is a bound
    ledger emitter, or None for the run's own <out_dir>/progress.jsonl."""
    return lifecycle.run(CpsAdvisorScenario(), args, progress=progress, manager=manager)


def main(argv=None):
    cli.main(
        CpsAdvisorScenario(),
        argv,
        description="Cyber-physical scenario with a SOC that advises an operator",
    )


if __name__ == "__main__":
    main()
