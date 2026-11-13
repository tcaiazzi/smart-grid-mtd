"""cli.py — command line of one cps-soc run.

The scenario lives in cyberrange/scenarios/cps_soc (the cps-advisor episode,
with the blue team on Wazuh's dashboard and DFIR-IRIS); the run lifecycle in
cyberrange/core.

Run:
    python -m cyberrange.scenarios.cps_soc.cli --attack --playground \
        --out-dir output/cps-soc/run-1 --seed 1
"""

from cyberrange.core import cli, lifecycle
from cyberrange.scenarios.cps_soc.scenario import CpsSocScenario


def run(args, progress=None, manager=None):
    """One cps-soc run (see core.lifecycle.run); ``progress`` is a bound ledger
    emitter, or None for the run's own <out_dir>/progress.jsonl."""
    return lifecycle.run(CpsSocScenario(), args, progress=progress, manager=manager)


def main(argv=None):
    cli.main(CpsSocScenario(), argv, description="Cyber-physical scenario with a real SOC's tools")


if __name__ == "__main__":
    main()
