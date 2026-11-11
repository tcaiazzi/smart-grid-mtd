"""cli.py — the command line of one scenario run.

Every scenario's entry module is just ``cli.main(Scenario())``: the common
options below plus the scenario's own (Scenario.add_arguments). The same
parser gives a campaign the scenario's defaults (``default_args``), so a new
scenario option is available to campaigns without being listed twice.
"""

import argparse
import logging
import sys

from cyberrange.core import lifecycle

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"


def build_parser(scenario, description=None):
    ap = argparse.ArgumentParser(description=description or f"{scenario.name} scenario run")
    common = ap.add_argument_group("platform")
    common.add_argument("--seed", type=int, default=None,
                        help="experiment seed; each role derives its own (core.context.role_seed)")
    common.add_argument("--progress-file", default=None,
                        help="progress ledger path (default <out-dir>/progress.jsonl)")
    common.add_argument("--run-id", default=None,
                        help="run id on the ledger (default: the output directory's name)")
    common.add_argument("--poll-interval", type=float, default=2.0,
                        help="seconds between live pulls of guest state into the ledger "
                             "(0 = no live view)")
    scenario.add_arguments(ap)
    return ap


def default_args(scenario, **overrides):
    """The scenario's argument namespace with every default, then ``overrides``."""
    ns = build_parser(scenario).parse_args([])
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


def main(scenario, argv=None, description=None):
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    args = build_parser(scenario, description).parse_args(argv)
    try:
        rc = lifecycle.run(scenario, args)
    except lifecycle.LabUnavailable as e:
        logging.getLogger("cli").error("%s", e)
        sys.exit(lifecycle.EXIT_NO_LAB)
    sys.exit(rc or 0)
