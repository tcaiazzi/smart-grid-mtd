"""responder.py — replay a response policy on a finished CPS run.

    python -m cyberrange.scenarios.cps.responder --replay output/cps/v2b-manual-hijack \
        --policy solver

Shows what the policy *would* have decided on the findings the run recorded,
and writes it to ``<run>/response.<policy>.replay.jsonl``. Nothing is deployed
and nothing is executed.

The policy itself is software of the SOC node (nodes/soc/soc_analytics.py);
this is the host-side entry point that runs it offline (soc_tool). In a live
run the decision is taken on the SOC node, not here.
"""

import argparse

from cyberrange.scenarios.cps import soc_tool

POLICIES = ("rules", "solver")


def main():
    ap = argparse.ArgumentParser(description="CPS response policy: offline replay")
    ap.add_argument("--replay", required=True, help="finished run directory")
    ap.add_argument("--policy", default="rules", choices=POLICIES)
    ap.add_argument("--approval", default="auto")
    ap.add_argument(
        "--out", default=None, help="response log (default <run>/response.<policy>.replay.jsonl)"
    )
    args = ap.parse_args()
    print(soc_tool.replay(args.replay, args.policy, args.approval, args.out), end="")


if __name__ == "__main__":
    main()
