#!/usr/bin/env python3
"""red_agent.py — the autonomous attacker, running inside the lab.

The red counterpart of soc_analytics.py: the attacker's brain runs on the
attacker node, not on the host. Given the attack tree as data (--tree-b64, as
the SOC is given its inventory), an AttackPlanner chooses each step by its
profile, runs it here by invoking exploit_client.py locally, observes the
outcome and re-plans when a countermeasure has closed a path. Every step and the
final summary are appended to --record as JSON lines; the host reads that record
to reconstruct the ground truth (the oracle stays off the lab, so the DPI sensor
never sees it). It decides in the lab and knows only what the tree tells it.

Copied flat onto the attacker node with planner.py, steps.py and tree_doc.py
(see the scenario's guest_files.py). Stdlib only.
"""

import argparse
import base64
import json
import subprocess
import sys
import time

import steps as S
from planner import PROFILES, AttackPlanner

STEP_TIMEOUT_S = 90.0


def run_shell(cmd):
    """-> (rc, output). From "/", where the node's tools are staged."""
    try:
        p = subprocess.run(
            ["sh", "-c", cmd], cwd="/", capture_output=True, text=True, timeout=STEP_TIMEOUT_S
        )
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {STEP_TIMEOUT_S:.0f}s"


class RedAgent:
    """Drives one planned episode on this node, appending every event to the
    record. ``run_cmd`` is injected so a test can drive it without a container."""

    def __init__(self, ctx, record_path, run_cmd=run_shell, clock=time.time):
        self.ctx = ctx
        self.run_cmd, self.clock = run_cmd, clock
        self._file = open(record_path, "a", buffering=1)
        self._phases = {}  # node -> the machine-readable lines its step printed
        self.mode = None

    def exec_step(self, node):
        """Run one planner step here and return {ok, writes, phases}. Keeps the
        step's phases so the plan_step record can carry its Modbus writes."""
        cmd = S.step_command(node, self.ctx)
        rc, text = self.run_cmd(cmd)
        # The step's own output is the only account of why it failed: echoed
        # here, it reaches this agent's log.
        print(f"--- {node} (rc={rc})\n{text.rstrip()}", flush=True)
        res = S.parse_outcome(node, text)
        self._phases[node] = res["phases"]
        return res

    def on_step(self, **entry):
        """The planner's per-step record callback: fold in the phases exec_step
        captured and append the plan_step line."""
        self._write(
            "plan_step", mode=self.mode, phases=self._phases.get(entry.get("node"), []), **entry
        )

    def _write(self, kind, **fields):
        row = {"t": round(self.clock(), 3), "kind": kind, **fields}
        self._file.write(json.dumps(row, default=str) + "\n")

    def run(self, planner, profile, dwell):
        self.mode = f"planner:{profile}"
        self._write(
            "attack_start",
            mode=self.mode,
            profile=profile,
            goal=planner.goal,
            dwell=dwell,
            target_url=self.ctx["target_url"],
            engine_ip=self.ctx["engine_ip"],
            engine_port=self.ctx["engine_port"],
        )
        summary = planner.run(self.exec_step, sleep=time.sleep, record=self.on_step, dwell=dwell)
        self._write(
            "attack_end",
            mode=self.mode,
            success=summary["success"],
            stage_reached=summary["stage_reached"],
            writes_ok=summary["writes_ok"],
        )
        return summary


def main():
    ap = argparse.ArgumentParser(description="Autonomous tree-guided attacker (in-lab)")
    ap.add_argument("--tree-b64", required=True, help="attack tree document, base64 of JSON")
    ap.add_argument("--profile", default="opportunistic", choices=PROFILES)
    ap.add_argument("--goal", default=None, help="targeted profile: the impact leaf to aim for")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--dwell", type=float, default=0.0, help="seconds between steps")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--target-url", required=True)
    ap.add_argument("--engine-ip", required=True)
    ap.add_argument("--engine-port", type=int, required=True)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--ot-write-path", default="/ot_write.py")
    ap.add_argument("--record", default="/red_actions.jsonl")
    args = ap.parse_args()

    tree = json.loads(base64.b64decode(args.tree_b64))
    ctx = {
        "target_url": args.target_url,
        "engine_ip": args.engine_ip,
        "engine_port": args.engine_port,
        "ot_write_path": args.ot_write_path,
        "interval": args.interval,
    }
    planner = AttackPlanner(
        tree, profile=args.profile, goal=args.goal, seed=args.seed, max_steps=args.max_steps
    )
    agent = RedAgent(ctx, args.record)
    summary = agent.run(planner, args.profile, args.dwell)
    print(
        f"red agent done: stage={summary['stage_reached']} success={summary['success']}", flush=True
    )
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
