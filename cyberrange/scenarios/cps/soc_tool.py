"""soc_tool.py — run the SOC's analytics on the host, offline, without importing it.

The knowledge graph, the attack tree and the response policy are software of
the SOC node (nodes/soc/). The host still needs three things from them when no
lab is up: the structure a run starts with (kg.json, tree.json — what the
dashboard draws), the same structure for runs recorded before it was saved,
and the replay of a policy on a finished run.

It gets them by *executing* the node's tool as a separate process, on the very
files the SOC node is staged with, laid out as on the node. It imports none of
them: what the SOC does stays the SOC's.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

from cyberrange.core import paths
from cyberrange.scenarios.cps.guest_files import SOC_FILES
from cyberrange.scenarios.cps.inventory import inventory

TOOL = "soc_analytics.py"


def run(*argv, args=None):
    """Run the SOC tool with the lab's inventory; returns its stdout. ``args``
    are the scenario arguments the topology is built from (default: defaults)."""
    stage = tempfile.mkdtemp(prefix="soc-tool-")
    try:
        for host_path, guest_path in SOC_FILES:
            if guest_path.endswith(".py"):
                shutil.copy(paths.resolve(host_path), os.path.join(stage, guest_path.lstrip("/")))
        inv = os.path.join(stage, "inventory.json")
        with open(inv, "w") as f:
            json.dump(inventory(args), f)
        done = subprocess.run(
            [sys.executable, TOOL, "--inventory", inv, *argv],
            cwd=stage,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if done.returncode != 0:
            raise RuntimeError(f"{TOOL} {' '.join(argv)} failed:\n{done.stderr.strip()[-600:]}")
        return done.stdout
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def describe(out_dir, it=False, args=None):
    """Write kg.json and tree.json of the lab into ``out_dir``."""
    run("--describe", "--out-dir", os.path.abspath(out_dir), *(["--it"] if it else []), args=args)


def structure(it=False):
    """{"kg": ..., "tree": ...} of the lab as declared today."""
    with tempfile.TemporaryDirectory(prefix="soc-structure-") as out:
        describe(out, it=it)
        with open(os.path.join(out, "kg.json")) as kg, open(os.path.join(out, "tree.json")) as tree:
            return {"kg": json.load(kg), "tree": json.load(tree)}


def replay(run_dir, policy, approval="auto", out=None):
    """What ``policy`` would have done on a finished run; returns the report."""
    argv = ["--replay", os.path.abspath(run_dir), "--policy", policy, "--approval", approval]
    if out:
        argv += ["--out", os.path.abspath(out)]
    return run(*argv)
