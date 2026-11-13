#!/usr/bin/env python3
"""red_recon_agent.py — the recon-driven attacker, running inside the lab.

Unlike red_agent.py (which is handed the attack tree), this one is given only a
scan scope — its own IT subnet and a port list — and *derives* the tree:

    1. scan the IT subnet with nmap           -> find the HMI's web app (foothold)
    2. foothold (RCE through the web app) and, living off the land on the HMI,
       read /proc/net/tcp + the HMI's pymodbus -> find the engine and its registers
    3. build the belief attack tree from what was found (belief_tree)
    4. plan and execute on it, reusing red_agent.RedAgent unchanged

It records the recon findings and writes the belief tree as an artifact; the host
reconstructs the ground truth from the same record (the oracle stays off the lab).

Copied flat onto the attacker node (kathara/redteam image) with recon.py,
belief_tree.py, the planner and the exploit chain (see guest_files.py). Stdlib +
nmap; pymodbus runs on the HMI, not here.
"""

import argparse
import json
import sys

import belief_tree
import recon
from exploit_client import rce
from planner import PROFILES, AttackPlanner
from red_agent import RedAgent, run_shell


def _append(record_path, **row):
    with open(record_path, "a", buffering=1) as f:
        f.write(json.dumps(row, default=str) + "\n")


def pick_foothold(hosts):
    """The attacker's foothold: a host exposing an HTTP service (the vuln web
    app). Prefers a service nmap named 'http'; falls back to the first open port."""
    for host in hosts:
        for port in host["ports"]:
            if (port.get("service") or "").startswith("http"):
                return {"ip": host["ip"], "port": port["port"]}
    for host in hosts:
        if host["ports"]:
            return {"ip": host["ip"], "port": host["ports"][0]["port"]}
    return None


def reconnoitre(it_cidr, scan_ports, record_path, scan=recon.scan_it, rce_fn=rce):
    """Run the two recon stages, record them, and return (findings, target_url).
    ``scan`` and ``rce_fn`` are injected so a test can drive it without a lab."""
    hosts = scan(it_cidr, scan_ports)
    foothold = pick_foothold(hosts)
    _append(record_path, kind="recon", stage="it", hosts=hosts, foothold=foothold)
    if not foothold:
        return {"foothold": None, "ot": {}}, None

    target_url = f"http://{foothold['ip']}:{foothold['port']}"
    ot = recon.discover_ot(lambda cmd: rce_fn(target_url, cmd))
    _append(record_path, kind="recon", stage="ot", **ot)
    return {"foothold": foothold, "ot": ot}, target_url


def main():
    ap = argparse.ArgumentParser(description="Recon-driven attacker (derives its own tree, in-lab)")
    ap.add_argument("--it-cidr", required=True, help="the IT subnet to scan (attacker's own)")
    ap.add_argument("--scan-ports", default="22,80,502,5020,8080", help="comma-separated ports")
    ap.add_argument("--profile", default="opportunistic", choices=PROFILES)
    ap.add_argument("--goal", default=None, help="targeted profile: the impact leaf to aim for")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--dwell", type=float, default=0.0, help="seconds between steps")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--ot-write-path", default="/ot_write.py")
    ap.add_argument("--record", default="/red_actions.jsonl")
    ap.add_argument("--belief-out", default="/belief_tree.json")
    args = ap.parse_args()

    ports = [int(p) for p in args.scan_ports.split(",") if p.strip()]
    findings, target_url = reconnoitre(args.it_cidr, ports, args.record)
    tree = belief_tree.build(findings)
    with open(args.belief_out, "w") as f:
        json.dump(tree, f)
    print(f"recon done: foothold={findings['foothold']} ot={findings['ot'] or 'none'}", flush=True)

    ot = findings["ot"] or {}
    ctx = {
        "target_url": target_url or "",
        "engine_ip": ot.get("engine_ip") or "",
        "engine_port": ot.get("modbus_port") or 0,
        "ot_write_path": args.ot_write_path,
        "interval": args.interval,
    }
    planner = AttackPlanner(
        tree, profile=args.profile, goal=args.goal, seed=args.seed, max_steps=args.max_steps
    )
    agent = RedAgent(ctx, args.record, run_cmd=run_shell)
    summary = agent.run(planner, args.profile, args.dwell)
    print(f"attack done: stage={summary['stage_reached']} success={summary['success']}", flush=True)
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
