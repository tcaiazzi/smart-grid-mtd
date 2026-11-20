#!/usr/bin/env python3
"""steps.py — map attack-tree leaf nodes to the lab step that realises them.

Each entry is data: which single exploit_client.py step runs the node, how loud
it is (detectability, used by the stealthy profile), and which stage it belongs
to. The commands compose the primitives the scripted chain already uses — this
registry only lets the planner invoke them one node at a time.

The tables are keyed by the *kind* of a step (``it_access``, ``breaker_open``).
A lab with several ways in or several feeders has the same step in several
places, each a node of its own (``breaker_open@hmib:u2``): the node's document
names its kind, and where it stands in the tree says which way in it goes
through and which feeder it acts on (``places``).

Copied flat onto the attacker node (see the scenario's guest_files.py), where
planner.py, red_agent.py and red_console.py all ``import steps``. Stdlib only.
"""

import re

# Prerequisite steps, in the order they build on each other. An impact needs
# the ones its branch of the tree names: "through the HMI" stops at the pivot,
# "between the PLC and the plant" goes by the engineering workstation.
PREREQ_ORDER = ["it_access", "it_exec", "pivot", "ot_foothold", "ot_aitm"]

# What a step needs that the tree does not say, because it is a fact of how the
# lab realises it: the workstation is reached with code execution on the HMI.
REQUIRES = {"ot_foothold": ("it_access", "it_exec")}

# Impact leaf -> exploit_client --attack mode (the writes it performs).
IMPACT_MODE = {
    "setpoint_oor": "setpoint-overvoltage",
    "breaker_open": "breaker-open",
    "mode_hijack": "manual-hijack",
    "setpoint_ramp": "slow-ramp",
    "setpoint_oscillation": "setpoint-oscillation",
    "breaker_chatter": "breaker-chatter",
    "meas_fdi": "meas-fdi",
}

# How likely the sensors flag the step (0..1). The stealthy profile prefers the
# quietest reachable impact; it informs no detection logic, only planning.
DETECTABILITY = {
    "it_access": 0.6,  # injection pattern in the web log
    "it_exec": 0.4,  # a child process of the web server
    "pivot": 0.3,  # an unexpected Modbus client connection
    "setpoint_oor": 0.9,  # out-of-range command, loud
    "breaker_open": 0.9,  # remote breaker write, policy violation
    "mode_hijack": 0.2,  # in-range writes from the HMI, quiet
    "setpoint_ramp": 0.15,  # in-range and no single jump, quietest
    "setpoint_oscillation": 0.6,  # in-range, but large repeated swings
    "breaker_chatter": 0.9,  # remote breaker writes, over and over
    "ot_foothold": 0.3,  # a maintenance request, from the host that makes them
    "ot_aitm": 0.8,  # the PLC and the engine see each other's address move
    "meas_fdi": 0.5,  # no write of the attacker's, but two versions of a reading
}

STAGES = PREREQ_ORDER + ["impact"]
STAGE_INDEX = {stage: i for i, stage in enumerate(STAGES)}

STEP_FILE = "exploit_client.py"


VIA_KIND, VIA_PREFIX = "via", "via_"  # the tree's node for one way in: via_<host>
_REGISTER_OF = re.compile(r"^reg:(\d+):")  # a register of the graph: reg:<unit>:<kind>:<address>


def kind_of(node):
    """The step a tree node is. ``node`` is its document, or the bare kind."""
    if isinstance(node, dict):
        return node.get("kind") or node["id"]
    return node


def stage_of(node):
    kind = kind_of(node)
    return "impact" if kind in IMPACT_MODE else kind


def is_step(node):
    kind = kind_of(node)
    return kind in PREREQ_ORDER or kind in IMPACT_MODE


def places(tree):
    """{node id: {"via": host | None, "unit": unit | None}} for every node of
    the tree document: the way in it is a step of (the ``via_<host>`` it stands
    under; None on the branch that goes by no HMI of its own) and the feeder
    whose registers it targets (None for a step that touches no register)."""
    out = {}

    def walk(node, via):
        if kind_of(node) == VIA_KIND and node["id"].startswith(VIA_PREFIX):
            via = node["id"][len(VIA_PREFIX) :]
        units = [m.group(1) for m in map(_REGISTER_OF.match, node.get("targets") or []) if m]
        out[node["id"]] = {"via": via, "unit": int(units[0]) if units else None}
        for child in node.get("children") or []:
            walk(child, via)

    walk(tree, None)
    return out


def step_command(node, ctx, place=None):
    """Shell command to run ONE step on the attacker container. ``node`` is the
    step's document in the tree (or its bare kind). ``ctx`` carries target_url,
    engine_ip, engine_port, ot_write_path, interval, and for a lab of several
    ways in or feeders ``ways`` ({host: its application's URL}) and
    ``plant_b64``. ``place`` (see ``places``) says which of them the step uses:
    the URL of its way in — ``target_url`` when it names none — and its unit."""
    kind, place = kind_of(node), place or {}
    if not is_step(kind):
        raise KeyError(f"{kind} is not an executable step")
    url = (ctx.get("ways") or {}).get(place.get("via")) or ctx["target_url"]
    base = (
        f"python3 {STEP_FILE} --target-url {url} "
        f"--engine-ip {ctx['engine_ip']} --engine-port {ctx['engine_port']} "
        f"--ot-write-path {ctx.get('ot_write_path', '/ot_write.py')} "
        f"--interval {ctx.get('interval', 0.5)}"
    )
    if place.get("unit") is not None:
        base += f" --unit-id {place['unit']}"
    if ctx.get("plant_b64"):
        base += f" --plant-b64 {ctx['plant_b64']}"
    if kind in IMPACT_MODE:
        return f"{base} --step impact --attack {IMPACT_MODE[kind]}"
    return f"{base} --step {kind}"


def parse_outcome(node, text):
    """Read the JSON ground-truth lines exploit_client prints for the step.
    Returns {ok, writes, phases}."""
    import json

    kind = kind_of(node)
    phases, writes, ok = [], 0, False
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        ph = ev.get("phase")
        if ph is None:
            continue
        phases.append(ev)
        if ph == "modbus_write" and ev.get("ok"):
            writes += 1
        if ph == stage_of(kind):
            ok = bool(ev.get("ok"))
    if kind in IMPACT_MODE and not any(p.get("phase") == "impact" for p in phases):
        ok = writes > 0  # older output without an explicit impact line
    return {"ok": ok, "writes": writes, "phases": phases}
