"""steps.py — map attack-tree leaf nodes to the lab step that realises them.

Each entry is data: which single exploit_client.py step runs the node, how loud
it is (detectability, used by the stealthy profile), and which stage it belongs
to. The commands compose the primitives the scripted chain already uses — this
registry only lets the planner invoke them one node at a time.
"""

# Ordered prerequisite steps shared by every "through the HMI" impact.
PREREQ_ORDER = ["it_access", "it_exec", "pivot"]

# Impact leaf -> exploit_client --attack mode (the writes it performs).
IMPACT_MODE = {
    "setpoint_oor": "setpoint-overvoltage",
    "breaker_open": "breaker-open",
    "mode_hijack": "manual-hijack",
}

# How likely the sensors flag the step (0..1). The stealthy profile prefers the
# quietest reachable impact; it informs no detection logic, only planning.
DETECTABILITY = {
    "it_access": 0.6,   # injection pattern in the web log
    "it_exec": 0.4,     # a child process of the web server
    "pivot": 0.3,       # an unexpected Modbus client connection
    "setpoint_oor": 0.9,   # out-of-range command, loud
    "breaker_open": 0.9,   # remote breaker write, policy violation
    "mode_hijack": 0.2,    # in-range writes from the HMI, quiet
}

STAGE_INDEX = {"it_access": 0, "it_exec": 1, "pivot": 2, "impact": 3}

STEP_FILE = "exploit_client.py"


def stage_of(node):
    return "impact" if node in IMPACT_MODE else node


def is_step(node):
    return node in PREREQ_ORDER or node in IMPACT_MODE


def step_command(node, ctx):
    """Shell command to run ONE step on the attacker container. ``ctx`` carries
    target_url, engine_ip, engine_port, ot_write_path, interval."""
    base = (f"python3 {STEP_FILE} --target-url {ctx['target_url']} "
            f"--engine-ip {ctx['engine_ip']} --engine-port {ctx['engine_port']} "
            f"--ot-write-path {ctx.get('ot_write_path', '/ot_write.py')} "
            f"--interval {ctx.get('interval', 0.5)}")
    if node in IMPACT_MODE:
        return f"{base} --step impact --attack {IMPACT_MODE[node]}"
    if node in PREREQ_ORDER:
        return f"{base} --step {node}"
    raise KeyError(f"{node} is not an executable step")


def parse_outcome(node, text):
    """Read the JSON ground-truth lines exploit_client prints for the step.
    Returns {ok, writes, phases}."""
    import json
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
        if ph == stage_of(node):
            ok = bool(ev.get("ok"))
    if node in IMPACT_MODE and not any(p.get("phase") == "impact" for p in phases):
        ok = writes > 0          # older output without an explicit impact line
    return {"ok": ok, "writes": writes, "phases": phases}
