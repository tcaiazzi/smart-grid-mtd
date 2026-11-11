"""active_attack.py — host-side driver for the cyber-physical active attack
(doc step 4's stimulus). It is to the OT scenario what detection_scenario.py is
to the MQTT one: it drives an episode on an already-deployed Kathará lab and
records the ground truth, keeping the oracle on the host (the DPI sensor never
sees it).

It exec's cyberrange/planes/attack/agents/exploit_client.py on the attacker container, which
performs the real chain — exploit the vulnerable app (RCE), pivot across the
IT/OT boundary, and issue the unauthorized Modbus write — then records what it
drove to ground_truth.jsonl so metrics can tell a genuine detection from an
attack that simply ran out of moves, and measure detection latency against the
attack window.
"""

import json
import logging
import time

log = logging.getLogger("active_attack")

STAGE_TO_GT = {"it_access": "rce"}   # map the access step to the kind metrics expect

# Attack mode -> the actuator writes it performs (mirrors exploit_client.ATTACKS;
# kept as a plain hint so this host module needs no guest imports).
ATTACK_TARGET = {
    "setpoint-overvoltage": [{"register": 0, "name": "dg_setpoint", "value": 200.0}],
    "breaker-open":         [{"register": 1, "name": "switch_cmd", "value": 1.0}],
    "manual-hijack":        [{"register": 2, "name": "ctrl_mode", "value": 1.0},
                             {"register": 0, "name": "dg_setpoint", "value": 60.0}],
}
REGISTER_NAMES = {t["register"]: t["name"] for ts in ATTACK_TARGET.values() for t in ts}
# Writes that are in the legitimate envelope and come from an allowed host:
# invisible to the source/range rules (the point of the stealthy mode).
STEALTHY_MODES = {"manual-hijack"}


def parse_exploit_events(text: str):
    """The JSON ground-truth lines exploit_client prints ({"t","phase",...})."""
    events = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict) and "phase" in ev:
            events.append(ev)
    return events


def drive_attack(manager, attacker, gt, target_url, engine_ip, engine_port,
                 attack_mode="setpoint-overvoltage", repeat=None, interval=0.5):
    """Run the exploit chain on the attacker container and record ground truth.

    Each Modbus write is recorded with the time the attacker actually issued it
    (from exploit_client's JSON lines), not when the exec returned.
    Returns the exploit_client return code (0 on success)."""
    targets = ATTACK_TARGET.get(attack_mode, [])
    rep = f" --repeat {repeat}" if repeat is not None else ""
    cmd = (f'bash -c "set -o pipefail; PYTHONUNBUFFERED=1 python3 exploit_client.py '
           f'--target-url {target_url} --engine-ip {engine_ip} --engine-port {engine_port} '
           f'--attack {attack_mode}{rep} --interval {interval} 2>&1 | tee exploit.log"')

    gt.record("attack_start", mode=attack_mode, target_url=target_url,
              engine_ip=engine_ip, engine_port=engine_port,
              writes=targets, stealthy=attack_mode in STEALTHY_MODES, repeat=repeat)
    log.info("Driving active attack (%s) against %s via %s", attack_mode, engine_ip, target_url)

    t0 = time.time()
    rc, out = 0, b""
    try:
        out, _err, rc = manager.exec_obj(attacker, cmd, stream=False)
    except Exception as e:
        log.warning("exploit exec raised: %s", e)
        rc = -1

    events = parse_exploit_events((out or b"").decode(errors="replace"))
    writes = [e for e in events if e.get("phase") == "modbus_write"]
    for e in events:
        if e.get("phase") == "rce":
            gt.record("rce", t=e["t"], mode=attack_mode)
    for e in writes:
        gt.record("modbus_write", t=e.get("t_send", e["t"]), mode=attack_mode,
                  register=e.get("register"), register_name=REGISTER_NAMES.get(e.get("register")),
                  value=e.get("value"), ok=e.get("ok"), attempt=e.get("attempt"),
                  source="pivot", unauthorized=True)
    if not writes:  # exploit output lost: keep a coarse record rather than none
        for t in targets:
            gt.record("modbus_write", mode=attack_mode, register=t["register"],
                      register_name=t["name"], value=t["value"], source="pivot",
                      unauthorized=True, approximate=True)
    gt.record("attack_end", mode=attack_mode, rc=rc, duration_s=round(time.time() - t0, 3))
    log.info("Active attack finished (rc=%s, %d writes recorded)", rc, len(writes))
    return rc


# ── tree-guided driver (reactive attacker) ───────────────────────────────────
def drive_attack_planned(manager, machines, gt, kg, target_url, engine_ip, engine_port,
                         profile="opportunistic", goal=None, seed=None, dwell=0.0,
                         max_steps=12, interval=0.5, emit=None, ot_write_path="/ot_write.py"):
    """Run a tree-guided episode: an AttackPlanner chooses each step and we exec
    it on the attacker container, recording ground truth (attack_start, per-step
    plan_step, rce, modbus_write, attack_end). Returns the planner summary.

    Imported lazily so the host module needs networkx/soar only on this path."""
    from cyberrange.planes.attack.planner import steps as S
    from cyberrange.planes.attack.planner.planner import AttackPlanner
    from cyberrange.planes.defense.soar import trees

    tree = trees.cps_attack_tree(kg)
    planner = AttackPlanner(tree, kg, profile=profile, goal=goal, seed=seed, max_steps=max_steps)
    ctx = {"target_url": target_url, "engine_ip": engine_ip, "engine_port": engine_port,
           "ot_write_path": ot_write_path, "interval": interval}
    attacker = machines["attacker"]
    emit = emit or (lambda *a, **k: None)

    gt.record("attack_start", mode=f"planner:{profile}", target_url=target_url,
              engine_ip=engine_ip, engine_port=engine_port, goal=goal, dwell=dwell)
    log.info("Driving tree-guided attack (profile=%s goal=%s dwell=%ss)", profile, goal, dwell)

    def exec_step(node):
        cmd = (f'bash -c "set -o pipefail; PYTHONUNBUFFERED=1 {S.step_command(node, ctx)} '
               f'2>&1 | tee -a exploit.log"')
        t0 = time.time()
        try:
            out, _err, _rc = manager.exec_obj(attacker, cmd, stream=False)
            text = (out or b"").decode(errors="replace")
        except Exception as e:
            log.warning("step %s exec raised: %s", node, e)
            text = ""
        res = S.parse_outcome(node, text)
        for e in res["phases"]:
            if e.get("phase") == "modbus_write":
                gt.record("modbus_write", t=e.get("t_send", e.get("t", t0)),
                          mode=f"planner:{profile}", register=e.get("register"),
                          register_name=REGISTER_NAMES.get(e.get("register")),
                          value=e.get("value"), ok=e.get("ok"), attempt=e.get("attempt"),
                          source="pivot", unauthorized=True)
        if node in STAGE_TO_GT and res["ok"]:
            gt.record(STAGE_TO_GT[node], mode=f"planner:{profile}")
        return res

    def on_step(**entry):
        gt.record("plan_step", mode=f"planner:{profile}", **entry)
        emit("plan_step", **entry)

    summary = planner.run(exec_step, sleep=time.sleep, record=on_step, dwell=dwell)
    gt.record("attack_end", mode=f"planner:{profile}", success=summary["success"],
              stage_reached=summary["stage_reached"], writes_ok=summary["writes_ok"])
    log.info("Tree-guided attack done: stage=%s success=%s", summary["stage_reached"],
             summary["success"])
    return summary
