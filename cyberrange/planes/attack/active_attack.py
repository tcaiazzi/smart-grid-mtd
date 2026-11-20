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

from cyberrange.planes.defense import ot_registers as reg

log = logging.getLogger("active_attack")

STAGE_TO_GT = {"it_access": "rce"}  # map the access step to the kind metrics expect


def _write(addr, value):
    return {"register": addr, "name": reg.ACTUATOR_REGISTERS[addr][0], "value": value}


_MANUAL = _write(reg.HR_CTRL_MODE, float(reg.CTRL_MANUAL))


def attack_targets(feeder=None):
    """Attack mode -> the actuator writes it performs on ``feeder`` (its
    description in the plant; default: the default plant's): the values mirror
    exploit_client's (a guest module this host module does not import), the
    registers are the plant contract's."""
    rated = float((feeder or reg.feeder(reg.plant()))["dg_rating_kw"])
    setpoint = reg.HR_DG_SETPOINT
    return {
        "setpoint-overvoltage": [_write(setpoint, round(rated * 10 / 3, 1))],
        "breaker-open": [_write(reg.HR_SWITCH_CMD, 1.0)],
        "manual-hijack": [_MANUAL, _write(setpoint, rated)],
        "slow-ramp": [_MANUAL, _write(setpoint, rated)],  # where the ramp ends
        "setpoint-oscillation": [_MANUAL, _write(setpoint, rated - 5.0), _write(setpoint, 5.0)],
        "breaker-chatter": [_write(reg.HR_SWITCH_CMD, 1.0)],
        "meas-fdi": [],  # no write of the attacker's: the PLC's readings are falsified
    }


REGISTER_NAMES = {addr: spec[0] for addr, spec in reg.ACTUATOR_REGISTERS.items()}
# Writes that are in the legitimate envelope and come from an allowed host:
# invisible to the source/range rules (the point of the stealthy mode).
STEALTHY_MODES = {"manual-hijack", "slow-ramp", "setpoint-oscillation", "meas-fdi"}


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


def drive_attack(
    manager,
    attacker,
    gt,
    target_url,
    engine_ip,
    engine_port,
    attack_mode="setpoint-overvoltage",
    repeat=None,
    interval=0.5,
    unit=None,
    plant=None,
    via=None,
):
    """Run the exploit chain on the attacker container and record ground truth.

    ``target_url`` is the way in (the application of host ``via``), ``unit`` the
    feeder of ``plant`` the writes go to (default: its first). Each Modbus write
    is recorded with the time the attacker actually issued it (from
    exploit_client's JSON lines), not when the exec returned.
    Returns the exploit_client return code (0 on success)."""
    plant = reg.plant(plant)
    unit = reg.units(plant)[0] if unit is None else unit
    targets = attack_targets(reg.feeder(plant, unit)).get(attack_mode, [])
    rep = f" --repeat {repeat}" if repeat is not None else ""
    cmd = (
        f'bash -c "set -o pipefail; PYTHONUNBUFFERED=1 python3 exploit_client.py '
        f"--target-url {target_url} --engine-ip {engine_ip} --engine-port {engine_port} "
        f"--unit-id {unit} --plant-b64 {reg.plant_b64(plant)} "
        f'--attack {attack_mode}{rep} --interval {interval} 2>&1 | tee exploit.log"'
    )

    gt.record(
        "attack_start",
        mode=attack_mode,
        target_url=target_url,
        via=via,
        unit=unit,
        engine_ip=engine_ip,
        engine_port=engine_port,
        writes=targets,
        stealthy=attack_mode in STEALTHY_MODES,
        repeat=repeat,
    )
    log.info(
        "Driving active attack (%s) against %s unit %s via %s",
        attack_mode,
        engine_ip,
        unit,
        target_url,
    )

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
        elif e.get("phase") in ("ot_foothold", "ot_aitm"):
            gt.record(e["phase"], t=e["t"], mode=attack_mode, ok=e.get("ok"))
        elif e.get("phase") == "fdi":
            fdi = {k: e.get(k) for k in ("ok", "t_end", "readings", "sent")}
            gt.record("fdi", t=e.get("t_start") or e["t"], mode=attack_mode, **fdi)
    for e in writes:
        gt.record(
            "modbus_write",
            t=e.get("t_send", e["t"]),
            mode=attack_mode,
            unit=e.get("unit", unit),
            register=e.get("register"),
            register_name=REGISTER_NAMES.get(e.get("register")),
            value=e.get("value"),
            ok=e.get("ok"),
            attempt=e.get("attempt"),
            source="pivot",
            unauthorized=True,
        )
    if not writes:  # exploit output lost (or a mode with no writes): the hint, if any
        for t in targets:
            gt.record(
                "modbus_write",
                mode=attack_mode,
                unit=unit,
                register=t["register"],
                register_name=t["name"],
                value=t["value"],
                source="pivot",
                unauthorized=True,
                approximate=True,
            )
    gt.record("attack_end", mode=attack_mode, rc=rc, duration_s=round(time.time() - t0, 3))
    log.info("Active attack finished (rc=%s, %d writes recorded)", rc, len(writes))
    return rc
