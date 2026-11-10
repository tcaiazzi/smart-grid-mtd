#!/usr/bin/env python3
"""hmi_client.py — the legitimate IT-zone HMI/SCADA client of the cyber-physical
scenario. It is the one host the IT/OT boundary firewall lets reach the physical
engine's Modbus port, and it is also where the vulnerable diagnostics web app
runs (vuln_app.py): the attacker compromises THIS host and pivots from it, so
its traffic is the "normal" the DPI sensor must tell the attack apart from.

Copied flat onto the hmi machine (see network_scenario/guest_files.py); imports
ot_registers as a flat module. Over ONE persistent Modbus/TCP session it:
  1. polls the sensor INPUT registers (fc 0x04) and the actuator HOLDING
     registers (fc 0x03) every --poll-interval seconds (historian / display),
  2. every ~--action-every seconds (seeded jitter) performs an operator
     dispatch: take MANUAL control (CTRL_MODE=1), command a SAFE in-range DG
     setpoint, hold it for --hold seconds, then hand control back to AUTO.

Those legitimate manual windows are exactly what an attacker's manual-hijack
looks like at the register level — which is what makes detection non-trivial.
"""

import argparse
import logging
import random
import time

from pymodbus.client import ModbusTcpClient

import ot_registers as reg

log = logging.getLogger("hmi")

DG_SCALE = reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1]
SAFE_SETPOINT_KW = (15.0, 35.0)   # operator dispatches stay well inside the safe band


def plan_actions(rng, start, horizon, every, jitter, hold):
    """Seeded operator schedule: list of (t_take, t_release, setpoint_kw)."""
    actions = []
    t = start + every + rng.uniform(-jitter, jitter)
    while t < start + horizon:
        sp = round(rng.uniform(*SAFE_SETPOINT_KW), 1)
        actions.append((t, t + hold, sp))
        t += hold + every + rng.uniform(-jitter, jitter)
    return actions


def _write(client, register, raw, unit):
    wr = client.write_register(register, raw, slave=unit)
    if wr.isError():
        raise IOError(f"write_register({register}) failed: {wr}")


def _read_holding(client, unit):
    hr = client.read_holding_registers(0, reg.ACTUATOR_COUNT, slave=unit)
    if hr.isError():
        raise IOError(f"read_holding_registers failed: {hr}")
    raw = hr.registers[reg.HR_DG_SETPOINT]
    return {"ctrl_mode": hr.registers[reg.HR_CTRL_MODE], "raw_setpoint": raw,
            "dg_setpoint": reg.decode(raw, DG_SCALE)}


def main():
    ap = argparse.ArgumentParser(description="Legitimate HMI / SCADA Modbus client")
    ap.add_argument("--engine-host", required=True)
    ap.add_argument("--port", type=int, default=reg.MODBUS_PORT)
    ap.add_argument("--unit-id", type=int, default=reg.UNIT_ID)
    ap.add_argument("--poll-interval", type=float, default=2.0)
    ap.add_argument("--action-every", type=float, default=12.0)
    ap.add_argument("--action-jitter", type=float, default=3.0)
    ap.add_argument("--hold", type=float, default=5.0)
    ap.add_argument("--duration", type=float, default=0.0, help="0 = forever")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    rng = random.Random(args.seed)

    client = ModbusTcpClient(args.engine_host, port=args.port)
    while not client.connect():
        log.warning("engine %s:%d not reachable yet; retrying", args.engine_host, args.port)
        time.sleep(1.0)
    log.info("HMI connected to engine %s:%d", args.engine_host, args.port)

    start = time.time()
    horizon = args.duration if args.duration else 24 * 3600.0
    actions = plan_actions(rng, start, horizon, args.action_every, args.action_jitter, args.hold)
    manual_until, my_raw = None, None
    next_poll = start
    try:
        while True:
            now = time.time()
            if args.duration and now - start >= args.duration:
                break
            try:
                if manual_until is None and actions and now >= actions[0][0]:
                    _t, t_rel, sp = actions.pop(0)
                    hr = _read_holding(client, args.unit_id)
                    if hr["ctrl_mode"] == reg.CTRL_MANUAL:
                        # Someone else holds control authority: an operator does
                        # not fight it, the scheduled dispatch is skipped.
                        log.info("operator: control already MANUAL (foreign), skip dispatch")
                    else:
                        _write(client, reg.HR_CTRL_MODE, reg.CTRL_MANUAL, args.unit_id)
                        _write(client, reg.HR_DG_SETPOINT, reg.encode(sp, DG_SCALE), args.unit_id)
                        manual_until, my_raw = t_rel, reg.encode(sp, DG_SCALE)
                        log.info("operator: MANUAL, dispatch DG=%.1fkW", sp)
                elif manual_until is not None and now >= manual_until:
                    hr = _read_holding(client, args.unit_id)
                    if hr["raw_setpoint"] == my_raw:
                        _write(client, reg.HR_CTRL_MODE, reg.CTRL_AUTO, args.unit_id)
                        log.info("operator: back to AUTO")
                    else:
                        log.info("operator: foreign setpoint %.1fkW in force, not handing back",
                                 hr["dg_setpoint"])
                    manual_until = None
                if now >= next_poll:
                    ir = client.read_input_registers(0, reg.SENSOR_COUNT, slave=args.unit_id)
                    hr = client.read_holding_registers(0, reg.ACTUATOR_COUNT, slave=args.unit_id)
                    if not ir.isError() and not hr.isError():
                        log.info("poll v_load=%.3f v_dg=%.3f mode=%d setpoint=%.1fkW",
                                 reg.decode(ir.registers[reg.IR_V_LOAD], 1000.0),
                                 reg.decode(ir.registers[reg.IR_V_DG], 1000.0),
                                 hr.registers[reg.HR_CTRL_MODE],
                                 reg.decode(hr.registers[reg.HR_DG_SETPOINT], DG_SCALE))
                    next_poll = now + args.poll_interval
            except Exception as e:  # keep the session alive across transient errors
                log.warning("hmi error: %s", e)
                if not client.connected:
                    client.connect()
            time.sleep(0.1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
