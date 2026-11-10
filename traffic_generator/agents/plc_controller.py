#!/usr/bin/env python3
"""plc_controller.py — the PLC: the Modbus *master* that drives the physical
engine (modbus_engine.py) over Modbus/TCP. This is the legitimate industrial
traffic generator of the cyber-physical scenario (the counterpart of
simple_client.py in the MQTT scenario).

Copied flat onto the plc machine (see network_scenario/guest_files.py); imports
ot_registers as a flat module. Each cycle it:
  1. reads the sensor INPUT registers (bus voltages, line loading, powers),
  2. reads the actuator HOLDING registers (fc 0x03): control mode + setpoint,
  3. in AUTO, runs a small control law that keeps the worst bus voltage in band
     and relaxes back to the nominal setpoint, then writes the DG setpoint
     (fc 0x06) — the only actuator it touches; the breaker stays closed.
     In MANUAL (operator authority, set from the HMI) it keeps reading but does
     not write: this is the hand-off an attacker abuses to make an impact stick.

The PLC is the authorized writer: its source IP is what the DPI sensor treats as
legitimate, so its in-range setpoint writes must NOT raise a finding. An
unauthorized write (different source) or an out-of-range value is the attack.
"""

import argparse
import logging
import time

from pymodbus.client import ModbusTcpClient

import ot_registers as reg

log = logging.getLogger("plc")

DG_SET = reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT]  # (name, scale, lo, hi)
V_TARGET_LOW  = reg.V_REG_LOW
V_TARGET_HIGH = reg.V_REG_HIGH
SETPOINT_STEP_KW = 2.0
RELAX_MARGIN_PU = 0.01


def read_sensors(client, unit) -> dict:
    rr = client.read_input_registers(0, reg.SENSOR_COUNT, slave=unit)
    if rr.isError():
        raise IOError(f"read_input_registers failed: {rr}")
    regs = rr.registers
    return {
        "v_load": reg.decode(regs[reg.IR_V_LOAD], reg.SENSOR_REGISTERS[reg.IR_V_LOAD][1]),
        "v_dg":   reg.decode(regs[reg.IR_V_DG],   reg.SENSOR_REGISTERS[reg.IR_V_DG][1]),
        "line_load": reg.decode(regs[reg.IR_LINE_LOAD], reg.SENSOR_REGISTERS[reg.IR_LINE_LOAD][1]),
        "p_load": reg.decode(regs[reg.IR_P_LOAD], reg.SENSOR_REGISTERS[reg.IR_P_LOAD][1]),
        "p_dg":   reg.decode(regs[reg.IR_P_DG],   reg.SENSOR_REGISTERS[reg.IR_P_DG][1]),
        "abnormal": int(regs[reg.IR_ABNORMAL]),
    }


def read_holding(client, unit) -> dict:
    """Current actuator state on the engine (fc 0x03): control mode + the DG
    setpoint actually in force (which may have been written by someone else)."""
    rr = client.read_holding_registers(0, reg.ACTUATOR_COUNT, slave=unit)
    if rr.isError():
        raise IOError(f"read_holding_registers failed: {rr}")
    regs = rr.registers
    return {
        "dg_setpoint": reg.decode(regs[reg.HR_DG_SETPOINT], DG_SET[1]),
        "ctrl_mode": int(regs[reg.HR_CTRL_MODE]),
    }


def control(sensors: dict, setpoint_kw: float) -> float:
    """Voltage regulation, clamped to the DG envelope.

    Regulates on the WORST bus voltage (the DG bus overvolts first): step the DG
    down on overvoltage, up on undervoltage, and otherwise relax one step back
    toward the nominal setpoint so a disturbance never leaves the DG curtailed."""
    _, _, lo, hi = DG_SET
    v_max = max(sensors["v_load"], sensors["v_dg"])
    v_min = min(sensors["v_load"], sensors["v_dg"])
    if v_max > V_TARGET_HIGH:
        setpoint_kw -= SETPOINT_STEP_KW      # lower DG -> reduce overvoltage
    elif v_min < V_TARGET_LOW:
        setpoint_kw += SETPOINT_STEP_KW      # raise DG -> support voltage
    elif setpoint_kw > reg.DG_NOMINAL_KW:
        setpoint_kw = max(reg.DG_NOMINAL_KW, setpoint_kw - SETPOINT_STEP_KW)
    elif setpoint_kw < reg.DG_NOMINAL_KW and v_max < V_TARGET_HIGH - RELAX_MARGIN_PU:
        # Raising the DG raises the voltage: only relax upward with headroom,
        # otherwise the loop would chatter around the band edge.
        setpoint_kw = min(reg.DG_NOMINAL_KW, setpoint_kw + SETPOINT_STEP_KW)
    return max(lo, min(hi, setpoint_kw))


def decide(sensors: dict, holding: dict, own_last: float):
    """One PLC cycle's decision. Returns (write, setpoint_kw).

    - MANUAL mode: the operator has control authority -> hands off (no write).
    - AUTO mode: start from the setpoint in force on the engine if it is inside
      the legitimate envelope (e.g. an operator dispatch just handed back), else
      reject it and fall back to the PLC's own last command; then regulate."""
    if holding.get("ctrl_mode", reg.CTRL_AUTO) == reg.CTRL_MANUAL:
        return False, own_last
    _, _, lo, hi = DG_SET
    current = holding.get("dg_setpoint")
    base = current if current is not None and lo <= current <= hi else own_last
    return True, control(sensors, base)


def main():
    ap = argparse.ArgumentParser(description="PLC Modbus master / controller")
    ap.add_argument("--engine-host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=reg.MODBUS_PORT)
    ap.add_argument("--unit-id", type=int, default=reg.UNIT_ID)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--duration", type=float, default=0.0, help="0 = forever")
    ap.add_argument("--seed", type=int, default=None)  # reserved for parity
    ap.add_argument("--log-file", default=None)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        filename=args.log_file or None)

    client = ModbusTcpClient(args.engine_host, port=args.port)
    while not client.connect():
        log.warning("engine %s:%d not reachable yet; retrying", args.engine_host, args.port)
        time.sleep(1.0)
    log.info("PLC connected to engine %s:%d unit=%d", args.engine_host, args.port, args.unit_id)

    setpoint_kw = reg.DG_NOMINAL_KW  # start at nominal DG setpoint
    start = time.time()
    polls = 0
    try:
        while True:
            try:
                sensors = read_sensors(client, args.unit_id)
                holding = read_holding(client, args.unit_id)
                write, setpoint_kw = decide(sensors, holding, setpoint_kw)
                if write:
                    word = reg.encode(setpoint_kw, DG_SET[1])
                    wr = client.write_register(reg.HR_DG_SETPOINT, word, slave=args.unit_id)
                    if wr.isError():
                        log.warning("write_register failed: %s", wr)
                polls += 1
                log.info("poll=%d v_load=%.3f v_dg=%.3f line=%.1f%% mode=%s -> %s abn=%d",
                         polls, sensors["v_load"], sensors["v_dg"], sensors["line_load"],
                         "MANUAL" if holding["ctrl_mode"] == reg.CTRL_MANUAL else "auto",
                         f"setpoint={setpoint_kw:.1f}kW" if write
                         else f"hands-off (in force {holding['dg_setpoint']:.1f}kW)",
                         sensors["abnormal"])
            except Exception as e:  # keep the controller alive across transient errors
                log.warning("poll error: %s", e)
                if not client.connected:
                    client.connect()
            if args.duration and (time.time() - start) >= args.duration:
                break
            time.sleep(args.interval)
    finally:
        client.close()


if __name__ == "__main__":
    main()
