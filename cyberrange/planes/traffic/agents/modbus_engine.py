#!/usr/bin/env python3
"""modbus_engine.py — the physical engine node: wraps the pandapower digital
twin (grid_sim.py) behind a Modbus/TCP server (pymodbus). It is the Modbus
*slave*; the PLC (plc_controller.py) is the master that polls its sensors and
writes its actuators.

Copied flat onto the engine machine (see the scenario's guest_files.py);
imports grid_sim and ot_registers as flat modules.

Two threads share one pymodbus datastore:
  - a background TCP server answering the PLC's reads/writes, and
  - a stepping loop that, once per interval, reads the actuator holding
    registers the master has written, advances the power flow, and refreshes the
    sensor input registers.
An unauthorized Modbus write to an actuator register therefore propagates into
the physics on the very next step, exactly as on a real PLC/field device.

Sensors (engine -> master) are INPUT registers (fc 0x04); actuators
(master -> engine) are HOLDING registers (fc 0x03/0x06/0x10). See ot_registers.
"""

import argparse
import json
import logging
import threading
import time

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusSlaveContext
from pymodbus.server import StartTcpServer

import grid_sim
import ot_registers as reg

log = logging.getLogger("modbus_engine")


def _build_context():
    """One slave context: holding registers seeded to the nominal actuator
    setpoints, input registers zeroed (filled on the first step)."""
    hr_init = [0] * reg.ACTUATOR_COUNT
    hr_init[reg.HR_DG_SETPOINT] = reg.encode(
        grid_sim.DG_NOMINAL_KW, reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1]
    )
    hr_init[reg.HR_SWITCH_CMD] = 0  # breaker closed
    hr_init[reg.HR_CTRL_MODE] = reg.CTRL_AUTO
    slave = ModbusSlaveContext(
        ir=ModbusSequentialDataBlock(0, [0] * reg.SENSOR_COUNT),
        hr=ModbusSequentialDataBlock(0, hr_init),
        zero_mode=True,
    )
    ctx = ModbusServerContext(slaves={reg.UNIT_ID: slave}, single=False)
    return ctx, slave


def _read_actuators(slave) -> dict:
    """Decode the holding registers the master has written into engineering
    units for grid_sim.step_grid()."""
    raw = slave.getValues(0x03, 0, reg.ACTUATOR_COUNT)
    return {
        "dg_setpoint": reg.decode(
            raw[reg.HR_DG_SETPOINT], reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1]
        ),
        "switch_cmd": reg.decode(
            raw[reg.HR_SWITCH_CMD], reg.ACTUATOR_REGISTERS[reg.HR_SWITCH_CMD][1]
        ),
        # Not a physical actuator (grid_sim ignores it) but recorded in every
        # frame so metrics can tell how long control authority was in MANUAL.
        "ctrl_mode": int(raw[reg.HR_CTRL_MODE]),
    }


def _write_sensors(slave, sensors: dict):
    """Encode grid_sim sensor outputs into the input registers."""
    words = [0] * reg.SENSOR_COUNT
    words[reg.IR_V_LOAD] = reg.encode(sensors["v_load"], reg.SENSOR_REGISTERS[reg.IR_V_LOAD][1])
    words[reg.IR_V_DG] = reg.encode(sensors["v_dg"], reg.SENSOR_REGISTERS[reg.IR_V_DG][1])
    words[reg.IR_LINE_LOAD] = reg.encode(
        sensors["line_load"], reg.SENSOR_REGISTERS[reg.IR_LINE_LOAD][1]
    )
    words[reg.IR_P_LOAD] = reg.encode(sensors["p_load"], reg.SENSOR_REGISTERS[reg.IR_P_LOAD][1])
    words[reg.IR_P_DG] = reg.encode(sensors["p_dg"], reg.SENSOR_REGISTERS[reg.IR_P_DG][1])
    words[reg.IR_ABNORMAL] = int(sensors["abnormal"])
    slave.setValues(0x04, 0, words)


def _stepper(slave, st, interval, duration, frame_log, stop):
    """Advance the physics once per `interval` until `duration` (0 = forever)."""
    start = time.time()
    while not stop.is_set():
        actuators = _read_actuators(slave)
        sensors = grid_sim.step_grid(st, actuators, dt_s=interval)
        _write_sensors(slave, sensors)
        frame = {**sensors, "actuators": actuators}
        if frame_log:
            frame_log.write(json.dumps(frame) + "\n")
            frame_log.flush()
        if sensors["abnormal"]:
            log.warning(
                "ABNORMAL step=%d v_load=%.3f v_dg=%.3f setpoint=%.1f switch_open=%s",
                sensors["step"],
                sensors["v_load"],
                sensors["v_dg"],
                actuators["dg_setpoint"],
                sensors["switch_open"],
            )
        else:
            log.info(
                "step=%d v_load=%.3f v_dg=%.3f line=%.1f%% p_grid=%.1f",
                sensors["step"],
                sensors["v_load"],
                sensors["v_dg"],
                sensors["line_load"],
                sensors["p_grid"],
            )
        if duration and (time.time() - start) >= duration:
            stop.set()
            break
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description="Modbus/TCP physical engine (pandapower twin)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=reg.MODBUS_PORT)
    ap.add_argument(
        "--interval", type=float, default=grid_sim.STEP_DT_S, help="seconds between physics steps"
    )
    ap.add_argument(
        "--duration", type=float, default=0.0, help="run this many seconds then exit (0 = forever)"
    )
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument(
        "--frame-log", default=None, help="append one JSON physics frame per step to this file"
    )
    ap.add_argument("--log-file", default=None)
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        filename=args.log_file or None,
    )

    st = grid_sim.build_grid(seed=args.seed)
    ctx, slave = _build_context()
    # Prime the input registers with the nominal state before the server starts.
    _write_sensors(slave, grid_sim.step_grid(st, _read_actuators(slave), dt_s=args.interval))

    frame_log = open(args.frame_log, "a", buffering=1) if args.frame_log else None
    stop = threading.Event()
    stepper = threading.Thread(
        target=_stepper,
        args=(slave, st, args.interval, args.duration, frame_log, stop),
        daemon=True,
    )
    stepper.start()
    log.info("engine serving Modbus/TCP on %s:%d unit=%d", args.host, args.port, reg.UNIT_ID)

    server_thread = threading.Thread(
        target=StartTcpServer,
        kwargs={"context": ctx, "address": (args.host, args.port)},
        daemon=True,
    )
    server_thread.start()

    try:
        while not stop.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        if frame_log:
            frame_log.close()


if __name__ == "__main__":
    main()
