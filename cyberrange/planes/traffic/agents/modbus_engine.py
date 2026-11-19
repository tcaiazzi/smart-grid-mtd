#!/usr/bin/env python3
"""modbus_engine.py — the physical engine node: wraps the pandapower digital
twin (grid_sim.py) behind a Modbus/TCP server (pymodbus). It is the Modbus
*slave*; the PLC (plc_controller.py) is the master that polls its sensors and
writes its actuators.

Copied flat onto the engine machine (see the scenario's guest_files.py);
imports grid_sim and ot_registers as flat modules.

Each feeder of the plant (ot_registers.plant, --plant-b64) is a Modbus unit of
its own, with the same register map. Two threads share the datastore:
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


def _build_context(st):
    """One slave context per feeder, under its unit id: holding registers seeded
    to the feeder's nominal actuator setpoints, input registers zeroed (filled
    on the first step)."""
    slaves = {}
    for f in st.feeders:
        hr_init = [0] * reg.ACTUATOR_COUNT
        scale = reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][1]
        hr_init[reg.HR_DG_SETPOINT] = reg.encode(f.spec["dg_kw"], scale)
        hr_init[reg.HR_SWITCH_CMD] = 0  # breaker closed
        hr_init[reg.HR_CTRL_MODE] = reg.CTRL_AUTO
        slaves[f.unit] = ModbusSlaveContext(
            ir=ModbusSequentialDataBlock(0, [0] * reg.SENSOR_COUNT),
            hr=ModbusSequentialDataBlock(0, hr_init),
            zero_mode=True,
        )
    return ModbusServerContext(slaves=slaves, single=False), slaves


def _read_actuators(slave) -> dict:
    """Decode the holding registers the master has written into engineering
    units for grid_sim.step_grid()."""
    raw = slave.getValues(0x03, 0, reg.ACTUATOR_COUNT)
    out = {
        name: reg.decode(raw[a], scale)
        for a, (name, scale, _lo, _hi) in reg.ACTUATOR_REGISTERS.items()
    }
    # Not a physical actuator (grid_sim ignores it) but recorded in every frame
    # so metrics can tell how long control authority was in MANUAL.
    out["ctrl_mode"] = int(raw[reg.HR_CTRL_MODE])
    return out


def _write_sensors(slave, readings: dict):
    """Encode one feeder's readings into its input registers."""
    words = [0] * reg.SENSOR_COUNT
    for a, (name, scale, _unit) in reg.SENSOR_REGISTERS.items():
        words[a] = reg.encode(float(readings[name]), scale)
    slave.setValues(0x04, 0, words)


def _step(slaves, st, interval):
    """One physics step: actuators in, frame out, input registers refreshed."""
    actuators = {unit: _read_actuators(slave) for unit, slave in slaves.items()}
    frame = grid_sim.step_grid(st, actuators, dt_s=interval)
    for unit, readings in grid_sim.unit_readings(st, frame).items():
        _write_sensors(slaves[unit], readings)
    frame["actuators"] = actuators[st.feeders[0].unit]
    if "units" in frame:
        for unit, a in actuators.items():
            frame["units"][str(unit)]["actuators"] = a
    return frame


def _stepper(slaves, st, interval, duration, frame_log, stop):
    """Advance the physics once per `interval` until `duration` (0 = forever)."""
    start = time.time()
    while not stop.is_set():
        frame = _step(slaves, st, interval)
        if frame_log:
            frame_log.write(json.dumps(frame) + "\n")
            frame_log.flush()
        if frame["abnormal"]:
            log.warning(
                "ABNORMAL step=%d v_load=%.3f v_dg=%.3f setpoint=%.1f switch_open=%s",
                frame["step"],
                frame["v_load"],
                frame["v_dg"],
                frame["actuators"]["dg_setpoint"],
                frame["switch_open"],
            )
        else:
            log.info(
                "step=%d v_load=%.3f v_dg=%.3f line=%.1f%% p_grid=%.1f",
                frame["step"],
                frame["v_load"],
                frame["v_dg"],
                frame["line_load"],
                frame["p_grid"],
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
    ap.add_argument("--plant-b64", default=None, help="the plant (default: the default plant)")
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

    st = grid_sim.build_grid(seed=args.seed, plant=args.plant_b64)
    ctx, slaves = _build_context(st)
    # Prime the input registers with the nominal state before the server starts.
    _step(slaves, st, args.interval)

    frame_log = open(args.frame_log, "a", buffering=1) if args.frame_log else None
    stop = threading.Event()
    stepper = threading.Thread(
        target=_stepper,
        args=(slaves, st, args.interval, args.duration, frame_log, stop),
        daemon=True,
    )
    stepper.start()
    log.info("engine serving Modbus/TCP on %s:%d units=%s", args.host, args.port, sorted(slaves))

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
