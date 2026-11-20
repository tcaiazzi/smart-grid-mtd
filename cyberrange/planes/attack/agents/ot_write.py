#!/usr/bin/env python3
"""ot_write.py — write actuator registers on the physical engine, over
Modbus/TCP, with the pymodbus client the host already has.

Copied onto the HMI host and the boundary firewall (see the scenario's
guest_files.py), pymodbus only. Two parties run it: the attacker, through the
command execution it gained on the HMI (via vuln_app.py), to pivot across the
IT/OT boundary; and the automated response, from the firewall, to put the plant
back. Both need to know whether the plant took the command: a write the engine
refuses (a unit it does not serve, a register it does not have) is reported as
failed, never as done — or an attack on the wrong feeder would be recorded as
one that landed, and a response as applied.

Usage: ot_write.py <engine_ip> <port> [--unit=<unit_id>] <register>=<raw_value> [...]
       ot_write.py <engine_ip> <port> <register> <raw_value> [unit_id]   (legacy form)
`raw_value` is the already-scaled 16-bit register word (see ot_registers.encode).
Several writes go out back to back over ONE TCP connection, in order, each as
a write-single-register (fc 0x06). Prints ``ot_write ok`` and exits 0 only if
every one was accepted.
"""

import sys

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

import ot_registers as reg


def write_registers(engine_ip, port, writes, unit=reg.UNIT_ID, timeout=5.0):
    """Issue the writes [(register, raw_value), ...] to ``unit``, in order over
    one connection, stopping at the first the engine does not accept. Returns
    [(register, raw_value, error)], ``error`` None for an accepted write."""
    client = ModbusTcpClient(engine_ip, port=port, timeout=timeout)
    if not client.connect():
        return [(writes[0][0], writes[0][1], f"no connection to {engine_ip}:{port}")]
    done = []
    try:
        for register, raw_value in writes:
            try:
                rr = client.write_register(register, raw_value & 0xFFFF, slave=unit)
                error = str(rr) if rr.isError() else None
            except ModbusException as e:
                error = str(e)
            done.append((register, raw_value, error))
            if error:
                break
    finally:
        client.close()
    return done


def write_single_register(engine_ip, port, register, raw_value, unit=reg.UNIT_ID, timeout=5.0):
    return write_registers(engine_ip, port, [(register, raw_value)], unit=unit, timeout=timeout)[0]


def parse_args(argv):
    """-> (engine_ip, port, [(register, raw)], unit)."""
    if len(argv) < 4:
        raise ValueError("usage")
    engine_ip, port, rest = argv[1], int(argv[2]), argv[3:]
    # The feeder a plant of several serves as its own Modbus unit.
    unit = next((int(a.split("=", 1)[1]) for a in rest if a.startswith("--unit=")), reg.UNIT_ID)
    rest = [a for a in rest if not a.startswith("--unit=")]
    if rest and "=" in rest[0]:
        writes = [tuple(int(x) for x in a.split("=", 1)) for a in rest]
        return engine_ip, port, writes, unit
    if len(rest) < 2:
        raise ValueError("usage")
    unit = int(rest[2]) if len(rest) > 2 else unit
    return engine_ip, port, [(int(rest[0]), int(rest[1]))], unit


def main(argv):
    try:
        engine_ip, port, writes, unit = parse_args(argv)
    except ValueError:
        print(
            "usage: ot_write.py <engine_ip> <port> [--unit=<unit>] <reg>=<raw> [<reg>=<raw> ...]",
            file=sys.stderr,
        )
        return 2
    done = write_registers(engine_ip, port, writes, unit=unit)
    refused = [(r, raw, e) for r, raw, e in done if e]
    if refused:
        r, raw, e = refused[0]
        print(f"ot_write failed: unit {unit} register {r}={raw}: {e}")
        return 1
    print(f"ot_write ok: unit {unit}", " ".join(f"{r}={raw}" for r, raw, _e in done))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
