#!/usr/bin/env python3
"""
pcap_parser.py
--------------
Parse a pcap file and reconstruct TCP flows carrying MQTT over TLS.
Only TLS Application Data records (type 0x17) are counted — TCP control
packets (SYN, FIN, ACK-only) and TLS handshake records are discarded so
they do not pollute the IAT series.

Usage:
    python3 pcap_parser.py capture.pcap [--port 8883]
"""

import argparse
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import dpkt


TLS_APP_DATA = 0x17   # record type that carries MQTT payload


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    timestamps: List[float] = field(default_factory=list)
    lengths: List[int] = field(default_factory=list)         # total IP packet length
    directions: List[int] = field(default_factory=list)      # +1 forward, -1 reverse
    tls_record_lengths: List[int] = field(default_factory=list)  # length field from TLS header


def ip_to_str(addr: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET if len(addr) == 4 else socket.AF_INET6, addr)
    except Exception:
        return addr.hex()


def is_tls_app_data(tcp_payload: bytes) -> Optional[int]:
    """
    Return the TLS record length if the payload starts with a
    TLS Application Data record (0x17 0x03 0x0x ...), else None.
    A single TCP segment may contain multiple TLS records; we check
    only the first one — if it is Application Data the segment carries
    MQTT ciphertext and is worth counting.
    """
    if len(tcp_payload) < 5:
        return None
    record_type = tcp_payload[0]
    major, minor = tcp_payload[1], tcp_payload[2]
    # TLS major version must be 3 (covers TLS 1.0 / 1.2 / 1.3)
    if record_type != TLS_APP_DATA or major != 3:
        return None
    record_len = struct.unpack(">H", tcp_payload[3:5])[0]
    return record_len


def parse_pcap(path: str, mqtt_ports: List[int]) -> Dict[tuple, Flow]:
    flows: Dict[tuple, Flow] = {}

    with open(path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
            link_type = pcap.datalink()
        except Exception as e:
            print(f"[!] Cannot open pcap: {e}")
            sys.exit(1)

        for ts, buf in pcap:
            try:
                # --- Link layer decapsulation ---
                if link_type == dpkt.pcap.DLT_EN10MB:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                elif link_type == dpkt.pcap.DLT_RAW:
                    ip = dpkt.ip.IP(buf)
                elif link_type == 113:  # Linux cooked capture
                    ip = dpkt.ip.IP(buf[2:])
                else:
                    continue

                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue

                tcp = ip.data
                src_ip   = ip_to_str(ip.src)
                dst_ip   = ip_to_str(ip.dst)
                src_port = tcp.sport
                dst_port = tcp.dport

                # --- Port filter ---
                if src_port not in mqtt_ports and dst_port not in mqtt_ports:
                    continue

                # --- TLS Application Data filter ---
                # tcp.data is the TCP payload (bytes after the TCP header)
                tls_len = is_tls_app_data(bytes(tcp.data))
                if tls_len is None:
                    continue  # handshake, change-cipher-spec, alert, or empty ACK

                # --- Canonical bidirectional flow key ---
                a = (src_ip, src_port)
                b = (dst_ip, dst_port)
                forward = a <= b
                ckey = (min(a, b), max(a, b))
                direction = +1 if forward else -1

                if ckey not in flows:
                    flows[ckey] = Flow(
                        src_ip   = src_ip   if forward else dst_ip,
                        dst_ip   = dst_ip   if forward else src_ip,
                        src_port = src_port if forward else dst_port,
                        dst_port = dst_port if forward else src_port,
                    )

                flows[ckey].timestamps.append(float(ts))
                flows[ckey].lengths.append(len(buf))
                flows[ckey].directions.append(direction)
                flows[ckey].tls_record_lengths.append(tls_len)

            except Exception:
                continue

    return flows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--port", type=int, nargs="+", default=[8883])
    args = parser.parse_args()

    flows = parse_pcap(args.pcap, args.port)

    print(f"{'Flow':<50} {'Pkts':>5} {'Duration(s)':>12}")
    print("-" * 70)
    for flow in sorted(flows.values(), key=lambda f: -len(f.timestamps)):
        fid = f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}"
        n   = len(flow.timestamps)
        dur = flow.timestamps[-1] - flow.timestamps[0] if n > 1 else 0.0
        print(f"{fid:<50} {n:>5} {dur:>12.2f}")

    print(f"\nTotal flows: {len(flows)}")


if __name__ == "__main__":
    main()