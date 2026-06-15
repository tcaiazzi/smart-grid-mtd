#!/usr/bin/env python3
"""
mtd_coordinator.py — MTD coordinator, runs on SEMP

Decides when to hop MQTT parameters and broadcasts SCHEDULE_HOP to all
connected SCMC executors. Waits for HOP_ACK (received) and HOP_DONE
(hop completed) from each executor before considering a hop finished.

Port hopping is realised live via iptables NAT, not by pre-opening every
pool port on mosquitto. mosquitto listens on a single fixed internal port
(--real-port, default 18883); the coordinator installs a PREROUTING REDIRECT
rule so the currently-active pool port is forwarded to it. On each hop the
new port's rule is installed *before* clients migrate, and the old port's
rule is removed only after every executor has reconnected (HOP_DONE), so:
  • exactly one pool port accepts new connections at any time (true MTD), and
  • established connections survive rule removal (conntrack keeps their NAT
    mapping), so nothing breaks for already-connected clients.

Two independent MTD actions are scheduled, each on its own timer:
  • port hop      (--hop-interval): rotate the active broker port (NAT, above).
  • payload padding (--pad-interval): broadcast a new set of size buckets that
    executors pad their MQTT payloads to. Each tick announces a random subset of
    the master --pad-buckets, so the on-wire size distribution keeps moving.

Both actions follow the same "apply in N messages" scheduling and the same
ACK/DONE confirmation pattern.

Usage:
  python3 mtd_coordinator.py \\
      --control-port 9998 \\
      --ip-pool 10.1.0.2 \\
      --port-pool 8883,8884,8885 \\
      --real-port 18883 \\
      --hop-interval 30 \\
      --pad-buckets 256,512,1024 --pad-interval 30
  # add --no-nat to skip iptables (host testing without root / pre-opened ports)

Protocol (TCP, 4-byte length-prefixed JSON):
  HELLO         SCMC → SEMP   {type, scmc_id}
  SCHEDULE_HOP  SEMP → SCMC   {type, seq, action, new_ip, new_port, in_messages}
  HOP_ACK       SCMC → SEMP   {type, seq, scmc_id}
  HOP_DONE      SCMC → SEMP   {type, seq, scmc_id}
  SET_PADDING   SEMP → SCMC   {type, seq, buckets, in_messages}
  PAD_ACK       SCMC → SEMP   {type, seq, scmc_id}
  PAD_DONE      SCMC → SEMP   {type, seq, scmc_id}
  SCHEDULE_SRC_HOP SEMP → SCMC {type, seq, new_src_ip, in_messages}
  SRC_HOP_ACK   SCMC → SEMP   {type, seq, scmc_id}
  SRC_HOP_DONE  SCMC → SEMP   {type, seq, scmc_id}

Besides the broker-side port/IP hop above, the coordinator runs an independent
source-IP hop loop (--scmc-ip-pool / --src-hop-interval): it tells executors to
rebind their OWN local source IP across a pool, so the SCMC publisher is a moving
target too (no iptables — the SCMC rebinds its socket source address).
"""

import argparse
import json
import random
import socket
import struct
import subprocess
import threading
import time


# ── Framing helpers ───────────────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf


def _send_msg(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_msg(sock: socket.socket) -> dict:
    length = struct.unpack(">I", _recv_exact(sock, 4))[0]
    return json.loads(_recv_exact(sock, length))


# ── Coordinator ───────────────────────────────────────────────────────────────

class SEMPCoordinator:
    """
    TCP server that manages the hop schedule for all connected SCMC executors.

    Port hopping is enforced live with iptables NAT (see module docstring):
    mosquitto listens only on real_port, and the coordinator redirects the
    active pool port to it. Set no_nat=True to skip iptables (host testing,
    or a broker already listening on every pool port).

    IP aliases in ip_pool, if used, must already be assigned on the SEMP
    interface — only ports are managed here.
    """

    def __init__(self, control_port: int, ip_pool: list, port_pool: list,
                 hop_interval: float, real_port: int = 18883, no_nat: bool = False,
                 pad_buckets: list = None, pad_interval: float = 30.0,
                 scmc_ip_pool: list = None, src_hop_interval: float = 30.0,
                 freq_pool: list = None, freq_interval: float = 30.0):
        self.control_port = control_port
        self.ip_pool      = ip_pool
        self.port_pool    = port_pool
        self.hop_interval = hop_interval
        self.real_port    = real_port
        self.no_nat       = no_nat
        self.pad_buckets  = sorted(pad_buckets or [])
        self.pad_interval = pad_interval
        self.scmc_ip_pool = scmc_ip_pool or []   # SCMC source IPs (empty = no src hop)
        self.src_hop_interval = src_hop_interval
        self.freq_pool    = freq_pool or []      # publish intervals (≤1 entry = no freq hop)
        self.freq_interval = freq_interval

        self.current_ip   = ip_pool[0]
        self.current_port = port_pool[0]
        self.current_src_ip = self.scmc_ip_pool[0] if self.scmc_ip_pool else None

        self._seq          = 0            # shared across all MTD actions
        self._lock         = threading.Lock()
        self._clients: dict  = {}         # scmc_id → socket
        self._pending_done: dict = {}     # hop seq → set of scmc_ids awaited
        self._hop_old_port: dict = {}     # hop seq → port to vacate on completion
        self._pending_pad_done: dict = {} # padding seq → set of scmc_ids awaited
        self._pending_src_done: dict = {} # src-hop seq → set of scmc_ids awaited
        self._pending_freq_done: dict = {} # freq-hop seq → set of scmc_ids awaited
        self._active_nat: set    = set()  # pool ports with a live REDIRECT rule

    # ── iptables NAT management ──

    def _nat_rule(self, action: str, port: int) -> None:
        """Add (-A), delete (-D) or check (-C) a REDIRECT rule for `port`."""
        subprocess.run(
            ["iptables", "-t", "nat", action, "PREROUTING",
             "-p", "tcp", "--dport", str(port),
             "-j", "REDIRECT", "--to-ports", str(self.real_port)],
            check=(action != "-D"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _nat_add(self, port: int) -> None:
        if self.no_nat or port == self.real_port or port in self._active_nat:
            return
        try:
            self._nat_rule("-A", port)
            self._active_nat.add(port)
            print(f"[coordinator] NAT  {port} → {self.real_port}", flush=True)
        except (OSError, subprocess.CalledProcessError) as e:
            print(f"[coordinator] NAT add {port} failed: {e}", flush=True)

    def _nat_del(self, port: int) -> None:
        if self.no_nat or port == self.real_port or port not in self._active_nat:
            return
        self._nat_rule("-D", port)          # check=False: ignore if already gone
        self._active_nat.discard(port)
        print(f"[coordinator] NAT  {port} closed", flush=True)

    # ── client management ──

    def _register(self, scmc_id: str, sock: socket.socket) -> None:
        with self._lock:
            self._clients[scmc_id] = sock
        print(f"[coordinator] {scmc_id} connected  (total={len(self._clients)})", flush=True)

    def _unregister(self, scmc_id: str, conn: socket.socket) -> None:
        vacated = []
        with self._lock:
            # A make-before-break control reconnect (control-follows-hop or
            # source-IP hop) registers a fresh socket under the same scmc_id
            # BEFORE closing the old one. If the registered socket is no longer
            # this one, this close is a handover, not a death: leave every pending
            # hop/pad/src action and its NAT port untouched. Clearing them here
            # would prematurely vacate the port the client is still using and
            # strand it with "connection refused".
            if self._clients.get(scmc_id) is not conn:
                return
            self._clients.pop(scmc_id, None)
            # Genuine disconnect — don't wait forever on a client that died mid-action.
            for seq in list(self._pending_done):
                self._pending_done[seq].discard(scmc_id)
                if not self._pending_done[seq]:
                    del self._pending_done[seq]
                    port = self._hop_old_port.pop(seq, None)
                    if port is not None:
                        vacated.append(port)
            for seq in list(self._pending_pad_done):
                self._pending_pad_done[seq].discard(scmc_id)
                if not self._pending_pad_done[seq]:
                    del self._pending_pad_done[seq]
            for seq in list(self._pending_src_done):
                self._pending_src_done[seq].discard(scmc_id)
                if not self._pending_src_done[seq]:
                    del self._pending_src_done[seq]
            for seq in list(self._pending_freq_done):
                self._pending_freq_done[seq].discard(scmc_id)
                if not self._pending_freq_done[seq]:
                    del self._pending_freq_done[seq]
        print(f"[coordinator] {scmc_id} disconnected", flush=True)
        for port in vacated:
            self._nat_del(port)

    def _broadcast(self, msg: dict) -> None:
        with self._lock:
            snapshot = list(self._clients.items())
        dead = []
        for scmc_id, sock in snapshot:
            try:
                _send_msg(sock, msg)
            except OSError:
                dead.append(scmc_id)
        if dead:
            with self._lock:
                for d in dead:
                    self._clients.pop(d, None)
            print(f"[coordinator] dropped dead clients: {dead}", flush=True)

    # ── per-client reader thread ──

    def _handle_client(self, conn: socket.socket, addr) -> None:
        scmc_id = None
        try:
            hello = _recv_msg(conn)
            if hello.get("type") != "HELLO":
                return
            scmc_id = hello["scmc_id"]
            self._register(scmc_id, conn)
            while True:
                msg   = _recv_msg(conn)
                mtype = msg.get("type")
                seq   = msg.get("seq")
                if mtype == "HOP_ACK":
                    print(f"[coordinator] HOP_ACK  seq={seq} from {scmc_id}", flush=True)
                elif mtype == "HOP_DONE":
                    print(f"[coordinator] HOP_DONE seq={seq} from {scmc_id}", flush=True)
                    vacated_port = None
                    with self._lock:
                        if seq in self._pending_done:
                            self._pending_done[seq].discard(scmc_id)
                            if not self._pending_done[seq]:
                                del self._pending_done[seq]
                                vacated_port = self._hop_old_port.pop(seq, None)
                    if vacated_port is not None:
                        print(
                            f"[coordinator] hop seq={seq} complete"
                            " — all executors migrated",
                            flush=True,
                        )
                        # Now that everyone is on the new port, close the old one
                        self._nat_del(vacated_port)
                elif mtype == "PAD_ACK":
                    print(f"[coordinator] PAD_ACK  seq={seq} from {scmc_id}", flush=True)
                elif mtype == "PAD_DONE":
                    print(f"[coordinator] PAD_DONE seq={seq} from {scmc_id}", flush=True)
                    completed = False
                    with self._lock:
                        if seq in self._pending_pad_done:
                            self._pending_pad_done[seq].discard(scmc_id)
                            if not self._pending_pad_done[seq]:
                                del self._pending_pad_done[seq]
                                completed = True
                    if completed:
                        print(
                            f"[coordinator] padding seq={seq} applied by all",
                            flush=True,
                        )
                elif mtype == "SRC_HOP_ACK":
                    print(f"[coordinator] SRC_HOP_ACK  seq={seq} from {scmc_id}", flush=True)
                elif mtype == "SRC_HOP_DONE":
                    print(f"[coordinator] SRC_HOP_DONE seq={seq} from {scmc_id}", flush=True)
                    completed = False
                    with self._lock:
                        if seq in self._pending_src_done:
                            self._pending_src_done[seq].discard(scmc_id)
                            if not self._pending_src_done[seq]:
                                del self._pending_src_done[seq]
                                completed = True
                    if completed:
                        print(
                            f"[coordinator] src hop seq={seq} complete"
                            " — all executors rebound source",
                            flush=True,
                        )
                elif mtype == "INTERVAL_ACK":
                    print(f"[coordinator] INTERVAL_ACK  seq={seq} from {scmc_id}", flush=True)
                elif mtype == "INTERVAL_DONE":
                    print(f"[coordinator] INTERVAL_DONE seq={seq} from {scmc_id}", flush=True)
                    completed = False
                    with self._lock:
                        if seq in self._pending_freq_done:
                            self._pending_freq_done[seq].discard(scmc_id)
                            if not self._pending_freq_done[seq]:
                                del self._pending_freq_done[seq]
                                completed = True
                    if completed:
                        print(
                            f"[coordinator] freq hop seq={seq} applied by all",
                            flush=True,
                        )
        except (ConnectionError, OSError):
            pass
        finally:
            if scmc_id:
                self._unregister(scmc_id, conn)
            conn.close()

    # ── TCP accept loop ──

    def _serve(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.control_port))
        srv.listen(16)
        print(f"[coordinator] control server on :{self.control_port}", flush=True)
        while True:
            conn, addr = srv.accept()
            threading.Thread(
                target=self._handle_client, args=(conn, addr), daemon=True
            ).start()

    # ── hop decision loop (main thread) ──

    def _hop_loop(self) -> None:
        while True:
            time.sleep(self.hop_interval)

            with self._lock:
                if not self._clients:
                    print("[coordinator] no clients — skipping hop", flush=True)
                    continue

                # Never overlap hops: a new SCHEDULE_HOP would reset the
                # executors' countdown and the previous hop would never fire.
                if self._pending_done:
                    pending = sorted(self._pending_done)
                    print(f"[coordinator] hop(s) {pending} still in progress — skipping",
                          flush=True)
                    continue

                self._seq += 1
                seq = self._seq

                ip_idx   = (self.ip_pool.index(self.current_ip)    + 1) % len(self.ip_pool)
                port_idx = (self.port_pool.index(self.current_port) + 1) % len(self.port_pool)
                new_ip   = self.ip_pool[ip_idx]
                new_port = self.port_pool[port_idx]

                ip_changed   = new_ip   != self.current_ip
                port_changed = new_port != self.current_port
                action = ("both"     if ip_changed and port_changed else
                          "ip_hop"   if ip_changed else
                          "port_hop")

                in_messages = random.randint(5, 15)
                self._pending_done[seq] = set(self._clients.keys())
                self._hop_old_port[seq] = self.current_port

                self.current_ip   = new_ip
                self.current_port = new_port

            # Open the new port BEFORE telling executors to migrate, so it is
            # reachable when they reconnect. The old port stays open until all
            # HOP_DONE arrive (see _handle_client).
            self._nat_add(new_port)

            msg = {
                "type":        "SCHEDULE_HOP",
                "seq":         seq,
                "action":      action,
                "new_ip":      new_ip,
                "new_port":    new_port,
                "in_messages": in_messages,
            }
            print(
                f"[coordinator] SCHEDULE_HOP seq={seq}  action={action}"
                f"  → {new_ip}:{new_port}  in {in_messages} msgs",
                flush=True,
            )
            self._broadcast(msg)

    # ── padding decision loop (daemon thread) ──

    def _pad_loop(self) -> None:
        if not self.pad_buckets:
            return    # padding disabled — no master bucket set configured
        while True:
            time.sleep(self.pad_interval)

            with self._lock:
                if not self._clients:
                    print("[coordinator] no clients — skipping padding", flush=True)
                    continue
                if self._pending_pad_done:
                    print("[coordinator] padding change still in progress — skipping",
                          flush=True)
                    continue

                self._seq += 1
                seq = self._seq

                # Announce a random subset of the master buckets as the new
                # active regime, so the size distribution keeps moving.
                k = random.randint(1, len(self.pad_buckets))
                buckets = sorted(random.sample(self.pad_buckets, k))
                in_messages = random.randint(5, 15)
                self._pending_pad_done[seq] = set(self._clients.keys())

            msg = {
                "type":        "SET_PADDING",
                "seq":         seq,
                "buckets":     buckets,
                "in_messages": in_messages,
            }
            print(
                f"[coordinator] SET_PADDING seq={seq}  buckets={buckets}"
                f"  in {in_messages} msgs",
                flush=True,
            )
            self._broadcast(msg)

    # ── source-IP hop decision loop (daemon thread) ──

    def _src_hop_loop(self) -> None:
        """Tell executors to hop their OWN source IP across scmc_ip_pool.

        Independent of the broker hop (own timer/pool) but coordinated here. No
        iptables involved — the SCMC just rebinds its local source address, so
        there is no old port/NAT state to tear down; we only track DONEs for
        logging/metrics.
        """
        if len(self.scmc_ip_pool) < 2:
            return    # source hopping disabled (need at least two addresses)
        while True:
            time.sleep(self.src_hop_interval)

            with self._lock:
                if not self._clients:
                    print("[coordinator] no clients — skipping src hop", flush=True)
                    continue
                if self._pending_src_done:
                    print("[coordinator] src hop still in progress — skipping", flush=True)
                    continue

                self._seq += 1
                seq = self._seq

                idx = (self.scmc_ip_pool.index(self.current_src_ip) + 1) % len(self.scmc_ip_pool)
                new_src_ip = self.scmc_ip_pool[idx]
                self.current_src_ip = new_src_ip

                in_messages = random.randint(5, 15)
                self._pending_src_done[seq] = set(self._clients.keys())

            msg = {
                "type":        "SCHEDULE_SRC_HOP",
                "seq":         seq,
                "new_src_ip":  new_src_ip,
                "in_messages": in_messages,
            }
            print(
                f"[coordinator] SCHEDULE_SRC_HOP seq={seq}  → src {new_src_ip}"
                f"  in {in_messages} msgs",
                flush=True,
            )
            self._broadcast(msg)

    # ── publish-frequency decision loop (daemon thread) ──

    def _freq_loop(self) -> None:
        """Tell executors to change their publish interval (message frequency).

        The fixed inter-arrival time is itself a fingerprint; rotating it across
        freq_pool keeps the timing signal moving. Mirrors _pad_loop: no broker
        state involved, executors just retime their publish loop, we only track
        DONEs for logging/metrics.
        """
        if len(self.freq_pool) < 2:
            return    # frequency hopping disabled (need at least two intervals)
        while True:
            time.sleep(self.freq_interval)

            with self._lock:
                if not self._clients:
                    print("[coordinator] no clients — skipping freq hop", flush=True)
                    continue
                if self._pending_freq_done:
                    print("[coordinator] freq change still in progress — skipping",
                          flush=True)
                    continue

                self._seq += 1
                seq = self._seq

                new_interval = random.choice(self.freq_pool)
                in_messages = random.randint(5, 15)
                self._pending_freq_done[seq] = set(self._clients.keys())

            msg = {
                "type":        "SET_INTERVAL",
                "seq":         seq,
                "interval":    new_interval,
                "in_messages": in_messages,
            }
            print(
                f"[coordinator] SET_INTERVAL seq={seq}  interval={new_interval}s"
                f"  in {in_messages} msgs",
                flush=True,
            )
            self._broadcast(msg)

    def run(self) -> None:
        # Open the initial active port so the first executors can connect.
        self._nat_add(self.current_port)
        threading.Thread(target=self._serve, daemon=True).start()
        threading.Thread(target=self._pad_loop, daemon=True).start()
        threading.Thread(target=self._src_hop_loop, daemon=True).start()
        threading.Thread(target=self._freq_loop, daemon=True).start()
        try:
            self._hop_loop()
        finally:
            for port in list(self._active_nat):
                self._nat_del(port)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MTD coordinator — runs on SEMP")
    parser.add_argument("--control-port", type=int,   default=9998,
                        help="TCP port for the control channel (default: 9998)")
    parser.add_argument("--ip-pool",      default="10.1.0.2",
                        help="Comma-separated broker IPs available for hopping")
    parser.add_argument("--port-pool",    default="8883,8884,8885",
                        help="Comma-separated broker ports available for hopping")
    parser.add_argument("--hop-interval", type=float, default=30.0,
                        help="Seconds between hops (default: 30)")
    parser.add_argument("--real-port",    type=int,   default=18883,
                        help="Fixed internal port mosquitto listens on (default: 18883)")
    parser.add_argument("--no-nat",       action="store_true",
                        help="Skip iptables NAT (host testing / pre-opened pool ports)")
    parser.add_argument("--pad-buckets",  default="256,512,1024",
                        help="Master padding bucket sizes, comma-separated "
                             "(empty disables padding)")
    parser.add_argument("--pad-interval", type=float, default=30.0,
                        help="Seconds between padding-policy changes (default: 30)")
    parser.add_argument("--scmc-ip-pool", default="",
                        help="Comma-separated SCMC source IPs for source-IP hopping "
                             "(empty or single entry disables source hopping)")
    parser.add_argument("--src-hop-interval", type=float, default=30.0,
                        help="Seconds between SCMC source-IP hops (default: 30)")
    parser.add_argument("--freq-pool",    default="1.0",
                        help="Comma-separated publish intervals in seconds for "
                             "message-frequency hopping (single entry disables it)")
    parser.add_argument("--freq-interval", type=float, default=30.0,
                        help="Seconds between publish-frequency changes (default: 30)")
    args = parser.parse_args()

    ip_pool      = [x.strip() for x in args.ip_pool.split(",")]
    port_pool    = [int(x.strip()) for x in args.port_pool.split(",")]
    pad_buckets  = [int(x) for x in args.pad_buckets.split(",") if x.strip()]
    scmc_ip_pool = [x.strip() for x in args.scmc_ip_pool.split(",") if x.strip()]
    freq_pool    = [float(x) for x in args.freq_pool.split(",") if x.strip()]
    SEMPCoordinator(
        args.control_port, ip_pool, port_pool, args.hop_interval,
        real_port=args.real_port, no_nat=args.no_nat,
        pad_buckets=pad_buckets, pad_interval=args.pad_interval,
        scmc_ip_pool=scmc_ip_pool, src_hop_interval=args.src_hop_interval,
        freq_pool=freq_pool, freq_interval=args.freq_interval,
    ).run()


if __name__ == "__main__":
    main()
