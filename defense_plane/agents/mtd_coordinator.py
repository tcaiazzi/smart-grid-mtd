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
  HOP_FAILED    SCMC → SEMP   {type, seq, scmc_id}   (new broker unreachable; stayed put)
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

Every action, reply and outcome is also recorded by mtd_telemetry.Telemetry
(--telemetry-path) and, with --dashboard-port, served live by mtd_dashboard.py.
"""

import argparse
import random
import socket
import subprocess
import threading
import time

# Crypto (AES-256-GCM under the QKD shared key) and wire framing are shared
# with mtd_executor.py, cert_authority.py and cert_client.py — see
# mtd_crypto.py / mtd_wire.py, copied alongside this file on every machine.
from mtd_wire import send_msg as _send_msg, recv_msg as _recv_msg
from delivery_detector import LiveDetector
from mtd_dashboard import DashboardServer
from mtd_telemetry import DataPlaneObserver, Telemetry
from rl_policy import KNOB_COST, KNOBS

# Executor reply type → the phase Telemetry records it as.
_REPLY_PHASE = {
    "HOP_ACK": "ACK", "HOP_DONE": "DONE", "HOP_FAILED": "FAILED",
    "PAD_ACK": "ACK", "PAD_DONE": "DONE",
    "SRC_HOP_ACK": "ACK", "SRC_HOP_DONE": "DONE",
    "INTERVAL_ACK": "ACK", "INTERVAL_DONE": "DONE",
}


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

    KIND = "fixed"    # coordinator type reported to the dashboard
    RECONNECT_GRACE_S = 2.0   # a closed executor may come back this fast (see _unregister)

    def __init__(self, control_port: int, ip_pool: list, port_pool: list,
                 hop_interval: float, real_port: int = 18883, no_nat: bool = False,
                 pad_buckets: list = None, pad_interval: float = 30.0,
                 scmc_ip_pool: list = None, src_hop_interval: float = 30.0,
                 freq_pool: list = None, freq_interval: float = 30.0,
                 hop_timeout: float = 10.0, shared_key: str = None,
                 seed: int = None, telemetry_path: str = None,
                 dashboard_port: int = None, detector_model: str = None):
        self.control_port = control_port
        self.seed = seed
        # In-memory unless a path is given; the dashboard needs a port.
        self.telemetry = Telemetry(telemetry_path, dict(zip(KNOBS, KNOB_COST)))
        self.dashboard_port = dashboard_port
        self.detector_model = detector_model
        # One RNG per knob, so a seeded run draws the same per-knob sequence no
        # matter how the knob threads interleave (seed=None → OS entropy).
        self._rng = {knob: random.Random(None if seed is None else f"{seed}:{knob}")
                     for knob in ("hop", "pad", "src", "freq")}
        # QKD-simulated shared key for control-channel encryption (None = plaintext).
        self._key = bytes.fromhex(shared_key) if shared_key else None
        self.ip_pool      = ip_pool
        self.port_pool    = port_pool
        self.hop_interval = hop_interval
        self.hop_timeout  = hop_timeout
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
        self._departing: dict = {}        # scmc_id → closed socket, within the grace
        self._pending_done: dict = {}     # hop seq → set of scmc_ids awaited
        self._hop_old_port: dict = {}     # hop seq → port to vacate on completion
        self._hop_new_port: dict = {}     # hop seq → new port (vacated on rollback)
        self._hop_deadline: dict = {}     # hop seq → time.monotonic() expiry
        self._hop_succeeded: dict = {}    # hop seq → set of scmc_ids that sent HOP_DONE
        self._hop_endpoints: dict = {}    # hop seq → (old_ip, old_port, new_ip, new_port)
        self._pending_pad_done: dict = {} # padding seq → set of scmc_ids awaited
        self._pending_src_done: dict = {} # src-hop seq → set of scmc_ids awaited
        self._pending_freq_done: dict = {} # freq-hop seq → set of scmc_ids awaited
        self._soft_deadline: dict = {}    # pad/src/freq seq → (its pending dict, expiry)
        self._active_nat: set    = set()  # pool ports with a live REDIRECT rule
        # Last broker endpoint an executor confirmed with HOP_DONE (and the hop's
        # seq). A rollback returns here, not to the hop's own starting point: a
        # DONE can arrive after its hop was rolled back (stuck behind a
        # blackhole), and the executor is then on that hop's endpoint.
        self._confirmed = (self.current_ip, self.current_port)
        self._confirmed_seq = 0
        self._rolled_back_to: dict = {}   # rolled-back hop seq → (new_ip, new_port)

    # ── telemetry / dashboard ──

    def _track_hop(self, seq: int, ip_changed: bool, port_changed: bool,
                   in_messages: int, new_ip: str, new_port: int) -> None:
        """Record a scheduled broker hop (call under self._lock, after the
        _pending_done/_hop_* entries are set, before current_* move)."""
        knobs = [k for k, changed in (("port", port_changed), ("ip", ip_changed)) if changed]
        self.telemetry.scheduled(seq, "hop", knobs, in_messages, self._clients,
                                 old_ip=self.current_ip, old_port=self.current_port,
                                 new_ip=new_ip, new_port=new_port)

    def _start_telemetry(self) -> None:
        """Record the run configuration; with a dashboard port, also start the
        HTTP dashboard and the data-plane observer."""
        self.telemetry.emit(
            "run_info", coordinator=self.KIND, seed=self.seed,
            knob_cost=dict(zip(KNOBS, KNOB_COST)),
            ip_pool=self.ip_pool, port_pool=self.port_pool,
            scmc_ip_pool=self.scmc_ip_pool, pad_buckets=self.pad_buckets,
            freq_pool=self.freq_pool, hop_timeout=self.hop_timeout,
            intervals={"hop": self.hop_interval, "pad": self.pad_interval,
                       "src": self.src_hop_interval, "freq": self.freq_interval},
            initial={"ip": self.current_ip, "port": self.current_port,
                     "src": self.current_src_ip,
                     "interval": self.telemetry.publish_interval},
        )
        if self.dashboard_port:
            DashboardServer(self.telemetry, self.dashboard_port).start()
            DataPlaneObserver(self.telemetry).start()
            # The detector scores the data-plane observer's events, so it needs it.
            if self.detector_model:
                LiveDetector(self.telemetry, self.detector_model).start()

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
            self.telemetry.emit("nat", port=port, op="add")
            print(f"[coordinator] NAT  {port} → {self.real_port}", flush=True)
        except (OSError, subprocess.CalledProcessError) as e:
            self.telemetry.emit("nat", port=port, op="add_failed", error=str(e))
            print(f"[coordinator] NAT add {port} failed: {e}", flush=True)

    def _nat_del(self, port: int) -> None:
        if self.no_nat or port == self.real_port or port not in self._active_nat:
            return
        self._nat_rule("-D", port)          # check=False: ignore if already gone
        self._active_nat.discard(port)
        self.telemetry.emit("nat", port=port, op="del")
        print(f"[coordinator] NAT  {port} closed", flush=True)

    def _apply_nat(self, vacated: list) -> None:
        """After a hop is finalized or reconciled (outside the lock): close the
        vacated pool ports, but never the active one, and make sure the active
        port is open — a rollback onto a late-confirmed endpoint may need it back."""
        for port in vacated:
            if port != self.current_port:
                self._nat_del(port)
        self._nat_add(self.current_port)

    # ── client management ──

    def _register(self, scmc_id: str, sock: socket.socket) -> None:
        with self._lock:
            # Already registered, or closed less than RECONNECT_GRACE_S ago, = a
            # control reconnect (see _unregister), not a new executor.
            returning = self._departing.pop(scmc_id, None) is not None
            event = "handover" if scmc_id in self._clients or returning else "connected"
            self._clients[scmc_id] = sock
        self.telemetry.emit("client", scmc_id=scmc_id, event=event)
        print(f"[coordinator] {scmc_id} connected  (total={len(self._clients)})", flush=True)

    def _release_client(self, scmc_id: str) -> list:
        """Stop waiting on a dead executor (call under self._lock): an action left
        pending would make its loop skip every future tick. Returns the pool ports
        to vacate."""
        vacated = []
        for seq in list(self._pending_done):
            self._pending_done[seq].discard(scmc_id)
            if not self._pending_done[seq]:
                vacated.extend(self._finalize_hop(seq))
        for pending in (self._pending_pad_done, self._pending_src_done,
                        self._pending_freq_done):
            for seq in list(pending):
                pending[seq].discard(scmc_id)
                if not pending[seq]:
                    del pending[seq]
                    self.telemetry.finished(seq)
        return vacated

    def _drop_client(self, scmc_id: str, conn: socket.socket) -> bool:
        """Forget an executor whose socket failed a send, right away (the message
        never reached it). Returns False, doing nothing, if `conn` is no longer its
        registered socket."""
        with self._lock:
            if self._clients.get(scmc_id) is not conn:
                return False
            self._clients.pop(scmc_id, None)
            vacated = self._release_client(scmc_id)
        self._apply_nat(vacated)              # NAT shell-out outside the lock
        return True

    def _unregister(self, scmc_id: str, conn: socket.socket) -> None:
        """An executor's control socket closed.

        A make-before-break control reconnect (control-follows-hop or source-IP
        hop) registers a fresh socket under the same scmc_id BEFORE closing the
        old one; if the registered socket is no longer this one, its close is a
        handover and every pending action and NAT port stays untouched — clearing
        them would vacate the port the client is about to use and strand it with
        "connection refused".

        The executor does send the new HELLO first, but the network may deliver the
        old socket's FIN first (reordering under delay/jitter). So a close of the
        registered socket is not final either: the executor gets RECONNECT_GRACE_S
        to come back under its scmc_id before its pending actions are released.
        """
        with self._lock:
            if self._clients.get(scmc_id) is not conn:
                return
            self._clients.pop(scmc_id, None)
            self._departing[scmc_id] = conn
        timer = threading.Timer(self.RECONNECT_GRACE_S, self._depart, args=(scmc_id, conn))
        timer.daemon = True
        timer.start()

    def _depart(self, scmc_id: str, conn: socket.socket) -> None:
        """RECONNECT_GRACE_S after a close: if the executor did not come back, it is gone."""
        with self._lock:
            if self._departing.get(scmc_id) is not conn:
                return                         # it reconnected in time
            del self._departing[scmc_id]
            vacated = self._release_client(scmc_id)
        self.telemetry.emit("client", scmc_id=scmc_id, event="disconnected")
        print(f"[coordinator] {scmc_id} disconnected", flush=True)
        self._apply_nat(vacated)

    def _finalize_hop(self, seq: int, timed_out=()) -> list:
        """Reconcile NAT state for a hop whose awaited set has just emptied.

        Called (under self._lock) from the HOP_DONE / HOP_FAILED handlers, the
        watchdog, and _unregister — every path that can empty _pending_done[seq].
        Centralizing it keeps the three outcomes consistent and stops the per-seq
        dicts from leaking. Returns the list of pool ports to NAT-delete; the
        caller must do so AFTER releasing the lock (iptables shell-out is slow).
        `timed_out` lists the executors the watchdog gave up on (telemetry only).
        """
        if seq in self._pending_done and self._pending_done[seq]:
            return []                      # still awaiting clients — nothing to do

        self._pending_done.pop(seq, None)
        old_port    = self._hop_old_port.pop(seq, None)
        new_port    = self._hop_new_port.pop(seq, None)
        succeeded   = self._hop_succeeded.pop(seq, set())
        endpoints   = self._hop_endpoints.pop(seq, None)
        self._hop_deadline.pop(seq, None)
        self.telemetry.finished(seq, timed_out=timed_out, rolled_back=not succeeded)

        if succeeded:
            # At least one executor migrated → the hop stands. Vacate the old port.
            print(f"[coordinator] hop seq={seq} complete — migrated: {sorted(succeeded)}",
                  flush=True)
            return [old_port] if old_port is not None else []

        # Nobody confirmed (all failed/timed-out): roll back to the last endpoint an
        # executor confirmed, so the coordinator's notion of "current" matches the
        # clients, and vacate the new port unless it is that endpoint. Remember the
        # hop's target in case its DONE still turns up (_late_hop_done).
        self.current_ip, self.current_port = self._confirmed
        if endpoints is not None:
            self._rolled_back_to[seq] = (endpoints[2], endpoints[3])
            for old in sorted(self._rolled_back_to)[:-32]:
                del self._rolled_back_to[old]
        print(f"[coordinator] hop seq={seq} rolled back — broker stays on "
              f"{self.current_ip}:{self.current_port}", flush=True)
        return [new_port] if new_port is not None else []

    def _reprice_hop(self, seq: int) -> None:
        """An executor answered broker hop `seq` (call under self._lock): price it by
        what it changes from the last CONFIRMED endpoint — where the executor really
        started from, which the coordinator's notion at send time may not be (an
        earlier hop rolled back but confirmed late). Matches what client.log, and so
        the post-hoc cost, records. Out-of-order (stale) answers keep their price."""
        if seq in self._hop_endpoints:
            target = self._hop_endpoints[seq][2:]
        elif seq in self._rolled_back_to:
            target = self._rolled_back_to[seq]
        else:
            return
        if seq < self._confirmed_seq:
            return
        (old_ip, old_port), (new_ip, new_port) = self._confirmed, target
        self.telemetry.reprice(seq, [k for k, a, b in (("port", old_port, new_port),
                                                      ("ip", old_ip, new_ip)) if a != b])

    def _late_hop_done(self, seq: int, scmc_id: str) -> list:
        """A HOP_DONE for a hop already rolled back (call under self._lock): the
        executor did migrate. Record its endpoint as confirmed and, unless another
        hop is in flight (its own rollback will now return there), move "current"
        there. Returns the pool ports to vacate. A DONE older than the last
        confirmed hop is stale and ignored."""
        target = self._rolled_back_to.pop(seq, None)
        if target is None or seq < self._confirmed_seq:
            return []
        self._confirmed, self._confirmed_seq = target, seq
        print(f"[coordinator] late HOP_DONE seq={seq} from {scmc_id} — "
              f"executor is on {target[0]}:{target[1]}", flush=True)
        if self._pending_done or (self.current_ip, self.current_port) == target:
            return []
        vacated = [self.current_port]
        self.current_ip, self.current_port = target
        return vacated

    def _broadcast(self, msg: dict) -> None:
        with self._lock:
            snapshot = list(self._clients.items())
        dead = []
        for scmc_id, sock in snapshot:
            try:
                _send_msg(sock, msg, self._key)
            except OSError:
                # Same cleanup as a disconnect (its reader thread will then see
                # the socket unregistered and stay quiet).
                if self._drop_client(scmc_id, sock):
                    dead.append(scmc_id)
                    self.telemetry.emit("client", scmc_id=scmc_id, event="broadcast_failed",
                                        msg_type=msg.get("type"), seq=msg.get("seq"))
        if dead:
            print(f"[coordinator] dropped dead clients: {dead}", flush=True)

    # ── per-client reader thread ──

    def _handle_client(self, conn: socket.socket, addr) -> None:
        scmc_id = None
        try:
            hello = _recv_msg(conn, self._key)
            if hello.get("type") != "HELLO":
                return
            scmc_id = hello["scmc_id"]
            self._register(scmc_id, conn)
            while True:
                msg   = _recv_msg(conn, self._key)
                mtype = msg.get("type")
                seq   = msg.get("seq")
                if mtype in ("HOP_DONE", "HOP_FAILED"):
                    with self._lock:
                        self._reprice_hop(seq)       # before reply() charges it
                if mtype in _REPLY_PHASE:
                    self.telemetry.reply(seq, scmc_id, _REPLY_PHASE[mtype])
                if mtype == "HOP_ACK":
                    print(f"[coordinator] HOP_ACK  seq={seq} from {scmc_id}", flush=True)
                elif mtype == "HOP_DONE":
                    print(f"[coordinator] HOP_DONE seq={seq} from {scmc_id}", flush=True)
                    vacated = []
                    with self._lock:
                        if seq in self._pending_done:
                            self._pending_done[seq].discard(scmc_id)
                            self._hop_succeeded.setdefault(seq, set()).add(scmc_id)
                            if seq > self._confirmed_seq:
                                endpoints = self._hop_endpoints[seq]
                                self._confirmed = (endpoints[2], endpoints[3])
                                self._confirmed_seq = seq
                            if not self._pending_done[seq]:
                                vacated = self._finalize_hop(seq)
                        else:
                            vacated = self._late_hop_done(seq, scmc_id)
                    self._apply_nat(vacated)      # NAT shell-out outside the lock
                elif mtype == "HOP_FAILED":
                    print(f"[coordinator] HOP_FAILED seq={seq} from {scmc_id}", flush=True)
                    vacated = []
                    with self._lock:
                        if seq in self._pending_done:
                            self._pending_done[seq].discard(scmc_id)
                            if not self._pending_done[seq]:
                                vacated = self._finalize_hop(seq)
                    self._apply_nat(vacated)
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
                        self.telemetry.finished(seq)
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
                        self.telemetry.finished(seq)
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
                        self.telemetry.finished(seq)
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
                    self.telemetry.skipped("hop", "no_clients")
                    print("[coordinator] no clients — skipping hop", flush=True)
                    continue

                # Never overlap hops: a new SCHEDULE_HOP would reset the
                # executors' countdown and the previous hop would never fire.
                if self._pending_done:
                    pending = sorted(self._pending_done)
                    self.telemetry.skipped("hop", "in_progress")
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

                in_messages = self._rng["hop"].randint(5, 15)
                self._pending_done[seq]  = set(self._clients.keys())
                self._hop_old_port[seq]  = self.current_port
                self._hop_new_port[seq]  = new_port
                self._hop_succeeded[seq] = set()
                self._hop_endpoints[seq] = (self.current_ip, self.current_port, new_ip, new_port)
                # Deadline must allow the executor's HOP_CONNECT_TIMEOUT + a margin
                # for the worst-case "in N messages" countdown before it even starts.
                self._hop_deadline[seq]  = time.monotonic() + self.hop_timeout + in_messages
                self._track_hop(seq, ip_changed, port_changed, in_messages, new_ip, new_port)

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

    # ── action watchdog (daemon thread) ──

    def _await(self, pending: dict, seq: int, in_messages: int) -> None:
        """Start awaiting a padding / source-hop / interval action's DONEs (call
        under self._lock), with a deadline for _action_watchdog_loop. The executor
        applies it after `in_messages` publishes, each at most max(freq_pool) apart."""
        pending[seq] = set(self._clients.keys())
        interval = max(self.freq_pool) if self.freq_pool else 1.0
        self._soft_deadline[seq] = (pending,
                                    time.monotonic() + self.hop_timeout + in_messages * interval)

    def _action_watchdog_loop(self) -> None:
        """Fail-safe for actions that never complete.

        Without this, a single executor that can't reach the new broker (down or
        attacker-blocked) leaves its seq in _pending_done forever, which both pins
        the old NAT port open and makes _hop_loop skip every future hop. We give
        each hop a deadline; once it passes, the still-awaited clients are treated
        as failed and the hop is finalized (rolled back if nobody migrated).

        Padding, source-hop and interval actions get the same deadline: a DONE lost
        to a blackhole would otherwise leave the action pending, and its loop
        skipping, for the rest of the run.
        """
        while True:
            time.sleep(1.0)
            self._expire_actions(time.monotonic())

    def _expire_actions(self, now: float) -> None:
        """One watchdog pass: close every action whose deadline is before `now`."""
        vacated = []
        with self._lock:
            for seq in list(self._pending_done):
                if now < self._hop_deadline.get(seq, float("inf")):
                    continue
                waiting = sorted(self._pending_done[seq])
                print(f"[coordinator] hop seq={seq} timed out — "
                      f"no response from {waiting}", flush=True)
                self._pending_done[seq].clear()
                vacated.extend(self._finalize_hop(seq, timed_out=waiting))
            for seq, (pending, deadline) in list(self._soft_deadline.items()):
                if seq not in pending:     # completed (or its client dropped)
                    del self._soft_deadline[seq]
                elif now >= deadline:
                    waiting = sorted(pending.pop(seq))
                    del self._soft_deadline[seq]
                    print(f"[coordinator] action seq={seq} timed out — "
                          f"no response from {waiting}", flush=True)
                    self.telemetry.finished(seq, timed_out=waiting)
        self._apply_nat(vacated)           # NAT shell-out outside the lock

    # ── padding decision loop (daemon thread) ──

    def _pad_loop(self) -> None:
        if not self.pad_buckets:
            return    # padding disabled — no master bucket set configured
        while True:
            time.sleep(self.pad_interval)

            with self._lock:
                if not self._clients:
                    self.telemetry.skipped("pad", "no_clients")
                    print("[coordinator] no clients — skipping padding", flush=True)
                    continue
                if self._pending_pad_done:
                    self.telemetry.skipped("pad", "in_progress")
                    print("[coordinator] padding change still in progress — skipping",
                          flush=True)
                    continue

                self._seq += 1
                seq = self._seq

                # Announce a random subset of the master buckets as the new
                # active regime, so the size distribution keeps moving.
                k = self._rng["pad"].randint(1, len(self.pad_buckets))
                buckets = sorted(self._rng["pad"].sample(self.pad_buckets, k))
                in_messages = self._rng["pad"].randint(5, 15)
                self._await(self._pending_pad_done, seq, in_messages)
                self.telemetry.scheduled(seq, "pad", ["pad"], in_messages,
                                         self._clients, buckets=buckets)

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
                    self.telemetry.skipped("src", "no_clients")
                    print("[coordinator] no clients — skipping src hop", flush=True)
                    continue
                if self._pending_src_done:
                    self.telemetry.skipped("src", "in_progress")
                    print("[coordinator] src hop still in progress — skipping", flush=True)
                    continue

                self._seq += 1
                seq = self._seq

                idx = (self.scmc_ip_pool.index(self.current_src_ip) + 1) % len(self.scmc_ip_pool)
                new_src_ip = self.scmc_ip_pool[idx]
                self.current_src_ip = new_src_ip

                in_messages = self._rng["src"].randint(5, 15)
                self._await(self._pending_src_done, seq, in_messages)
                self.telemetry.scheduled(seq, "src", ["src"], in_messages,
                                         self._clients, new_src_ip=new_src_ip)

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
                    self.telemetry.skipped("freq", "no_clients")
                    print("[coordinator] no clients — skipping freq hop", flush=True)
                    continue
                if self._pending_freq_done:
                    self.telemetry.skipped("freq", "in_progress")
                    print("[coordinator] freq change still in progress — skipping",
                          flush=True)
                    continue

                self._seq += 1
                seq = self._seq

                new_interval = self._rng["freq"].choice(self.freq_pool)
                in_messages = self._rng["freq"].randint(5, 15)
                self._await(self._pending_freq_done, seq, in_messages)
                self.telemetry.scheduled(seq, "freq", ["freq"], in_messages,
                                         self._clients, interval=new_interval)

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
        self._start_telemetry()
        # Open the initial active port so the first executors can connect.
        self._nat_add(self.current_port)
        threading.Thread(target=self._serve, daemon=True).start()
        threading.Thread(target=self._action_watchdog_loop, daemon=True).start()
        threading.Thread(target=self._pad_loop, daemon=True).start()
        threading.Thread(target=self._src_hop_loop, daemon=True).start()
        threading.Thread(target=self._freq_loop, daemon=True).start()
        try:
            self._hop_loop()
        finally:
            for port in list(self._active_nat):
                self._nat_del(port)


# ── Entry point ───────────────────────────────────────────────────────────────

def add_telemetry_args(parser: argparse.ArgumentParser) -> None:
    """CLI flags shared with mtd_rl_coordinator.py."""
    parser.add_argument("--telemetry-path", default="telemetry.jsonl",
                        help="File the MTD telemetry events are appended to "
                             "(default: telemetry.jsonl; empty = memory only)")
    parser.add_argument("--dashboard-port", type=int, default=None,
                        help="Serve the live MTD dashboard on this port and observe "
                             "the data plane over the broker's loopback listener "
                             "(omit = no dashboard)")
    parser.add_argument("--detector-model", default=None,
                        help="Delivery attack detector (.npz from "
                             "train_delivery_detector.py) to run live; needs "
                             "--dashboard-port (omit = no detector)")


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
    parser.add_argument("--hop-timeout", type=float, default=10.0,
                        help="Seconds to await HOP_DONE before declaring a hop failed "
                             "and rolling back (keep > executor HOP_CONNECT_TIMEOUT; "
                             "default: 10)")
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
    parser.add_argument("--shared-key", default=None,
                        help="64-char hex QKD shared key for control-channel "
                             "AES-256-GCM encryption (omit = plaintext)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Seed for the per-knob random draws (omit = unseeded)")
    add_telemetry_args(parser)
    args = parser.parse_args()

    if args.shared_key is not None and len(args.shared_key) != 64:
        parser.error("--shared-key must be exactly 64 hex chars (32 bytes)")

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
        hop_timeout=args.hop_timeout, shared_key=args.shared_key,
        seed=args.seed, telemetry_path=args.telemetry_path,
        dashboard_port=args.dashboard_port, detector_model=args.detector_model,
    ).run()


if __name__ == "__main__":
    main()
