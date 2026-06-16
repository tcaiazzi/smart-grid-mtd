#!/usr/bin/env python3
"""
mtd_executor.py — MTD executor, runs on each SCMC

Connects to the SEMP coordinator, publishes MQTT telemetry from a pymgrid
microgrid simulator (same physics as simple_client.py), and applies the MTD
actions it is told to:
  • port/IP hop  (SCHEDULE_HOP): after N publishes, reconnect to the new
    (ip, port) and confirm with HOP_DONE.
  • payload padding (SET_PADDING): after N publishes, switch to a new set of
    size buckets and confirm with PAD_DONE. Each published message is then
    padded to a random bucket via a JSON "_pad" field, masking the packet-size
    fingerprint feature (TLS preserves length, so this is visible on the wire).

Usage:
  python3 mtd_executor.py \\
      --grid-id scmc1 \\
      --broker 10.1.0.2 --mqtt-port 8883 \\
      --semp-control-ip 10.1.0.2 --semp-control-port 9998 \\
      [--ssl --cafile PATH --certfile PATH --keyfile PATH] \\
      [--pad-buckets 256,512,1024]

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

The executor also hops its OWN source IP (SCHEDULE_SRC_HOP): after N publishes it
rebinds both the MQTT and control sockets to the new local source address, so the
SCMC publisher's on-wire identity is a moving target too. The control channel
additionally follows the broker IP on each broker hop, so the SEMP exposes no
fixed control endpoint.

Deps:   pip install paho-mqtt pymgrid
"""

import argparse
import json
import logging
import os
import random
import socket
import struct
import threading
import time
import warnings

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger(__name__)

import numpy as np
import paho.mqtt.client as mqtt

warnings.filterwarnings("ignore")   # suppress gym deprecation noise

from pymgrid import Microgrid
from pymgrid.modules import (
    GensetModule, BatteryModule, LoadModule, RenewableModule,
)

# ── Grid physics constants ────────────────────────────────────────────────────
FREQ_NOMINAL    = 50.0    # Hz  (use 60.0 for North America)
VOLT_NOMINAL    = 230.0   # V   (line-to-neutral, EU standard)
FREQ_DROOP      = 0.01    # Hz per kW of net imbalance  (droop coefficient)
VOLT_DROOP      = 0.5     # V  per kW of load above nominal
LOAD_NOMINAL    = 70.0    # kW  midpoint of our load timeseries

# Bounded window for a hop's NEW broker to answer before we give up and keep
# publishing on the old endpoint (make-before-break, see _do_hop). Short on
# purpose: a blocked target should be abandoned fast so telemetry barely stalls.
# Keep below the coordinator's --hop-timeout so it sees HOP_FAILED first.
HOP_CONNECT_TIMEOUT = 3.0


# ── Microgrid simulator ───────────────────────────────────────────────────────

def build_microgrid(steps: int = 10_000) -> Microgrid:
    """PV + battery + genset + load microgrid with realistic timeseries."""
    rng = np.random.default_rng(seed=42)
    pv_series   = np.clip(rng.normal(50, 15, steps),  0, 100)
    load_series = np.clip(rng.normal(70, 10, steps), 20, 120)

    return Microgrid([
        GensetModule(
            running_min_production=10,
            running_max_production=50,
            genset_cost=0.5,
        ),
        BatteryModule(
            min_capacity=0, max_capacity=100,
            max_charge=50,  max_discharge=50,
            efficiency=0.95, init_soc=0.5,
        ),
        ("pv", RenewableModule(time_series=pv_series)),
        LoadModule(time_series=load_series),
    ])


def derive_frequency(net_balance_kw: float) -> float:
    freq = FREQ_NOMINAL + FREQ_DROOP * net_balance_kw
    freq += np.random.normal(0, 0.005)          # ±5 mHz sensor noise
    return round(float(np.clip(freq, 49.0, 51.0)), 4)


def derive_voltage(load_kw: float) -> float:
    volt = VOLT_NOMINAL - VOLT_DROOP * (load_kw - LOAD_NOMINAL)
    volt += np.random.normal(0, 0.3)            # ±0.3 V sensor noise
    return round(float(np.clip(volt, 200.0, 260.0)), 2)


def step_microgrid(mg: Microgrid, scmc_id: str) -> dict:
    action = {
        "genset":  [np.array([1.0, 0.6])],  # on, 60 % of max (normalised)
        "battery": [np.array([0.0])],         # hold
    }
    _, _, _, info = mg.run(action, normalized=True)

    def _kw(key, kind) -> float:
        return float(dict(info.get(key, [])).get(kind, 0.0))

    load_kw   = _kw("load",    "absorbed_energy")
    pv_kw     = _kw("pv",     "provided_energy")
    genset_kw = _kw("genset", "provided_energy")
    bat_kw    = _kw("battery","absorbed_energy")

    net_kw   = pv_kw + genset_kw - load_kw - bat_kw
    power_kw = round(pv_kw + genset_kw, 2)

    return {
        "scmc_id":   scmc_id,
        "timestamp": round(time.time(), 3),
        "power_kw":  power_kw,
        "frequency": derive_frequency(net_kw),
        "voltage":   derive_voltage(load_kw),
        "load_kw":   round(load_kw,  2),
        "pv_kw":     round(pv_kw,    2),
        "genset_kw": round(genset_kw,2),
        "net_kw":    round(net_kw,   2),
        "bat_soc":   round(float(mg.modules["battery"][0].soc), 3),
    }


# ── Crypto helpers (AES-256-GCM under the QKD shared key) ──────────────────────
# Same construction as the cert-exchange protocol (assets/qkd/cert_client.py),
# so the control channel rides the same QKD-simulated key.

def encrypt_payload(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt_payload(data: bytes, key: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)


# ── Framing helpers ───────────────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf


def _send_msg(sock: socket.socket, obj: dict, key: bytes = None) -> None:
    payload = json.dumps(obj).encode()
    if key is not None:
        payload = encrypt_payload(payload, key)
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_msg(sock: socket.socket, key: bytes = None) -> dict:
    length = struct.unpack(">I", _recv_exact(sock, 4))[0]
    payload = _recv_exact(sock, length)
    if key is not None:
        payload = decrypt_payload(payload, key)
    return json.loads(payload)


# ── Executor ──────────────────────────────────────────────────────────────────

class SCMCExecutor:
    """
    Publishes MQTT telemetry from the pymgrid simulator and executes broker
    hops as directed by the SEMP coordinator.

    Control channel (TCP) and MQTT client run in separate threads; the
    main thread owns the publish loop and hop execution.
    """

    def __init__(self, grid_id: str, broker: str, mqtt_port: int,
                 semp_ip: str, semp_port: int, interval: float = 1.0,
                 ssl: bool = False, cafile: str = None,
                 certfile: str = None, keyfile: str = None,
                 pad_buckets: list = None, src_ip: str = None,
                 shared_key: str = None):
        self.grid_id   = grid_id
        # QKD-simulated shared key for control-channel encryption (None = plaintext).
        self._key      = bytes.fromhex(shared_key) if shared_key else None
        self.broker    = broker
        self.mqtt_port = mqtt_port
        self.semp_ip   = semp_ip
        self.semp_port = semp_port
        self.interval  = interval
        self.ssl       = ssl
        self.cafile    = cafile
        self.certfile  = certfile
        self.keyfile   = keyfile
        self.pad_buckets = list(pad_buckets or [])   # active padding policy
        # Local source IP both connections (MQTT + control) bind to. Hopped on
        # SCHEDULE_SRC_HOP so the SCMC's own on-wire identity is also a moving
        # target. None → let the kernel pick the default source.
        self.src_ip    = src_ip

        self._lock           = threading.Lock()
        self._pub_seq        = 0       # monotonic publish counter (never reset)
        self._pending_hop    = None    # {..hop.., fire_at}, or None
        self._pending_pad    = None    # {buckets, seq, fire_at}, or None
        self._pending_src_hop = None   # {new_src_ip, seq, fire_at}, or None
        self._pending_freq   = None    # {interval, seq, fire_at}, or None
        self._ctrl_sock      = None    # TCP socket to coordinator
        self._mqtt_client    = None
        self._mqtt_connected = False

        log.info("[%s] Building microgrid simulator...", grid_id)
        self.mg = build_microgrid()

    # ── MQTT ──

    def _on_connect(self, client, userdata, flags, rc, props=None):
        with self._lock:
            self._mqtt_connected = (rc == 0)
        status = "ok" if rc == 0 else f"rc={rc}"
        log.info("[%s] MQTT → %s:%s (%s)", self.grid_id, self.broker, self.mqtt_port, status)

    def _on_disconnect(self, client, userdata, rc, props=None):
        with self._lock:
            self._mqtt_connected = False
        log.info("[%s] MQTT disconnected (rc=%s)", self.grid_id, rc)

    def _mqtt_connect(self) -> None:
        if self._mqtt_client:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except Exception:
                pass

        c = mqtt.Client(client_id=self.grid_id, protocol=mqtt.MQTTv5)
        c.on_connect    = self._on_connect
        c.on_disconnect = self._on_disconnect
        if self.ssl:
            c.tls_set(
                ca_certs=self.cafile,
                certfile=self.certfile,
                keyfile=self.keyfile,
            )
        self._mqtt_client = c

        while True:
            try:
                # bind_address pins the local source IP so MQTT rides the
                # current src_ip (hopped on SCHEDULE_SRC_HOP). "" = kernel default.
                c.connect(self.broker, self.mqtt_port, keepalive=60,
                          bind_address=self.src_ip or "")
                c.loop_start()
                for _ in range(20):          # wait up to 4 s for CONNACK
                    with self._lock:
                        if self._mqtt_connected:
                            return
                    time.sleep(0.2)
                raise ConnectionError("CONNACK timeout")
            except Exception as e:
                log.warning("[%s] MQTT connect failed (%s), retry in 3s", self.grid_id, e)
                time.sleep(3)

    def _try_connect(self, broker: str, port: int, deadline_s: float):
        """Make-before-break helper: bring up a FRESH MQTT client to (broker, port)
        without touching self._mqtt_client, so the current connection stays live.

        Uses a LOCAL connect-result flag (not the shared self._mqtt_connected) so the
        trial cannot race the still-connected old client. Retries until deadline_s of
        wall-clock has elapsed. Returns the connected client on success, or None on
        timeout (after stopping the trial client's network loop)."""
        result = {"connected": False}

        def _on_conn(_client, _ud, _flags, rc, _props=None):
            result["connected"] = (rc == 0)

        c = mqtt.Client(client_id=self.grid_id, protocol=mqtt.MQTTv5)
        c.on_connect = _on_conn
        if self.ssl:
            c.tls_set(
                ca_certs=self.cafile,
                certfile=self.certfile,
                keyfile=self.keyfile,
            )

        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline:
            result["connected"] = False
            try:
                c.connect(broker, port, keepalive=60, bind_address=self.src_ip or "")
                c.loop_start()
                while time.monotonic() < deadline:    # await CONNACK within the budget
                    if result["connected"]:
                        return c
                    time.sleep(0.1)
                break                                 # budget spent without CONNACK
            except Exception as e:
                log.warning("[%s] MQTT connect failed (%s)", self.grid_id, e)
                try:
                    c.loop_stop()
                except Exception:
                    pass
                # Brief backoff, but never past the deadline.
                time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))

        try:
            c.loop_stop()
        except Exception:
            pass
        return None

    def _pad_payload(self, obj: dict) -> bytes:
        """
        Serialize `obj` and pad it to a random bucket size via a "_pad" field.
        Returns the (possibly padded) UTF-8 bytes. A fresh bucket is chosen per
        call, so each message gets an independent size. Bucket sizes are
        approximate (off by the length of the integer filler count), which is
        irrelevant for defeating the size fingerprint.
        """
        raw = json.dumps(obj).encode()
        buckets = self.pad_buckets
        if not buckets:
            return raw

        candidates = [b for b in buckets if b >= len(raw)]
        if not candidates:
            return raw                      # already larger than every bucket
        target = random.choice(candidates)

        # Account for the overhead the "_pad" field itself adds to the JSON.
        overhead = len(json.dumps({**obj, "_pad": ""}).encode())
        filler   = max(0, target - overhead)
        return json.dumps({**obj, "_pad": "A" * filler}).encode()

    def _publish(self, seq_num: int) -> None:
        r = step_microgrid(self.mg, self.grid_id)
        topic_base = f"grid/{self.grid_id}"

        for metric in ("power_kw", "frequency", "voltage"):
            self._mqtt_client.publish(
                f"{topic_base}/{metric}",
                self._pad_payload({
                    "value":   r[metric],
                    "ts":      r["timestamp"],
                    "scmc_id": self.grid_id,
                }),
                qos=0,
            )

        self._mqtt_client.publish(f"{topic_base}/snapshot", self._pad_payload(r), qos=0)

        pad_label = ",".join(map(str, self.pad_buckets)) if self.pad_buckets else "off"
        log.info(
            "[%s] #%d → %s:%d  power=%6.1f kW  freq=%.4f Hz  volt=%.2f V  pad=[%s]",
            self.grid_id, seq_num, self.broker, self.mqtt_port,
            r["power_kw"], r["frequency"], r["voltage"], pad_label,
        )

    # ── hop execution ──

    def _do_hop(self, hop: dict) -> None:
        seq      = hop["seq"]
        new_ip   = hop["new_ip"]
        new_port = hop["new_port"]
        log.info("[%s] hop seq=%s  %s:%s → %s:%s",
                 self.grid_id, seq, self.broker, self.mqtt_port, new_ip, new_port)

        # Make-before-break: bring up the NEW broker connection and only swap once
        # it is confirmed live. If it never answers within HOP_CONNECT_TIMEOUT we
        # keep publishing on the current (old) endpoint and report HOP_FAILED, so a
        # blocked/down target can't strand us (cf. break-before-make, which wedged
        # the publish loop forever — see the attack-scenario client.log).
        new_client = self._try_connect(new_ip, new_port, HOP_CONNECT_TIMEOUT)
        if new_client is None:
            log.warning("[%s] hop seq=%s failed — staying on %s:%s",
                        self.grid_id, seq, self.broker, self.mqtt_port)
            self._send_ctrl({"type": "HOP_FAILED", "seq": seq, "scmc_id": self.grid_id})
            return

        # New broker is up. Swap it in, then tear down the old client. Detach the
        # old client's disconnect callback first so its teardown doesn't clobber
        # self._mqtt_connected after we've set it for the new one.
        old_client = self._mqtt_client
        new_client.on_connect    = self._on_connect
        new_client.on_disconnect = self._on_disconnect
        with self._lock:
            self._mqtt_client    = new_client
            self._mqtt_connected = True
            self.broker          = new_ip
            self.mqtt_port       = new_port
        if old_client is not None:
            old_client.on_disconnect = None
            try:
                old_client.loop_stop()
                old_client.disconnect()
            except Exception:
                pass

        self._send_ctrl({"type": "HOP_DONE", "seq": seq, "scmc_id": self.grid_id})

        # MTD on the SEMP itself: the control channel follows the broker IP so the
        # coordinator exposes no fixed endpoint on :9998. The reconnect is
        # make-before-break so the coordinator never sees a gap (see _reconnect_ctrl).
        if new_ip != self.semp_ip:
            log.info("[%s] ctrl follows hop → %s:%s", self.grid_id, new_ip, self.semp_port)
            self.semp_ip = new_ip
            self._reconnect_ctrl()

    def _do_src_hop(self, hop: dict) -> None:
        """Hop the SCMC's own source IP: rebind both MQTT and the control channel
        to the new local address so the publisher is a moving target too."""
        seq        = hop["seq"]
        new_src_ip = hop["new_src_ip"]
        log.info("[%s] src hop seq=%s  %s → %s",
                 self.grid_id, seq, self.src_ip, new_src_ip)
        # DONE goes out on the OLD control socket (old source still valid) before
        # we rebind; then MQTT and the control channel move to the new source.
        self._send_ctrl({"type": "SRC_HOP_DONE", "seq": seq, "scmc_id": self.grid_id})
        self.src_ip = new_src_ip
        self._mqtt_connect()                 # reconnect MQTT bound to the new source
        self._reconnect_ctrl()               # control channel rebinds to the new source

    # ── control channel ──

    def _send_ctrl(self, msg: dict) -> None:
        try:
            _send_msg(self._ctrl_sock, msg, self._key)
        except OSError as e:
            log.warning("[%s] ctrl send error: %s", self.grid_id, e)

    def _reconnect_ctrl(self) -> None:
        """Make-before-break control reconnect.

        Open a fresh control socket bound to the current (src_ip → semp_ip) and
        HELLO it, THEN tear down the old one. Because the new socket registers
        before the old closes, the coordinator sees one continuous client and
        never mistakes the swap for a disconnect — which would otherwise tear
        down an unrelated in-flight hop's NAT port and strand the client.

        _ctrl_reader is blocked in recv() on the old socket. We must wake it so
        it re-reads self._ctrl_sock and resumes on the new socket. close() alone
        does NOT do this: closing a socket from another thread does not interrupt
        a recv() already blocked on it (the fd is dropped but the in-kernel wait
        is not woken), so the reader would hang forever on the dead socket and
        silently stop receiving commands. shutdown(SHUT_RDWR) reliably forces the
        blocked recv() to return EOF; the reader then sees sock is not
        self._ctrl_sock and continues on the new socket instead of reconnecting.
        """
        old = self._ctrl_sock
        self._ctrl_connect()                 # opens new, HELLO, sets self._ctrl_sock
        if old is not None and old is not self._ctrl_sock:
            try:
                old.shutdown(socket.SHUT_RDWR)   # wake reader blocked in recv()
            except OSError:
                pass
            try:
                old.close()
            except OSError:
                pass

    def _ctrl_reader(self) -> None:
        """Daemon thread: receives MTD action commands from the coordinator."""
        while True:
            sock = self._ctrl_sock           # snapshot: may be swapped by _reconnect_ctrl
            try:
                msg   = _recv_msg(sock, self._key)
                mtype = msg.get("type")
                seq   = msg.get("seq")
                in_m  = msg.get("in_messages", 0)

                if mtype == "SCHEDULE_HOP":
                    log.info("[%s] SCHEDULE_HOP seq=%s  action=%s  → %s:%s  in %d msgs",
                             self.grid_id, seq, msg["action"],
                             msg["new_ip"], msg["new_port"], in_m)
                    with self._lock:
                        self._pending_hop = {**msg, "fire_at": self._pub_seq + in_m}
                    self._send_ctrl({"type": "HOP_ACK", "seq": seq, "scmc_id": self.grid_id})

                elif mtype == "SET_PADDING":
                    buckets = msg.get("buckets", [])
                    log.info("[%s] SET_PADDING seq=%s  buckets=%s  in %d msgs",
                             self.grid_id, seq, buckets, in_m)
                    with self._lock:
                        self._pending_pad = {
                            "buckets": buckets, "seq": seq,
                            "fire_at": self._pub_seq + in_m,
                        }
                    self._send_ctrl({"type": "PAD_ACK", "seq": seq, "scmc_id": self.grid_id})

                elif mtype == "SCHEDULE_SRC_HOP":
                    new_src_ip = msg["new_src_ip"]
                    log.info("[%s] SCHEDULE_SRC_HOP seq=%s  → src %s  in %d msgs",
                             self.grid_id, seq, new_src_ip, in_m)
                    with self._lock:
                        self._pending_src_hop = {
                            "new_src_ip": new_src_ip, "seq": seq,
                            "fire_at": self._pub_seq + in_m,
                        }
                    self._send_ctrl({"type": "SRC_HOP_ACK", "seq": seq, "scmc_id": self.grid_id})

                elif mtype == "SET_INTERVAL":
                    new_interval = msg.get("interval")
                    log.info("[%s] SET_INTERVAL seq=%s  interval=%ss  in %d msgs",
                             self.grid_id, seq, new_interval, in_m)
                    with self._lock:
                        self._pending_freq = {
                            "interval": new_interval, "seq": seq,
                            "fire_at": self._pub_seq + in_m,
                        }
                    self._send_ctrl({"type": "INTERVAL_ACK", "seq": seq, "scmc_id": self.grid_id})
            except (ConnectionError, OSError) as e:
                # A make-before-break swap (_reconnect_ctrl) already installed a new
                # socket — just resume reading from it, don't reconnect a second time.
                if sock is not self._ctrl_sock:
                    continue
                log.warning("[%s] ctrl lost (%s), reconnecting...", self.grid_id, e)
                self._ctrl_connect()

    def _ctrl_connect(self) -> None:
        while True:
            try:
                # source_address pins the local source IP so the control channel
                # rides the current src_ip too (hopped on SCHEDULE_SRC_HOP).
                sock = socket.create_connection(
                    (self.semp_ip, self.semp_port), timeout=5,
                    source_address=(self.src_ip, 0) if self.src_ip else None,
                )
                sock.settimeout(None)
                self._ctrl_sock = sock
                _send_msg(sock, {"type": "HELLO", "scmc_id": self.grid_id}, self._key)
                log.info("[%s] ctrl → %s:%s", self.grid_id, self.semp_ip, self.semp_port)
                return
            except OSError as e:
                log.warning("[%s] ctrl connect failed (%s), retry in 3s", self.grid_id, e)
                time.sleep(3)

    # ── main publish loop ──

    def run(self) -> None:
        self._ctrl_connect()
        threading.Thread(target=self._ctrl_reader, daemon=True).start()
        self._mqtt_connect()

        try:
            while True:
                with self._lock:
                    connected = self._mqtt_connected

                if connected:
                    with self._lock:
                        self._pub_seq += 1
                        seq_num = self._pub_seq
                    self._publish(seq_num)

                    # Apply scheduled padding change (independent countdown)
                    with self._lock:
                        pad = self._pending_pad
                        if pad and seq_num >= pad["fire_at"]:
                            self._pending_pad = None
                        else:
                            pad = None
                    if pad:
                        self.pad_buckets = pad["buckets"]
                        print(f"[{self.grid_id}] padding policy → {pad['buckets']}", flush=True)
                        log.info("[%s] padding policy → %s", self.grid_id, pad["buckets"])
                        self._send_ctrl({"type": "PAD_DONE", "seq": pad["seq"],
                                         "scmc_id": self.grid_id})

                    # Apply scheduled publish-frequency change (independent countdown).
                    # New interval takes effect at the time.sleep below.
                    with self._lock:
                        freq = self._pending_freq
                        if freq and seq_num >= freq["fire_at"]:
                            self._pending_freq = None
                        else:
                            freq = None
                    if freq:
                        self.interval = freq["interval"]
                        print(f"[{self.grid_id}] publish interval → {freq['interval']}s", flush=True)
                        log.info("[%s] publish interval → %ss", self.grid_id, freq["interval"])
                        self._send_ctrl({"type": "INTERVAL_DONE", "seq": freq["seq"],
                                         "scmc_id": self.grid_id})

                    # Apply scheduled source-IP hop (independent countdown). Comes
                    # before the broker hop; both reconnect MQTT.
                    with self._lock:
                        src_hop = self._pending_src_hop
                        if src_hop and seq_num >= src_hop["fire_at"]:
                            self._pending_src_hop = None
                        else:
                            src_hop = None
                    if src_hop:
                        self._do_src_hop(src_hop)

                    # Apply scheduled hop (must come last: it reconnects MQTT)
                    with self._lock:
                        hop = self._pending_hop
                        if hop and seq_num >= hop["fire_at"]:
                            self._pending_hop = None
                        else:
                            hop = None
                    if hop:
                        self._do_hop(hop)

                time.sleep(self.interval + np.random.uniform(-0.05, 0.05))
        except KeyboardInterrupt:
            log.info("[%s] stopped", self.grid_id)
        finally:
            if self._mqtt_client:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MTD executor — runs on each SCMC")
    parser.add_argument("--grid-id",           default="scmc1",
                        help="SCMC identifier (default: scmc1)")
    parser.add_argument("--broker",            default="10.1.0.2",
                        help="Initial MQTT broker IP (default: 10.1.0.2)")
    parser.add_argument("--mqtt-port",         type=int,   default=None,
                        help="Initial broker port (default: 8883 with --ssl, 1883 otherwise)")
    parser.add_argument("--semp-control-ip",   default="10.1.0.2",
                        help="SEMP coordinator IP (default: 10.1.0.2)")
    parser.add_argument("--semp-control-port", type=int,   default=9998,
                        help="SEMP coordinator control port (default: 9998)")
    parser.add_argument("--interval",          type=float, default=1.0,
                        help="Seconds between publish cycles (default: 1.0)")
    parser.add_argument("--ssl",      action="store_true",  help="Enable MQTT over TLS")
    parser.add_argument("--cafile",   default=None,
                        help="CA certificate file (required with --ssl)")
    parser.add_argument("--certfile", default=None,
                        help="Client certificate for mutual TLS (optional)")
    parser.add_argument("--keyfile",  default=None,
                        help="Client private key for mutual TLS (optional)")
    parser.add_argument("--pad-buckets", default="",
                        help="Initial padding bucket sizes, comma-separated "
                             "(default: empty = no padding until coordinator sets it)")
    parser.add_argument("--scmc-ip-pool", default="",
                        help="Comma-separated local source IP pool for source-IP "
                             "hopping. The first entry is the initial source bound by "
                             "MQTT and the control channel; the coordinator announces "
                             "the rest via SCHEDULE_SRC_HOP (default: empty = no "
                             "source hop, kernel-chosen source).")
    parser.add_argument("--log-file", default="mtd_executor.log",
                        help="File to write the message-exchange log "
                             "(default: mtd_executor.log in the working directory)")
    parser.add_argument("--shared-key", default=None,
                        help="64-char hex QKD shared key for control-channel "
                             "AES-256-GCM encryption (omit = plaintext)")
    args = parser.parse_args()

    if args.shared_key is not None and len(args.shared_key) != 64:
        parser.error("--shared-key must be exactly 64 hex chars (32 bytes)")

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
    )

    if args.ssl and args.cafile is None:
        parser.error("--cafile is required when --ssl is set")
    if bool(args.certfile) != bool(args.keyfile):
        parser.error("--certfile and --keyfile must be provided together")

    if args.mqtt_port is None:
        args.mqtt_port = 8883 if args.ssl else 1883

    pad_buckets = [int(x) for x in args.pad_buckets.split(",") if x.strip()]
    scmc_ip_pool = [x.strip() for x in args.scmc_ip_pool.split(",") if x.strip()]
    src_ip = scmc_ip_pool[0] if scmc_ip_pool else None

    SCMCExecutor(
        grid_id     = args.grid_id,
        broker      = args.broker,
        mqtt_port   = args.mqtt_port,
        semp_ip     = args.semp_control_ip,
        semp_port   = args.semp_control_port,
        interval    = args.interval,
        ssl         = args.ssl,
        cafile      = args.cafile,
        certfile    = args.certfile,
        keyfile     = args.keyfile,
        pad_buckets = pad_buckets,
        src_ip      = src_ip,
        shared_key  = args.shared_key,
    ).run()


if __name__ == "__main__":
    main()
