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
  SET_PADDING   SEMP → SCMC   {type, seq, buckets, in_messages}
  PAD_ACK       SCMC → SEMP   {type, seq, scmc_id}
  PAD_DONE      SCMC → SEMP   {type, seq, scmc_id}

Deps:   pip install paho-mqtt pymgrid
"""

import argparse
import json
import random
import socket
import struct
import threading
import time
import warnings

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
                 pad_buckets: list = None):
        self.grid_id   = grid_id
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

        self._lock           = threading.Lock()
        self._pub_seq        = 0       # monotonic publish counter (never reset)
        self._pending_hop    = None    # {..hop.., fire_at}, or None
        self._pending_pad    = None    # {buckets, seq, fire_at}, or None
        self._ctrl_sock      = None    # TCP socket to coordinator
        self._mqtt_client    = None
        self._mqtt_connected = False

        print(f"[{grid_id}] Building microgrid simulator...", flush=True)
        self.mg = build_microgrid()

    # ── MQTT ──

    def _on_connect(self, client, userdata, flags, rc, props=None):
        with self._lock:
            self._mqtt_connected = (rc == 0)
        status = "ok" if rc == 0 else f"rc={rc}"
        print(f"[{self.grid_id}] MQTT → {self.broker}:{self.mqtt_port} ({status})", flush=True)

    def _on_disconnect(self, client, userdata, rc, props=None):
        with self._lock:
            self._mqtt_connected = False
        print(f"[{self.grid_id}] MQTT disconnected (rc={rc})", flush=True)

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
                c.connect(self.broker, self.mqtt_port, keepalive=60)
                c.loop_start()
                for _ in range(20):          # wait up to 4 s for CONNACK
                    with self._lock:
                        if self._mqtt_connected:
                            return
                    time.sleep(0.2)
                raise ConnectionError("CONNACK timeout")
            except Exception as e:
                print(f"[{self.grid_id}] MQTT connect failed ({e}), retry in 3s", flush=True)
                time.sleep(3)

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
        print(
            f"[{self.grid_id}] #{seq_num} → {self.broker}:{self.mqtt_port}  "
            f"power={r['power_kw']:6.1f} kW  "
            f"freq={r['frequency']:.4f} Hz  "
            f"volt={r['voltage']:.2f} V  "
            f"pad=[{pad_label}]",
            flush=True,
        )

    # ── hop execution ──

    def _do_hop(self, hop: dict) -> None:
        seq      = hop["seq"]
        new_ip   = hop["new_ip"]
        new_port = hop["new_port"]
        print(
            f"[{self.grid_id}] hop seq={seq}  "
            f"{self.broker}:{self.mqtt_port} → {new_ip}:{new_port}",
            flush=True,
        )
        self.broker    = new_ip
        self.mqtt_port = new_port
        self._mqtt_connect()
        self._send_ctrl({"type": "HOP_DONE", "seq": seq, "scmc_id": self.grid_id})

    # ── control channel ──

    def _send_ctrl(self, msg: dict) -> None:
        try:
            _send_msg(self._ctrl_sock, msg)
        except OSError as e:
            print(f"[{self.grid_id}] ctrl send error: {e}", flush=True)

    def _ctrl_reader(self) -> None:
        """Daemon thread: receives MTD action commands from the coordinator."""
        while True:
            try:
                msg   = _recv_msg(self._ctrl_sock)
                mtype = msg.get("type")
                seq   = msg.get("seq")
                in_m  = msg.get("in_messages", 0)

                if mtype == "SCHEDULE_HOP":
                    print(
                        f"[{self.grid_id}] SCHEDULE_HOP seq={seq}"
                        f"  action={msg['action']}"
                        f"  → {msg['new_ip']}:{msg['new_port']}"
                        f"  in {in_m} msgs",
                        flush=True,
                    )
                    with self._lock:
                        self._pending_hop = {**msg, "fire_at": self._pub_seq + in_m}
                    self._send_ctrl({"type": "HOP_ACK", "seq": seq, "scmc_id": self.grid_id})

                elif mtype == "SET_PADDING":
                    buckets = msg.get("buckets", [])
                    print(
                        f"[{self.grid_id}] SET_PADDING seq={seq}"
                        f"  buckets={buckets}  in {in_m} msgs",
                        flush=True,
                    )
                    with self._lock:
                        self._pending_pad = {
                            "buckets": buckets, "seq": seq,
                            "fire_at": self._pub_seq + in_m,
                        }
                    self._send_ctrl({"type": "PAD_ACK", "seq": seq, "scmc_id": self.grid_id})
            except (ConnectionError, OSError) as e:
                print(f"[{self.grid_id}] ctrl lost ({e}), reconnecting...", flush=True)
                self._ctrl_connect()

    def _ctrl_connect(self) -> None:
        while True:
            try:
                sock = socket.create_connection(
                    (self.semp_ip, self.semp_port), timeout=5
                )
                sock.settimeout(None)
                self._ctrl_sock = sock
                _send_msg(sock, {"type": "HELLO", "scmc_id": self.grid_id})
                print(f"[{self.grid_id}] ctrl → {self.semp_ip}:{self.semp_port}", flush=True)
                return
            except OSError as e:
                print(f"[{self.grid_id}] ctrl connect failed ({e}), retry in 3s", flush=True)
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
                        self._send_ctrl({"type": "PAD_DONE", "seq": pad["seq"],
                                         "scmc_id": self.grid_id})

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
            print(f"\n[{self.grid_id}] stopped", flush=True)
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
    args = parser.parse_args()

    if args.ssl and args.cafile is None:
        parser.error("--cafile is required when --ssl is set")
    if bool(args.certfile) != bool(args.keyfile):
        parser.error("--certfile and --keyfile must be provided together")

    if args.mqtt_port is None:
        args.mqtt_port = 8883 if args.ssl else 1883

    pad_buckets = [int(x) for x in args.pad_buckets.split(",") if x.strip()]

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
    ).run()


if __name__ == "__main__":
    main()
