#!/usr/bin/env python3
"""
client.py — SCMC with pymgrid simulator
Publishes power (kW), frequency (Hz) and voltage (V) to the broker.

Usage:
  python3 client.py [--port PORT] [--scmc-id ID] [--broker HOST]
                    [--ssl] [--cafile PATH] [--certfile PATH] [--keyfile PATH]

Deps:   pip install paho-mqtt pymgrid
"""

import argparse
import json
import sys
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

INTERVAL = 1.0            # seconds between publishes


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


# ── MQTT callbacks ────────────────────────────────────────────────────────────

connected = False

def on_connect(_client, userdata, _flags, rc, _properties=None):
    global connected
    if rc == 0:
        connected = True
        print(f"[{userdata}] Connected to broker")
    else:
        print(f"[{userdata}] Connection failed rc={rc}")

def on_disconnect(_client, userdata, rc, _properties=None):
    global connected
    connected = False
    print(f"[{userdata}] Disconnected (rc={rc})")


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="SCMC MQTT client with optional SSL/TLS")
    parser.add_argument("--broker",   default="10.1.0.2",  help="Broker hostname or IP")
    parser.add_argument("--port",     type=int, default=None,
                        help="Broker port (default: 8883 with --ssl, 1883 otherwise)")
    parser.add_argument("--scmc-id",  default="scmc1",     help="SCMC identifier")
    parser.add_argument("--ssl",      action="store_true",  help="Enable MQTT over TLS")
    parser.add_argument("--cafile",   default=None,
                        help="CA certificate file (required with --ssl)")
    parser.add_argument("--certfile", default=None,
                        help="Client certificate for mutual TLS (optional)")
    parser.add_argument("--keyfile",  default=None,
                        help="Client private key for mutual TLS (optional)")
    args = parser.parse_args()

    if args.ssl and args.cafile is None:
        parser.error("--cafile is required when --ssl is set")
    if bool(args.certfile) != bool(args.keyfile):
        parser.error("--certfile and --keyfile must be provided together")

    if args.port is None:
        args.port = 8883 if args.ssl else 1883

    return args


def main():
    args    = parse_args()
    scmc_id = args.scmc_id

    print(f"[{scmc_id}] Building microgrid simulator...")
    mg = build_microgrid()

    tls_label = f"TLS  cafile={args.cafile}" if args.ssl else "plain"
    print(f"[{scmc_id}] Ready — broker={args.broker}:{args.port}  ({tls_label})")

    client = mqtt.Client(client_id=scmc_id, protocol=mqtt.MQTTv5, userdata=scmc_id)
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect

    if args.ssl:
        client.tls_set(
            ca_certs=args.cafile,
            certfile=args.certfile,
            keyfile=args.keyfile,
        )

    client.connect(args.broker, args.port, keepalive=60)
    client.loop_start()

    for _ in range(10):
        if connected:
            break
        time.sleep(0.5)

    if not connected:
        print(f"[{scmc_id}] Could not connect — exiting")
        sys.exit(1)

    topic_base = f"grid/{scmc_id}"
    print(f"[{scmc_id}] Publishing every {INTERVAL}s  →  {topic_base}/#\n")

    try:
        while True:
            r = step_microgrid(mg, scmc_id)

            for metric in ("power_kw", "frequency", "voltage"):
                client.publish(
                    f"{topic_base}/{metric}",
                    json.dumps({
                        "value":   r[metric],
                        "ts":      r["timestamp"],
                        "scmc_id": scmc_id,
                    }),
                    qos=0,
                )

            client.publish(f"{topic_base}/snapshot", json.dumps(r), qos=0)

            print(
                f"[{scmc_id}] "
                f"power={r['power_kw']:6.1f} kW  "
                f"freq={r['frequency']:.4f} Hz  "
                f"volt={r['voltage']:.2f} V"
            )

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print(f"\n[{scmc_id}] Stopped")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
