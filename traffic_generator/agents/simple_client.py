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
import logging
import sys
import time
import warnings

log = logging.getLogger(__name__)
import paho.mqtt.client as mqtt

warnings.filterwarnings("ignore")   # suppress gym deprecation noise

# Same pymgrid physics as mtd_executor.py (MTD publisher) — see
# microgrid_sim.py, copied alongside this file on every scmc machine.
from microgrid_sim import build_microgrid, step_microgrid

INTERVAL = 1.0            # seconds between publishes


# ── MQTT callbacks ────────────────────────────────────────────────────────────

connected = False

def on_connect(_client, userdata, _flags, rc, _properties=None):
    global connected
    if rc == 0:
        connected = True
        log.info("[%s] Connected to broker", userdata)
    else:
        log.warning("[%s] Connection failed rc=%s", userdata, rc)

def on_disconnect(_client, userdata, rc, _properties=None):
    global connected
    connected = False
    log.info("[%s] Disconnected (rc=%s)", userdata, rc)


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
    parser.add_argument("--log-file", default="simple_client.log",
                        help="File to write the message-exchange log "
                             "(default: simple_client.log in the working directory)")
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

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
    )

    log.info("[%s] Building microgrid simulator...", scmc_id)
    mg = build_microgrid()

    tls_label = f"TLS  cafile={args.cafile}" if args.ssl else "plain"
    log.info("[%s] Ready — broker=%s:%s  (%s)", scmc_id, args.broker, args.port, tls_label)

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
        log.warning("[%s] Could not connect — exiting", scmc_id)
        sys.exit(1)

    topic_base = f"grid/{scmc_id}"
    log.info("[%s] Publishing every %ss  →  %s/#", scmc_id, INTERVAL, topic_base)

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

            log.info("[%s] power=%6.1f kW  freq=%.4f Hz  volt=%.2f V",
                     scmc_id, r["power_kw"], r["frequency"], r["voltage"])

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        log.info("[%s] Stopped", scmc_id)
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
