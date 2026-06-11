"""
Runs inside each scmc container.
Publishes MQTT telemetry and writes per-publish stats to /shared/metrics/.
Reads MTD state from /shared/control/state_<grid_id>.json and applies:
  padding_bytes  – pad payload to this block size
  publish_interval – override send interval
  add_dummy       – inject extra dummy publishes per real one
  topic_prefix    – prepend to all topic names (topic rotation)
"""
import argparse
import json
import os
import time

import numpy as np
import paho.mqtt.client as mqtt

METRICS_DIR = "/shared/metrics"
CONTROL_DIR = "/shared/control"


class MicrogridSimulator:
    def __init__(self, grid_id: str, broker_host: str, broker_port: int = 1883,
                 interval: float = 1.0):
        self.grid_id      = grid_id
        self.broker_host  = broker_host
        self.broker_port  = broker_port
        self.interval     = interval

        self.power_base = 100.0
        self.freq_base  = 50.0
        self.volt_base  = 230.0

        self.client = mqtt.Client(client_id=f"scmc-{grid_id}")
        self.client.on_connect    = lambda *_: print(f"[{grid_id}] connected", flush=True)
        self.client.on_disconnect = lambda *_: print(f"[{grid_id}] disconnected", flush=True)

        self._metrics_file = os.path.join(METRICS_DIR, f"traffic_{grid_id}.jsonl")
        self._state_file   = os.path.join(CONTROL_DIR,  f"state_{grid_id}.json")
        os.makedirs(METRICS_DIR, exist_ok=True)
        os.makedirs(CONTROL_DIR, exist_ok=True)

    # ------------------------------------------------------------------

    def _load_state(self) -> dict:
        try:
            with open(self._state_file) as f:
                return json.load(f)
        except Exception:
            return {}

    def _load_traffic_config(self) -> dict:
        try:
            with open(os.path.join(CONTROL_DIR, "traffic_config.json")) as f:
                return json.load(f)
        except Exception:
            return {}

    def _connect(self):
        while True:
            try:
                self.client.connect(self.broker_host, self.broker_port, keepalive=60)
                return
            except Exception as e:
                print(f"[{self.grid_id}] connect failed: {e}, retry in 5s", flush=True)
                time.sleep(5)

    def _build_payload(self, reading: dict, state: dict) -> bytes:
        raw = json.dumps(reading).encode()
        pad = state.get("padding_bytes", 0)
        if pad > 0:
            remainder = len(raw) % pad
            if remainder:
                raw += b"\x00" * (pad - remainder)
        return raw

    def _topic(self, base: str, state: dict) -> str:
        prefix = state.get("topic_prefix", "")
        return f"{prefix}/{base}" if prefix else base

    def _write_stats(self, payload_size: int, interval: float, state: dict):
        record = {
            "ts":           time.time(),
            "grid_id":      self.grid_id,
            "payload_size": payload_size,
            "interval":     interval,
            "padding":      state.get("padding_bytes", 0),
            "dummy":        state.get("add_dummy", 0),
            "topic_prefix": state.get("topic_prefix", ""),
        }
        with open(self._metrics_file, "a") as f:
            f.write(json.dumps(record) + "\n")

    # ------------------------------------------------------------------

    def generate_reading(self) -> dict:
        return {
            "power":     round(self.power_base + np.random.normal(0, 2), 4),
            "frequency": round(self.freq_base  + np.random.normal(0, 0.1), 4),
            "voltage":   round(self.volt_base  + np.random.normal(0, 5), 4),
            "timestamp": time.time(),
        }

    def run(self):
        self._connect()
        self.client.loop_start()
        print(f"[{self.grid_id}] started", flush=True)

        while True:
            state    = self._load_state()
            cfg      = self._load_traffic_config()
            # Precedence: MTD state > traffic_config (set by run_emulation --mqtt-rate) > CLI default
            base_interval = cfg.get("publish_interval", self.interval)
            interval = state.get("publish_interval", base_interval)
            reading  = self.generate_reading()
            payload  = self._build_payload(reading, state)
            base     = f"grid/{self.grid_id}"

            # Real publish
            topic = self._topic(f"{base}/telemetry", state)
            self.client.publish(topic, payload, qos=0)
            self._write_stats(len(payload), interval, state)

            # Dummy publishes
            for _ in range(int(state.get("add_dummy", 0))):
                dummy_payload = os.urandom(len(payload))
                self.client.publish(self._topic(f"{base}/dummy", state), dummy_payload, qos=0)

            time.sleep(interval + np.random.uniform(-0.05, 0.05))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--grid-id",  default="microgrid1")
    parser.add_argument("--broker",   default="10.0.0.1")
    parser.add_argument("--port",     type=int,   default=1883)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()

    MicrogridSimulator(args.grid_id, args.broker, args.port, args.interval).run()
