#!/usr/bin/env python3
"""
mtd_telemetry.py — live telemetry of the MTD defense, runs on SEMP.

The coordinator reports everything it does here: every MTD action it schedules,
every ACK/DONE/FAILED an executor sends back, how each action ended (applied,
rolled back, timed out, client lost), the actions it skipped, the executors that
come and go, the NAT rules it opens and closes, and — for the RL coordinator —
every policy decision. Each report becomes one event:

  {"i": <index>, "t": <unix time>, "kind": "<kind>", ...}

Events are kept in memory (served live by mtd_dashboard.py) and appended, one
JSON object per line, to a telemetry.jsonl file that run_experiment.py downloads
with the other logs, so the dashboard can replay a finished run.

Telemetry only records — it derives no metrics. Every aggregate the dashboard
shows (rates, latencies, entropy, cumulative cost) is computed by the page's
reducer from the raw events, so the live view and a replay use the same code.

The one thing computed here is the availability cost of each action, so that it
is written to the log next to the outcome it belongs to. It uses the same
per-knob weights as the RL reward and monitor/compare_coordinators.py
(rl_policy.KNOB_COST), and charges an action when an executor actually fired it
(DONE, or FAILED for a broker hop it attempted) — the moment the executor writes
the client.log line compare_coordinators bills. A broker hop is charged per field
that changed (ip and/or port) — counted from where the executor really was when it
answered (reprice), not from where the coordinator believed it was when it sent the
hop. A DONE/FAILED that only arrives after the action was closed (timed out or its
executor dropped — e.g. stuck behind a blackhole) is charged then, as an
`action_late` event.

DataPlaneObserver adds what the control channel cannot see: whether the nanogrid
data still reaches the broker. It subscribes to the broker over a loopback-only
listener and reports arrivals per second and inter-arrival gaps.

Stdlib only (paho-mqtt is imported lazily by DataPlaneObserver): this file is
copied flat into the semp container next to mtd_coordinator.py.
"""

import json
import threading
import time


class Telemetry:
    """Thread-safe event log plus the ledger of in-flight MTD actions."""

    def __init__(self, path: str = None, knob_cost: dict = None):
        self._lock = threading.Lock()
        self._events: list = []
        self._file = open(path, "a", buffering=1) if path else None
        self._cost = dict(knob_cost or {})
        self._actions: dict = {}           # seq → in-flight action record
        self._unconfirmed: dict = {}       # seq → record closed with no DONE/FAILED
        self._listeners: list = []         # called with every event, outside the lock
        # Publish interval the executors currently use; DataPlaneObserver judges
        # gaps against it. 1.0 s is the executor's default --interval.
        self.publish_interval = 1.0

    # ── raw log ──

    def emit(self, kind: str, **fields) -> dict:
        with self._lock:
            ev = {"i": len(self._events), "t": round(time.time(), 3), "kind": kind, **fields}
            self._events.append(ev)
            if self._file is not None:
                self._file.write(json.dumps(ev) + "\n")
            listeners = list(self._listeners)
        for fn in listeners:
            fn(ev)
        return ev

    def add_listener(self, fn) -> None:
        """Call fn(event) after every emit (e.g. delivery_detector.LiveDetector)."""
        with self._lock:
            self._listeners.append(fn)

    def events(self, since: int = 0) -> list:
        with self._lock:
            return self._events[max(0, since):]

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    # ── MTD action ledger ──

    def scheduled(self, seq: int, action: str, knobs: list, in_messages: int,
                  awaited, **params) -> None:
        """An action was broadcast. `knobs` are the KNOB_COST keys it moves
        (a broker hop lists only the fields that changed)."""
        with self._lock:
            self._actions[seq] = {
                "t": time.time(), "action": action, "params": params,
                "cost": sum(self._cost.get(k, 0.0) for k in knobs),
                "done": set(), "failed": set(),
            }
        self.emit("action_scheduled", seq=seq, action=action, knobs=list(knobs),
                  in_messages=in_messages, awaited=sorted(awaited), params=params)

    def reply(self, seq: int, scmc_id: str, phase: str) -> None:
        """An executor answered: phase is ACK, DONE or FAILED."""
        late = None
        with self._lock:
            rec = self._actions.get(seq)
            latency = None
            if rec is None and phase in ("DONE", "FAILED"):
                late = self._unconfirmed.pop(seq, None)
                if late is not None and late["action"] == "freq" and phase == "DONE":
                    self.publish_interval = late["params"]["interval"]
            if rec is not None:
                latency = round(time.time() - rec["t"], 3)
                if phase == "DONE":
                    rec["done"].add(scmc_id)
                    if rec["action"] == "freq":
                        self.publish_interval = rec["params"]["interval"]
                elif phase == "FAILED":
                    rec["failed"].add(scmc_id)
        self.emit("reply", seq=seq, scmc_id=scmc_id, phase=phase, latency_s=latency)
        if late is not None:
            # The executor did fire it after all (its DONE was stuck, e.g. behind a
            # blackhole): charge it now, as client.log — and so the post-hoc cost — does.
            self.emit("action_late", seq=seq, action=late["action"], scmc_id=scmc_id,
                      phase=phase, cost=round(late["cost"], 4),
                      delay_s=round(time.time() - late["t"], 3))

    def finished(self, seq: int, timed_out=(), rolled_back: bool = False) -> None:
        """The coordinator stopped waiting on `seq`. Classifies the outcome:
        applied (someone DONE), failed (only FAILED), timed_out (the watchdog gave
        up with no answer) or client_lost (every awaited executor disconnected)."""
        with self._lock:
            rec = self._actions.pop(seq, None)
        if rec is None:
            return
        if rec["done"]:
            status = "applied"
        elif rec["failed"]:
            status = "failed"
        elif timed_out:
            status = "timed_out"
        else:
            status = "client_lost"
        fired = rec["done"] or rec["failed"]
        if not fired:
            with self._lock:
                self._unconfirmed[seq] = rec
                for old in [q for q, r in self._unconfirmed.items() if time.time() - r["t"] > 600]:
                    del self._unconfirmed[old]
        self.emit("action_outcome", seq=seq, action=rec["action"], status=status,
                  rolled_back=rolled_back,
                  cost=round(rec["cost"], 4) if fired else 0.0,
                  duration_s=round(time.time() - rec["t"], 3),
                  done=sorted(rec["done"]), failed=sorted(rec["failed"]),
                  timed_out=sorted(timed_out))

    def reprice(self, seq: int, knobs: list) -> None:
        """Charge `seq` for these knobs instead of those it was scheduled with — the
        coordinator calls it when the executor answers a broker hop, from where the
        executor really started (see SEMPCoordinator._reprice_hop). Works on in-flight
        actions and on closed-but-unconfirmed ones (a late DONE/FAILED)."""
        with self._lock:
            rec = self._actions.get(seq) or self._unconfirmed.get(seq)
            if rec is not None:
                rec["cost"] = sum(self._cost.get(k, 0.0) for k in knobs)

    def skipped(self, action: str, reason: str) -> None:
        self.emit("action_skipped", action=action, reason=reason)

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.close()
                self._file = None


class DataPlaneObserver:
    """Watches the nanogrid data reaching the broker (grid/<scmc>/snapshot).

    Emits a `data` event every `period` seconds — arrivals in the window per SCMC
    and the current silence (time since each SCMC's last message) — and a
    `data_gap` event whenever two consecutive messages from one SCMC are more
    than `gap_factor` publish intervals apart. Connects over the loopback-only
    listener in mosquitto.conf, so it never adds traffic to the observed link.
    """

    def __init__(self, telemetry: Telemetry, host: str = "127.0.0.1", port: int = 1883,
                 period: float = 1.0, gap_factor: float = 2.0):
        self.telemetry = telemetry
        self.host, self.port = host, port
        self.period, self.gap_factor = period, gap_factor
        self._lock = threading.Lock()
        self._count: dict = {}             # scmc_id → arrivals in current window
        self._last: dict = {}              # scmc_id → time of last arrival

    def _on_message(self, _client, _userdata, msg) -> None:
        parts = msg.topic.split("/")
        if len(parts) != 3:
            return
        scmc_id, now = parts[1], time.time()
        expected = self.telemetry.publish_interval
        with self._lock:
            self._count[scmc_id] = self._count.get(scmc_id, 0) + 1
            last = self._last.get(scmc_id)
            self._last[scmc_id] = now
        if last is not None and now - last > self.gap_factor * expected:
            self.telemetry.emit("data_gap", scmc_id=scmc_id, t_start=round(last, 3),
                                gap_s=round(now - last, 3), expected_s=expected)

    def _tick_loop(self) -> None:
        while True:
            time.sleep(self.period)
            now = time.time()
            with self._lock:
                counts, self._count = self._count, {}
                silence = {s: round(now - t, 3) for s, t in self._last.items()}
            if counts or silence:
                self.telemetry.emit("data", window_s=self.period,
                                    n={s: counts.get(s, 0) for s in silence},
                                    silence_s=silence,
                                    expected_s=self.telemetry.publish_interval)

    def start(self) -> None:
        import paho.mqtt.client as mqtt
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                                 client_id="semp-telemetry")
        except AttributeError:             # paho < 2.0 (the image pins 1.6.1)
            client = mqtt.Client(client_id="semp-telemetry")
        client.on_connect = lambda c, *_: c.subscribe("grid/+/snapshot", qos=0)
        client.on_message = self._on_message
        client.connect_async(self.host, self.port)
        client.loop_start()                # retries until the broker is up
        threading.Thread(target=self._tick_loop, daemon=True).start()
        print(f"[telemetry] observing data plane on {self.host}:{self.port}", flush=True)
