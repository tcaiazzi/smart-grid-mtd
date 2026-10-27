#!/usr/bin/env python3
"""
delivery_detector.py — detects a blackhole attack from the SEMP's side.

The attacker's active phase is a blackhole on the router (`iptables -A FORWARD -s
<ip> -j DROP`): once it hits an address the SCMC <-> SEMP path uses, nanogrid data
stops reaching the broker. This module turns what the SEMP observes into one feature
vector per SCMC per 1 s window and scores it "attack in effect" vs "normal". Data also
stops for benign reasons — a broker / source-IP hop reconnecting, a lossy or slow
network, an executor restarting — and the features are chosen to tell those apart:

  • a hop/source hop explains a short gap (an MTD action is in flight);
  • a restart closes the control channel explicitly (a disconnect event), while a
    blackhole is silent: the coordinator keeps sending actions and the ACKs never come
    (blocking the SCMC's source drops its replies; blocking the broker drops the
    commands, so the executor never answers either);
  • a lossy/slow network delays ACKs and data but rarely silences them.

Features come in sets (FEATURE_SETS): the Featurizer computes all of them and each
trained model records which ones it uses, so feature sets can be compared on the
same data. "v2h" adds short history (values 2 and 4 windows ago), kept by History —
the same object in replay() and LiveDetector, so live and offline vectors match.

Everything is computed from mtd_telemetry events only, so the same Featurizer runs
offline on a downloaded telemetry.jsonl (training, KPIs) and live on the SEMP
(LiveDetector, fed by Telemetry.add_listener) — the two can't drift apart.

The trained detector — a small MLP or a gradient-boosted tree ensemble (sklearn,
train_delivery_detector.py on the host) — is exported to a flat .npz that
NumpyDetector / NumpyTreeDetector replay with numpy only (load_detector picks the
right one): the semp image has numpy but no sklearn. Same approach as rl_policy.py, and like it this file is numpy-only
and copied flat into the semp container (`import delivery_detector`).
"""

import threading
import time
from collections import deque

import numpy as np

# Bumped whenever a feature's meaning changes: a model exported for another schema is
# refused (NumpyDetector.load) instead of silently scoring the wrong inputs.
FEATURE_SCHEMA = 2

BASE_FEATURES = [
    # ── v1 ──
    "silence",            # time since the last data message, in publish intervals
    "rate_1s",            # messages in the last window × expected interval (≈1 normal)
    "rate_5s",            # same, over the last 5 windows
    "unacked",            # actions sent 1–10 s ago this SCMC has not answered at all
    "ctrl_quiet",         # log1p(seconds since this SCMC's last control message)
    "ctrl_connected",     # control channel up (0/1)
    "since_disconnect",   # log1p(seconds since its last disconnect), capped
    "reconnecting",       # broker/source hop in flight or closed < 3 s ago (0/1)
    "ack_ms",             # log1p(max ACK latency over the last 10 s, ms)
    "gaps_30s",           # data gaps over the last 30 s
    "expected_s",         # current publish interval (s)
    # ── v2 ──
    "pending_age",        # age of the oldest still-open action awaiting it, no reply at all (s)
    "pending_n",          # how many such actions
    "since_reconnect",    # log1p(seconds since its last confirmed hop/source hop: DONE)
    "unconfirmed_age",    # age of the oldest open hop/source hop it has not DONE (s)
    "silence_vs_normal",  # silence / max(largest gap of the last 60 s, expected interval)
    "ctrl_alive_silent",  # silence while control messages still arrive (last 3 s)
]
HISTORY = ["silence", "rate_1s", "pending_age"]   # also seen 2 and 4 windows ago
HISTORY_LAGS = (2, 4)
FEATURES = BASE_FEATURES + [f"{f}_lag{k}" for k in HISTORY_LAGS for f in HISTORY]

_V2 = ["silence", "rate_1s", "rate_5s", "ctrl_quiet", "ctrl_connected", "since_disconnect",
       "ack_ms", "gaps_30s", "expected_s", "pending_age", "pending_n", "since_reconnect",
       "unconfirmed_age", "silence_vs_normal", "ctrl_alive_silent"]
FEATURE_SETS = {
    "v1": BASE_FEATURES[:11],
    "v2": _V2,
    "v2h": _V2 + FEATURES[len(BASE_FEATURES):],
}
_IDX = {f: i for i, f in enumerate(FEATURES)}

ACK_GRACE_S = 1.0        # an ACK normally takes milliseconds
RECENT_S = 10.0          # window for unacked actions and ACK latency
RECONNECT_GRACE_S = 3.0  # a hop's reconnect can still explain a gap this long after
PENDING_CAP_S = 30.0     # the coordinator's watchdog closes actions well before this
NORMAL_GAP_S = 60.0      # window for the "normal" gap size
CTRL_ALIVE_S = 3.0
NEVER_S = 600.0          # cap for "time since" features
RULE_K = 3.0             # rule baseline: silent for more than RULE_K intervals


class _Scmc:
    def __init__(self, t: float):
        self.first_t = t
        self.last_arrival = None          # time of the last data message
        self.arrivals = deque()           # (window end t, n messages)
        self.arrival_times = deque()      # distinct last-arrival times (for gap sizes)
        self.last_ctrl = t
        self.connected = True
        self.last_disconnect = None
        self.last_reconnect = None        # last DONE of a hop / source hop
        self.ack_lat = deque()            # (t, latency_s)
        self.gaps = deque()               # gap end times


class Featurizer:
    """Folds mtd_telemetry events into per-SCMC state; features() reads it at a time
    and returns the BASE_FEATURES vector (History adds the lagged ones)."""

    def __init__(self):
        self.expected = 1.0
        self.scmc: dict = {}
        self.actions: dict = {}           # seq → {t, action, awaited, answered, done, end}

    def _get(self, scmc_id: str, t: float) -> _Scmc:
        if scmc_id not in self.scmc:
            self.scmc[scmc_id] = _Scmc(t)
        return self.scmc[scmc_id]

    def apply(self, ev: dict) -> None:
        kind, t = ev.get("kind"), ev.get("t", 0.0)
        if kind == "run_info":
            self.expected = float((ev.get("initial") or {}).get("interval") or 1.0)
        elif kind == "data":
            self.expected = float(ev.get("expected_s") or self.expected)
            for sid, n in (ev.get("n") or {}).items():
                s = self._get(sid, t)
                s.arrivals.append((t, n))
                silence = (ev.get("silence_s") or {}).get(sid)
                if silence is not None:
                    s.last_arrival = t - silence
                    if not s.arrival_times or s.last_arrival - s.arrival_times[-1] > 1e-3:
                        s.arrival_times.append(s.last_arrival)
                while s.arrivals and s.arrivals[0][0] < t - 5.5:
                    s.arrivals.popleft()
                while s.arrival_times and s.arrival_times[0] < t - NORMAL_GAP_S:
                    s.arrival_times.popleft()
        elif kind == "data_gap":
            self._get(ev["scmc_id"], t).gaps.append(t)
        elif kind == "action_scheduled":
            self.actions[ev["seq"]] = {"t": t, "action": ev.get("action"),
                                       "awaited": set(ev.get("awaited") or []),
                                       "answered": set(), "done": set(), "end": None}
            self._prune(t)
        elif kind == "reply":
            s = self._get(ev["scmc_id"], t)
            s.last_ctrl = t
            a = self.actions.get(ev.get("seq"))
            if a is not None:
                a["answered"].add(ev["scmc_id"])
                if ev.get("phase") == "DONE":
                    a["done"].add(ev["scmc_id"])
                    if a["action"] in ("hop", "src"):
                        s.last_reconnect = t
            if ev.get("phase") == "ACK" and ev.get("latency_s") is not None:
                s.ack_lat.append((t, float(ev["latency_s"])))
        elif kind == "action_outcome":
            a = self.actions.get(ev.get("seq"))
            if a is not None:
                a["end"] = t
        elif kind == "client":
            s = self._get(ev["scmc_id"], t)
            if ev.get("event") in ("connected", "handover"):
                s.connected, s.last_ctrl = True, t
            elif ev.get("event") in ("disconnected", "broadcast_failed"):
                s.connected, s.last_disconnect = False, t

    def _prune(self, t: float) -> None:
        for seq in [q for q, a in self.actions.items() if a["t"] < t - 60]:
            del self.actions[seq]

    def scmc_ids(self) -> list:
        return sorted(self.scmc)

    def features(self, scmc_id: str, now: float) -> np.ndarray:
        s = self.scmc.get(scmc_id) or _Scmc(now)
        exp = max(self.expected, 1e-3)
        last = s.last_arrival if s.last_arrival is not None else s.first_t
        silence_s = max(0.0, now - last)
        n1 = sum(n for t, n in s.arrivals if t > now - 1.5)
        n5 = sum(n for t, n in s.arrivals if t > now - 5.5)
        mine = [a for a in self.actions.values() if scmc_id in a["awaited"] and a["t"] <= now]
        unacked = sum(1 for a in mine if now - RECENT_S <= a["t"] <= now - ACK_GRACE_S
                      and scmc_id not in a["answered"])
        reconnecting = any(a["action"] in ("hop", "src") and
                           (a["end"] is None or now - a["end"] < RECONNECT_GRACE_S)
                           and a["t"] <= now
                           for a in self.actions.values())
        silent_open = [now - a["t"] for a in mine if a["end"] is None
                       and scmc_id not in a["answered"] and now - a["t"] >= ACK_GRACE_S]
        unconfirmed = [now - a["t"] for a in mine if a["end"] is None
                       and a["action"] in ("hop", "src") and scmc_id not in a["done"]]
        while s.ack_lat and s.ack_lat[0][0] < now - RECENT_S:
            s.ack_lat.popleft()
        while s.gaps and s.gaps[0] < now - 30:
            s.gaps.popleft()
        ack = max((lat for t, lat in s.ack_lat if t <= now), default=0.0)
        since_disc = NEVER_S if s.last_disconnect is None else min(NEVER_S, now - s.last_disconnect)
        since_rec = NEVER_S if s.last_reconnect is None else min(NEVER_S, now - s.last_reconnect)
        times = [a for a in s.arrival_times if now - NORMAL_GAP_S <= a <= now]
        normal_gap = max((b - a for a, b in zip(times, times[1:])), default=exp)
        silence = min(60.0, silence_s / exp)
        ctrl_quiet_s = min(NEVER_S, max(0.0, now - s.last_ctrl))
        return np.array([
            silence,
            min(5.0, n1 * exp),
            min(5.0, n5 * exp / 5.0),
            min(10.0, unacked),
            np.log1p(ctrl_quiet_s),
            1.0 if s.connected else 0.0,
            np.log1p(max(0.0, since_disc)),
            1.0 if reconnecting else 0.0,
            np.log1p(ack * 1000.0),
            min(10.0, sum(1 for g in s.gaps if g <= now)),
            exp,
            min(PENDING_CAP_S, max(silent_open, default=0.0)),
            min(10.0, len(silent_open)),
            np.log1p(max(0.0, since_rec)),
            min(PENDING_CAP_S, max(unconfirmed, default=0.0)),
            min(60.0, silence_s / max(normal_gap, exp)),
            silence if ctrl_quiet_s < CTRL_ALIVE_S else 0.0,
        ], dtype=np.float32)


class History:
    """Per-SCMC memory of past BASE_FEATURES vectors (one per 1 s tick); full()
    appends the HISTORY features as they were HISTORY_LAGS ticks ago (the oldest
    available early on). Shared by replay() and LiveDetector."""

    def __init__(self):
        self._past: dict = {}

    def full(self, scmc_id: str, base: np.ndarray) -> np.ndarray:
        past = self._past.setdefault(scmc_id, deque(maxlen=max(HISTORY_LAGS) + 1))
        past.append(base)
        lagged = [past[max(0, len(past) - 1 - k)][_IDX[f]] for k in HISTORY_LAGS for f in HISTORY]
        return np.concatenate([base, np.asarray(lagged, dtype=np.float32)])


def replay(events, step: float = 1.0):
    """Feed recorded events through a Featurizer and yield (t, scmc_id, features)
    every `step` seconds, from the first data event on — the offline twin of
    LiveDetector's 1 s tick. Features are the full FEATURES vector."""
    events = sorted(events, key=lambda e: (e.get("t", 0.0), e.get("i", 0)))
    fz, hist = Featurizer(), History()
    start = next((e["t"] for e in events if e.get("kind") == "data"), None)
    if start is None:
        return
    end = events[-1]["t"]
    i, now = 0, start
    while now <= end:
        while i < len(events) and events[i]["t"] <= now:
            fz.apply(events[i])
            i += 1
        for sid in fz.scmc_ids():
            yield now, sid, hist.full(sid, fz.features(sid, now))
        now += step


def rule_decision(x: np.ndarray) -> bool:
    """Threshold baseline on a full FEATURES vector: silent for more than RULE_K
    publish intervals with no confirmed hop/source hop in the last few seconds
    (which would explain the gap)."""
    return bool(x[_IDX["silence"]] > RULE_K
                and x[_IDX["since_reconnect"]] > np.log1p(RECONNECT_GRACE_S))


def smooth(hits, k: int = 2, n: int = 3) -> np.ndarray:
    """k-of-n smoothing of per-window decisions (each window: at least k hits among
    the last n). n=1 leaves them unchanged."""
    hits = np.asarray(hits, dtype=bool)
    if n <= 1:
        return hits
    c = np.convolve(hits.astype(int), np.ones(n, dtype=int))[:len(hits)]
    return c >= k


class NumpyDetector:
    """Replays the exported MLP (StandardScaler + ReLU hidden layers + logistic
    output, as sklearn's MLPClassifier) with numpy only, on the model's own subset
    of FEATURES."""

    def __init__(self, mean, std, weights, biases, threshold: float, features=None,
                 smoothing=(1, 1)):
        self.mean, self.std = np.asarray(mean), np.asarray(std)
        self.weights, self.biases = weights, biases
        self.threshold = float(threshold)
        self.features = list(features or FEATURE_SETS["v1"])
        self.smoothing = tuple(int(v) for v in smoothing)
        self._cols = [_IDX[f] for f in self.features]

    @classmethod
    def load(cls, path: str) -> "NumpyDetector":
        z = np.load(path)
        schema = int(z["feature_schema"]) if "feature_schema" in z else 1
        if schema != FEATURE_SCHEMA:
            raise ValueError(f"{path}: detector exported for feature schema {schema}, "
                             f"this delivery_detector computes schema {FEATURE_SCHEMA} — retrain it")
        n = int(z["n_layers"])
        return cls(z["mean"], z["std"], [z[f"W{i}"] for i in range(n)],
                   [z[f"b{i}"] for i in range(n)], float(z["threshold"]),
                   [str(f) for f in z["features"]], tuple(z["smoothing"]))

    def save(self, path: str) -> None:
        arrays = {"kind": "mlp", "mean": self.mean, "std": self.std,
                  "threshold": self.threshold,
                  "n_layers": len(self.weights), "features": np.array(self.features),
                  "feature_schema": FEATURE_SCHEMA, "smoothing": np.array(self.smoothing)}
        for i, (w, b) in enumerate(zip(self.weights, self.biases)):
            arrays[f"W{i}"], arrays[f"b{i}"] = w, b
        np.savez(path, **arrays)

    def select(self, x_full: np.ndarray) -> np.ndarray:
        """The model's columns out of full FEATURES vector(s)."""
        return np.atleast_2d(x_full)[:, self._cols]

    def proba(self, X: np.ndarray) -> np.ndarray:
        """X: rows in the model's own feature order (see select())."""
        h = (np.atleast_2d(X) - self.mean) / self.std
        for w, b in zip(self.weights[:-1], self.biases[:-1]):
            h = np.maximum(0.0, h @ w + b)
        z = h @ self.weights[-1] + self.biases[-1]
        return (1.0 / (1.0 + np.exp(-z))).ravel()

    def top_features(self, x: np.ndarray, k: int = 3) -> list:
        """The k features furthest from normal (largest |z-score|) — a hint for the UI.
        x in the model's own feature order."""
        z = (np.ravel(x) - self.mean) / self.std
        return [self.features[i] for i in np.argsort(-np.abs(z))[:k]]


class NumpyTreeDetector(NumpyDetector):
    """Replays an exported HistGradientBoostingClassifier (binary, numerical features,
    on standardized inputs like the MLP) with numpy only: every tree is walked from
    its root, going left when x[feature] <= threshold, and the leaf values are summed
    on top of the baseline into the logit.

    All trees live in flat node arrays (left/right are global node indices); `roots`
    holds each tree's first node.
    """

    def __init__(self, mean, std, baseline: float, roots, feature, thr, left, right,
                 leaf, value, threshold: float, features=None, smoothing=(1, 1)):
        super().__init__(mean, std, [], [], threshold, features, smoothing)
        self.baseline = float(baseline)
        self.roots, self.feature, self.thr = map(np.asarray, (roots, feature, thr))
        self.left, self.right = np.asarray(left), np.asarray(right)
        self.leaf, self.value = np.asarray(leaf, dtype=bool), np.asarray(value)

    @classmethod
    def from_npz(cls, z) -> "NumpyTreeDetector":
        return cls(z["mean"], z["std"], float(z["baseline"]), z["roots"], z["feature"],
                   z["thr"], z["left"], z["right"], z["leaf"], z["value"],
                   float(z["threshold"]), [str(f) for f in z["features"]], tuple(z["smoothing"]))

    def save(self, path: str) -> None:
        np.savez(path, kind="hgb", mean=self.mean, std=self.std, baseline=self.baseline,
                 roots=self.roots, feature=self.feature, thr=self.thr, left=self.left,
                 right=self.right, leaf=self.leaf, value=self.value,
                 threshold=self.threshold, features=np.array(self.features),
                 feature_schema=FEATURE_SCHEMA, smoothing=np.array(self.smoothing))

    def proba(self, X: np.ndarray) -> np.ndarray:
        h = (np.atleast_2d(X) - self.mean) / self.std
        rows = np.arange(len(h))
        z = np.full(len(h), self.baseline)
        for root in self.roots:
            node = np.full(len(h), root)
            while True:
                inner = ~self.leaf[node]
                if not inner.any():
                    break
                n = node[inner]
                go_left = h[rows[inner], self.feature[n]] <= self.thr[n]
                node[inner] = np.where(go_left, self.left[n], self.right[n])
            z += self.value[node]
        return 1.0 / (1.0 + np.exp(-z))


def load_detector(path: str) -> NumpyDetector:
    """The exported detector in `path`, MLP or trees, after the schema check."""
    z = np.load(path)
    schema = int(z["feature_schema"]) if "feature_schema" in z else 1
    if schema != FEATURE_SCHEMA:
        raise ValueError(f"{path}: detector exported for feature schema {schema}, "
                         f"this delivery_detector computes schema {FEATURE_SCHEMA} — retrain it")
    if "kind" in z and str(z["kind"]) == "hgb":
        return NumpyTreeDetector.from_npz(z)
    return NumpyDetector.load(path)


class LiveDetector:
    """Runs the detector on the SEMP: listens to telemetry, scores every SCMC each
    second and emits `detection` events plus `detector_alert` on state changes.

    A window is a hit when its score passes the threshold — after the model's own
    k-of-n smoothing, if it was trained with one, exactly as the KPIs were computed.
    The alert adds hysteresis on top (raised after RAISE hits, cleared after CLEAR
    misses) so the dashboard doesn't flicker.
    """

    RAISE, CLEAR = 2, 3

    def __init__(self, telemetry, model_path: str, period: float = 1.0):
        self.telemetry = telemetry
        self.model = load_detector(model_path)
        self.period = period
        self.fz = Featurizer()
        self.hist = History()
        self._lock = threading.Lock()
        self._raw: dict = {}
        self._above: dict = {}
        self._below: dict = {}
        self._alert: dict = {}

    def _on_event(self, ev: dict) -> None:
        if ev.get("kind") in ("detection", "detector_alert"):
            return
        with self._lock:
            self.fz.apply(ev)

    def step(self, now: float) -> None:
        with self._lock:
            rows = [(sid, self.hist.full(sid, self.fz.features(sid, now)))
                    for sid in self.fz.scmc_ids()]
        k, n = self.model.smoothing
        for sid, x in rows:
            xm = self.model.select(x)
            p = float(self.model.proba(xm)[0])
            raw = self._raw.setdefault(sid, deque(maxlen=max(n, 1)))
            raw.append(p >= self.model.threshold)
            hit = sum(raw) >= k if n > 1 else raw[-1]
            self._above[sid] = self._above.get(sid, 0) + 1 if hit else 0
            self._below[sid] = 0 if hit else self._below.get(sid, 0) + 1
            alert = self._alert.get(sid, False)
            if not alert and self._above[sid] >= self.RAISE:
                alert = True
            elif alert and self._below[sid] >= self.CLEAR:
                alert = False
            self.telemetry.emit("detection", scmc_id=sid, p=round(p, 4), hit=bool(hit),
                                rule=rule_decision(x), alert=alert,
                                threshold=self.model.threshold,
                                top=self.model.top_features(xm),
                                x=[round(float(v), 3) for v in x])
            if alert != self._alert.get(sid, False):
                self._alert[sid] = alert
                self.telemetry.emit("detector_alert", scmc_id=sid,
                                    state="raised" if alert else "cleared", p=round(p, 4))

    def _loop(self) -> None:
        while True:
            time.sleep(self.period)
            self.step(time.time())

    def start(self) -> None:
        for ev in self.telemetry.events():        # catch up on what happened so far
            self._on_event(ev)
        self.telemetry.add_listener(self._on_event)
        threading.Thread(target=self._loop, daemon=True).start()
        print(f"[detector] delivery attack detector running "
              f"({len(self.model.features)} features, threshold {self.model.threshold:.2f}, "
              f"smoothing {self.model.smoothing[0]}-of-{self.model.smoothing[1]})", flush=True)
