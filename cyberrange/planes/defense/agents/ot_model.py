#!/usr/bin/env python3
"""ot_model.py — the learned half of the OT sensor: a per-window behavioural
featurizer over the observed Modbus traffic + process state, and a robust
anomaly model calibrated online on the normal phase.

Copied flat onto the sensor machine next to ot_sensor.py (see
the scenario's guest_files.py). Stdlib + numpy only, unit-testable off-wire.

Why a model next to the rules: the rules (ot_sensor.py) encode the plant
contract — who may write what, which values are in range, when the physics went
out of band. A stealthy attacker that writes legitimate values from an allowed
host passes every write-time rule and is only caught once the physics moves.
The model instead learns what normal *behaviour* looks like (session churn,
setpoint jump sizes, how long control stays in MANUAL, …) and flags the
deviation, possibly before the impact.

Model: for every feature, center = median and scale = max(MAD·1.4826, floor)
over the calibration windows; a window's score is its largest robust |z|. The
floors are per-feature priors in natural units (a count, kW, pu, seconds) so a
feature that never varied during calibration does not make the model explode on
the first harmless blip. Threshold = max(k, margin × the q-quantile of the
calibration scores) — a quantile, not the max, so a start-up transient inside
the calibration period (the clients' first TCP handshakes) cannot inflate it.
"""

import math

import numpy as np

FEATURES = (
    "reads_ir",  # fc 0x04 requests
    "reads_hr",  # fc 0x03 requests
    "writes",  # write requests (any source)
    "writes_nonplc",  # write requests not from the PLC
    "plc_writes",  # PLC write requests (drop to 0 when it hands off)
    "new_sessions",  # TCP SYNs toward the engine's Modbus port
    "n_sources",  # distinct client IPs talking Modbus in the window
    "mode_writes",  # writes to the control-mode register
    "max_dsetpoint",  # largest |Δ| of a DG setpoint write vs the setpoint in force (kW)
    "manual_run_s",  # seconds control has continuously been in MANUAL
    "v_max",  # worst-high bus voltage observed (pu)
    "v_min",  # worst-low bus voltage observed (pu)
)

# Per-feature scale floors (natural units).
FLOORS = {
    "reads_ir": 1.0,
    "reads_hr": 1.0,
    "writes": 1.0,
    "writes_nonplc": 1.0,
    "plc_writes": 1.0,
    "new_sessions": 0.2,
    "n_sources": 0.5,
    "mode_writes": 0.5,
    "max_dsetpoint": 5.0,
    "manual_run_s": 2.0,
    "v_max": 0.008,
    "v_min": 0.008,
}

MAD_TO_SIGMA = 1.4826


class WindowFeaturizer:
    """Accumulates observations and emits one feature vector per window.

    The sensor feeds it parsed events (observe_*) and calls flush(now), which
    closes every window that ended at or before `now` (empty windows included,
    so silence is a signal too) and returns [(window_start, vector)]."""

    def __init__(self, plc_ip, window_s=1.0, setpoint_register=0, mode_register=2, manual_value=1):
        self.plc_ip = plc_ip
        self.window_s = float(window_s)
        self.sp_reg = setpoint_register
        self.mode_reg = mode_register
        self.manual_value = manual_value
        self._win = None  # current window index
        self._c = self._empty()
        # Process state carried across windows.
        self.setpoint = None
        self.ctrl_mode = 0
        self.manual_since = None
        self.v_max = None
        self.v_min = None

    def _empty(self):
        return {
            "reads_ir": 0,
            "reads_hr": 0,
            "writes": 0,
            "writes_nonplc": 0,
            "plc_writes": 0,
            "new_sessions": 0,
            "sources": set(),
            "mode_writes": 0,
            "max_dsetpoint": 0.0,
            "v_max": None,
            "v_min": None,
        }

    def _index(self, t):
        return int(math.floor(t / self.window_s))

    def _advance(self, t):
        """Close windows up to t; return the closed ones."""
        out = []
        idx = self._index(t)
        if self._win is None:
            self._win = idx
            return out
        while self._win < idx:
            out.append((self._win * self.window_s, self._vector(self._win)))
            self._win += 1
            self._c = self._empty()
        return out

    @property
    def current_window(self):
        return self._win

    def peek(self, t):
        """The still-open window's vector as of time t (does not close it)."""
        return self._vector(self._win, end=t)

    def _vector(self, win, end=None):
        c = self._c
        end = (win + 1) * self.window_s if end is None else end
        manual_run = (end - self.manual_since) if self.manual_since is not None else 0.0
        v_max = c["v_max"] if c["v_max"] is not None else self.v_max
        v_min = c["v_min"] if c["v_min"] is not None else self.v_min
        return np.array(
            [
                c["reads_ir"],
                c["reads_hr"],
                c["writes"],
                c["writes_nonplc"],
                c["plc_writes"],
                c["new_sessions"],
                len(c["sources"]),
                c["mode_writes"],
                c["max_dsetpoint"],
                max(0.0, manual_run),
                v_max if v_max is not None else 1.0,
                v_min if v_min is not None else 1.0,
            ],
            dtype=float,
        )

    # ── observations ────────────────────────────────────────────────────────
    def observe_syn(self, t, src):
        closed = self._advance(t)
        self._c["new_sessions"] += 1
        self._c["sources"].add(src)
        return closed

    def observe_read(self, t, src, fc):
        closed = self._advance(t)
        self._c["sources"].add(src)
        if fc == 0x04:
            self._c["reads_ir"] += 1
        elif fc == 0x03:
            self._c["reads_hr"] += 1
        return closed

    def observe_write(self, t, src, register, value):
        """`value` in engineering units (None if unknown register)."""
        closed = self._advance(t)
        c = self._c
        c["writes"] += 1
        c["sources"].add(src)
        if src == self.plc_ip:
            c["plc_writes"] += 1
        else:
            c["writes_nonplc"] += 1
        if register == self.mode_reg:
            c["mode_writes"] += 1
            self._set_mode(t, value)
        elif register == self.sp_reg and value is not None:
            if self.setpoint is not None:
                c["max_dsetpoint"] = max(c["max_dsetpoint"], abs(value - self.setpoint))
            self.setpoint = value
        return closed

    def observe_state(self, t, state):
        """Process state decoded from read responses: any of v_load, v_dg,
        ctrl_mode, dg_setpoint."""
        closed = self._advance(t)
        vs = [state[k] for k in ("v_load", "v_dg") if state.get(k) is not None]
        if vs:
            hi, lo = max(vs), min(vs)
            c = self._c
            c["v_max"] = hi if c["v_max"] is None else max(c["v_max"], hi)
            c["v_min"] = lo if c["v_min"] is None else min(c["v_min"], lo)
            self.v_max, self.v_min = hi, lo
        if state.get("ctrl_mode") is not None:
            self._set_mode(t, state["ctrl_mode"])
        if state.get("dg_setpoint") is not None:
            self.setpoint = state["dg_setpoint"]
        return closed

    def _set_mode(self, t, mode):
        if mode is None:
            return
        mode = int(round(mode))
        if mode == self.manual_value and self.ctrl_mode != self.manual_value:
            self.manual_since = t
        elif mode != self.manual_value:
            self.manual_since = None
        self.ctrl_mode = mode

    def flush(self, now):
        return self._advance(now)


class RobustAnomalyModel:
    """Median/MAD robust z-score model with online calibration."""

    def __init__(self, k=6.0, margin=1.2, quantile=0.95, min_calibration=10, floors=None):
        self.k = float(k)
        self.margin = float(margin)
        self.quantile = float(quantile)
        self.min_calibration = int(min_calibration)
        self.floors = np.array([(floors or FLOORS)[f] for f in FEATURES], dtype=float)
        self._calib = []
        self.center = None
        self.scale = None
        self.threshold = None

    @property
    def fitted(self):
        return self.center is not None

    def add_calibration(self, vec):
        self._calib.append(np.asarray(vec, dtype=float))

    def fit(self):
        if len(self._calib) < self.min_calibration:
            raise ValueError(
                f"need >= {self.min_calibration} calibration windows, got {len(self._calib)}"
            )
        X = np.vstack(self._calib)
        self.center = np.median(X, axis=0)
        mad = np.median(np.abs(X - self.center), axis=0) * MAD_TO_SIGMA
        self.scale = np.maximum(mad, self.floors)
        calib_scores = [self.score(x)[0] for x in X]
        self.threshold = max(self.k, self.margin * float(np.quantile(calib_scores, self.quantile)))
        return self

    def score(self, vec):
        """-> (score, z-vector)."""
        z = np.abs((np.asarray(vec, dtype=float) - self.center) / self.scale)
        return float(z.max()), z

    def explain(self, z, top=3):
        idx = np.argsort(z)[::-1][:top]
        return [{"feature": FEATURES[i], "z": round(float(z[i]), 2)} for i in idx]

    def is_anomalous(self, vec):
        s, z = self.score(vec)
        return s > self.threshold, s, z
