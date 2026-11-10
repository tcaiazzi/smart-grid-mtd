"""progress.py — the experiment progress ledger: an append-only JSONL file of
events that the CPS runners write while they work and the progress dashboard
(monitor/cps_dashboard.py) reads. It is the single source of truth for what is
queued, running, done or failed, which phase a run is in, the live plant state
pulled from the containers, and the results as they come in.

Every line is one event:

    {"seq": <n>, "t": <unix time>, "kind": "<kind>", ["run_id": ...], ...}

`seq` keeps counting across re-opens of the same file, so a resumed campaign
appends to its ledger without renumbering. Host-side, stdlib only.
"""

import json
import os
import threading
import time


class ProgressLog:
    """Thread-safe append-only JSONL event ledger."""

    def __init__(self, path):
        self.path = path
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                self._seq = sum(1 for line in f if line.strip())
        self._file = open(path, "a", buffering=1)

    def emit(self, kind, **fields):
        with self._lock:
            ev = {"seq": self._seq, "t": round(time.time(), 3), "kind": kind, **fields}
            self._file.write(json.dumps(ev, default=str) + "\n")
            self._seq += 1
        return ev

    __call__ = emit

    def bind(self, **fixed):
        """An emitter that stamps every event with `fixed` (e.g. run_id=...)."""
        return BoundProgress(self, fixed)

    def close(self):
        with self._lock:
            if not self._file.closed:
                self._file.close()


class BoundProgress:
    def __init__(self, log, fixed):
        self._log = log
        self._fixed = dict(fixed)

    def emit(self, kind, **fields):
        return self._log.emit(kind, **{**self._fixed, **fields})

    __call__ = emit

    def bind(self, **more):
        return BoundProgress(self._log, {**self._fixed, **more})

    def close(self):
        pass   # the owner of the log closes it


class NullProgress:
    """Emitter that records nothing."""

    def emit(self, kind, **fields):
        return None

    __call__ = emit

    def bind(self, **_fixed):
        return self

    def close(self):
        pass


def read_events(path, since=0):
    """Events with seq >= since from a ledger (tolerates a partial last line)."""
    out = []
    if not os.path.exists(path):
        return out
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("seq", 0) >= since:
                out.append(ev)
    return out
