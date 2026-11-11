"""streams.py — the three event streams of a run.

Every run of every scenario leaves the same three JSONL streams. They are kept
apart on purpose: what the defenders could observe never mixes with what
really happened, so a detector or a response policy cannot be scored against
information it could not have had.

  ground_truth.jsonl   WHAT REALLY HAPPENED. Written host-side only (attack
                       drivers, fault injection, the scenario itself); never
                       copied into a container, never readable by a defender.
                       Line: {"t", "kind", ...}. Scorers and dataset builders
                       read it.

  telemetry.jsonl      WHAT THE DEFENDERS OBSERVED AND DID. Written inside the
                       containers by defense components (MTD coordinator, OT/IT
                       sensors) through cyberrange/planes/defense/agents/mtd_telemetry.py.
                       Line: {"i", "t", "kind", ...}. Downloaded per component
                       (e.g. sensor.telemetry.jsonl, hmi.it_telemetry.jsonl).

  progress.jsonl       THE RUN AS IT HAPPENS. The host ledger
                       (cyberrange/core/progress.py): lifecycle (run_start, phase,
                       run_end), campaign bookkeeping and a live mirror of the
                       telemetry. Line: {"seq", "t", "kind", ["run_id"], ...}.
                       The dashboard reads only this.

Kinds common to every scenario (scenario-specific kinds are documented with
the scenario):

  progress   run_start{scenario, mode, seed, phases[{name, planned_s, timed}],
                       planned_s, ...}   phase{name, state=start|end, ok, duration_s}
             run_end{status=ok|failed|interrupted, duration_s, error, rc}
             campaign_start / unit_start / step_start / step_end / step_skipped /
             step_retry / step_failed / run_metrics / aggregate / campaign_end
  ground     run_meta{scenario, seed, ...}   run_end
"""

import json
import threading
import time

GROUND_TRUTH = "ground_truth.jsonl"
PROGRESS = "progress.jsonl"
TELEMETRY = "telemetry.jsonl"


class GroundTruth:
    """Append-only ground_truth.jsonl writer (thread-safe). An explicit ``t=``
    overrides the host clock (e.g. the send time an attack agent reported)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._f = open(path, "w", buffering=1)

    def record(self, kind: str, **fields) -> None:
        line = json.dumps({"t": round(time.time(), 3), "kind": kind, **fields}, default=str)
        with self._lock:
            if not self._f.closed:
                self._f.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._f.close()


def read_jsonl(path):
    """Every parseable line of a JSONL file ([] if it is missing)."""
    out = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return out
