"""cps_responder.py — host-side response loop for the cyber-physical scenario.

Tails the DPI sensor's telemetry inside the running lab, folds each finding
into the campaign state (defense_plane.soar.mapping), asks the response policy
for a decision (defense_plane.soar.policy) and applies the countermeasures'
commands on the lab hosts. It runs as a thread next to the episode, because
the attack phase blocks the main thread.

Everything it does goes to ``<out_dir>/response.jsonl`` (host clock ``t``):
    response_up   policy, approval, interval
    tree_state    campaign state, whenever it changes
    decision      Decision.to_dict() + decided_t
    approval      requested / granted for actions that need an operator
    action        one per countermeasure: id, machine, ok, issued_t, done_t,
                  commands [{cmd, rc, out}]
plus ``kg.json`` and ``tree.json`` (knowledge graph, attack-defense tree).

Replay (no lab, no commands — what the policy *would* have done):
    python -m network_scenario.cps_responder --replay output/cps/v2b-manual-hijack \
        --policy solver
"""

import argparse
import json
import logging
import os
import threading
import time

from defense_plane.soar import kg as kgmod
from defense_plane.soar import mapping, policy, trees

log = logging.getLogger("cps_responder")

POLICIES = ("off", "rules", "solver")
SENSOR_TELEMETRY = "/telemetry.jsonl"


def parse_approval(spec):
    """'auto' | 'deny' | 'delay:<s>' -> (mode, delay_s)."""
    spec = (spec or "auto").strip()
    if spec in ("auto", "deny"):
        return spec, 0.0
    if spec.startswith("delay:"):
        try:
            d = float(spec.split(":", 1)[1])
        except ValueError:
            d = -1
        if d >= 0:
            return "delay", d
    raise ValueError(f"approval must be auto, deny or delay:<seconds>, got {spec!r}")


class JsonlRecorder:
    def __init__(self, path):
        self._f = open(path, "w") if path else None
        self._lock = threading.Lock()
        self.rows = []

    def __call__(self, kind, **fields):
        row = {"t": round(fields.pop("t", time.time()), 3), "kind": kind, **fields}
        with self._lock:
            self.rows.append(row)
            if self._f:
                self._f.write(json.dumps(row, default=str) + "\n")
                self._f.flush()
        return row

    def close(self):
        if self._f:
            self._f.close()
            self._f = None


def write_structure(out_dir, g=None):
    """kg.json + tree.json (knowledge graph, attack-defense tree) of the lab
    into ``out_dir`` — what the progress dashboard draws. Returns the graph."""
    g = g if g is not None else kgmod.build_cps_kg()
    os.makedirs(out_dir, exist_ok=True)
    kgmod.save(g, os.path.join(out_dir, "kg.json"))
    with open(os.path.join(out_dir, "tree.json"), "w") as f:
        json.dump(trees.to_json(trees.cps_attack_tree(g), trees.cps_countermeasures(g)), f,
                  indent=1)
    return g


def compact_state(snap):
    """Campaign state in the small form put on the progress ledger."""
    return {"nodes": {n: [v["state"], v["score"]] for n, v in snap["nodes"].items()},
            "active": snap["active_impacts"], "hosts": snap["hosts_implicated"],
            "next": snap["next"], "guest_t": snap.get("t")}


class ResponseEngine:
    """Mapping + policy, independent of how events arrive or actions run."""

    def __init__(self, kind, approval="auto", g=None, record=None, on_state=None):
        self.g = g if g is not None else kgmod.build_cps_kg()
        self.tree = trees.cps_attack_tree(self.g)
        self.cms = {c.id: c for c in trees.cps_countermeasures(self.g)}
        mode, _delay = parse_approval(approval)
        self.policy = policy.make_policy(kind, list(self.cms.values()), self.tree,
                                         approval="deny" if mode == "deny" else "auto")
        self.state = mapping.CampaignState(self.tree, self.g)
        self.record = record or (lambda kind, **f: None)
        self.on_state = on_state or (lambda snap: None)
        self._last_sig = None

    def on_event(self, ev, now=None):
        """Fold one telemetry event; returns a Decision or None."""
        if not self.state.update(ev):
            return None
        snap = self.state.snapshot(ev.get("t"))
        sig = json.dumps({n: v["state"] for n, v in snap["nodes"].items()}, sort_keys=True)
        stamp = now if now is not None else time.time()
        if sig != self._last_sig:
            self._last_sig = sig
            body = dict(snap)
            body["belief_t"] = body.pop("t")
            self.record("tree_state", t=stamp, **body)
            self.on_state(snap)
        d = self.policy.decide(snap, now)
        if d is None:
            return None
        self.policy.mark_applied([a for a in d.actions if a != "notify"])
        body = d.to_dict()
        body.pop("t")
        self.record("decision", t=stamp, decided_t=now, trigger_t=ev.get("t"),
                    trigger_klass=ev.get("klass"), **body)
        return d


class Responder(threading.Thread):
    """Live responder: tails the sensor, decides, applies countermeasures."""

    def __init__(self, manager, machines, kind, out_dir, emit=None, interval=0.5,
                 approval="auto", exec_fn=None, read_fn=None):
        super().__init__(name="cps-responder", daemon=True)
        self.manager, self.machines = manager, machines
        self.interval = float(interval)
        self.approval, self.approval_delay = parse_approval(approval)
        self.emit = emit or (lambda *a, **k: None)
        os.makedirs(out_dir, exist_ok=True)
        self.record = JsonlRecorder(os.path.join(out_dir, "response.jsonl"))
        self.engine = ResponseEngine(
            kind, approval, record=self.record,
            on_state=lambda snap: self.emit("tree_state", **compact_state(snap)))
        write_structure(out_dir, self.engine.g)
        self._exec = exec_fn or self._exec_in_lab
        self._read = read_fn or self._read_sensor
        self._halt = threading.Event()
        self._lines = 0
        self._pending = []            # (due_t, decision, countermeasure id)
        self.record("response_up", policy=kind, approval=approval, interval=self.interval)

    # ── lab I/O ──────────────────────────────────────────────────────────────
    def _exec_in_lab(self, machine, cmd):
        out, err, rc = self.manager.exec_obj(self.machines[machine], ["sh", "-c", cmd],
                                             stream=False)
        text = ((out or b"") + (err or b"")).decode(errors="replace")
        return rc, text

    def _read_sensor(self, start_line):
        out, _err, _rc = self.manager.exec_obj(self.machines["sensor"],
                                               f"tail -n +{start_line} {SENSOR_TELEMETRY}",
                                               stream=False)
        return (out or b"").decode(errors="replace")

    # ── loop ─────────────────────────────────────────────────────────────────
    def stop(self):
        self._halt.set()
        self.join(timeout=max(5.0, 4 * self.interval))
        self.record.close()

    def run(self):
        while not self._halt.is_set():
            try:
                self.poll_once()
            except Exception as e:      # never let monitoring kill the episode
                log.warning("responder poll failed: %s", e)
            self._halt.wait(self.interval)

    def poll_once(self):
        raw = self._read(self._lines + 1)
        lines = raw.split("\n")
        complete = lines[:-1]          # the last element is "" or a partial line
        self._lines += len(complete)
        for line in complete:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            d = self.engine.on_event(ev, now=time.time())
            if d is not None:
                self._dispatch(d)
        self._run_due()

    def _dispatch(self, d):
        self.emit("decision", policy=d.policy, actions=d.actions, guest_t=d.t,
                  rationale=d.rationale, covers=d.covers, needs_approval=d.needs_approval)
        for a in d.actions:
            cm = self.engine.cms[a]
            if cm.requires_approval and self.approval == "delay":
                due = time.time() + self.approval_delay
                self.record("approval", action=a, state="requested", due_t=round(due, 3))
                self._pending.append((due, d, a))
            else:
                self.apply(a, d)

    def _run_due(self):
        now = time.time()
        due = [p for p in self._pending if p[0] <= now]
        self._pending = [p for p in self._pending if p[0] > now]
        for _t, d, a in due:
            self.record("approval", action=a, state="granted")
            self.apply(a, d)

    def apply(self, action_id, decision=None):
        cm = self.engine.cms[action_id]
        issued = time.time()
        results, ok = [], True
        for cmd in cm.apply:
            try:
                rc, out = self._exec(cm.machine, cmd)
            except Exception as e:
                rc, out = -1, str(e)
            results.append({"cmd": cmd, "rc": rc, "out": out[-300:]})
            ok = ok and rc == 0
        done = time.time()
        self.record("action", t=done, id=action_id, machine=cm.machine, ok=ok,
                    issued_t=round(issued, 3), done_t=round(done, 3),
                    decided_t=decision.t if decision else None, commands=results)
        self.emit("action", id=action_id, ok=ok, machine=cm.machine)
        log.info("countermeasure %s%s: %s", action_id,
                 f" on {cm.machine}" if cm.machine else "", "ok" if ok else "FAILED")
        return ok


# ── Offline replay ───────────────────────────────────────────────────────────

def replay_run(run_dir, kind, approval="auto", out_path=None):
    """Run mapping + policy over a finished run's sensor telemetry. Decisions
    are stamped with the triggering finding's time; nothing is executed."""
    tel = None
    for name in ("sensor.telemetry.jsonl", "telemetry.jsonl"):
        p = os.path.join(run_dir, name)
        if os.path.exists(p):
            tel = p
            break
    if tel is None:
        raise FileNotFoundError(f"no sensor telemetry in {run_dir}")
    rec = JsonlRecorder(out_path)
    rec("response_up", policy=kind, approval=approval, replay=True, source=tel)
    eng = ResponseEngine(kind, approval, record=rec)
    decisions = []
    with open(tel) as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            d = eng.on_event(ev, now=ev.get("t"))
            if d is not None:
                decisions.append(d)
                for a in d.actions:
                    if a != "notify":
                        rec("action", t=ev.get("t"), id=a, machine=eng.cms[a].machine,
                            ok=True, planned=True, issued_t=ev.get("t"), done_t=ev.get("t"))
    rec.close()
    return decisions, rec.rows


def main():
    ap = argparse.ArgumentParser(description="CPS response loop: offline replay")
    ap.add_argument("--replay", required=True, help="finished run directory")
    ap.add_argument("--policy", default="rules", choices=POLICIES[1:])
    ap.add_argument("--approval", default="auto")
    ap.add_argument("--out", default=None,
                    help="response log (default <run>/response.<policy>.replay.jsonl)")
    args = ap.parse_args()
    out = args.out or os.path.join(args.replay, f"response.{args.policy}.replay.jsonl")
    decisions, _rows = replay_run(args.replay, args.policy, args.approval, out)
    t0 = None
    gt = os.path.join(args.replay, "ground_truth.jsonl")
    if os.path.exists(gt):
        with open(gt) as f:
            for line in f:
                r = json.loads(line)
                if r.get("kind") == "modbus_write":
                    t0 = r["t"]
                    break
    for d in decisions:
        rel = f"+{d.t - t0:.3f}s from first write" if (t0 and d.t) else f"t={d.t}"
        print(f"[{d.policy}] {rel}: {', '.join(d.actions)}\n    {d.rationale}")
    if not decisions:
        print("no decisions")
    print(f"log: {out}")


if __name__ == "__main__":
    main()
