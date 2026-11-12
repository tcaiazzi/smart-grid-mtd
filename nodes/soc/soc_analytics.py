#!/usr/bin/env python3
"""soc_analytics.py — the SOC's analytics: from the manager's alerts to a response.

Runs next to the Wazuh manager. It builds the knowledge graph and the attack
tree of the lab from the SOC's inventory (soar_kg, soar_trees), follows the
manager's alerts, folds every sensor finding into the campaign state
(soar_mapping), asks the response policy what to do (soar_policy) and requests
the chosen countermeasures from the manager as active responses on the agents
of the hosts concerned. Nothing outside the lab takes part in the loop.

Copied flat onto the SOC node with the soar_* modules and ot_registers.py (see
the scenario's guest_files.py). Stdlib + networkx (through soar_kg).

Three ways to run it, one engine:

    soc_analytics.py --inventory-b64 B64 --policy rules [--approval auto] [--it]
        the service. Writes, in --out-dir (default "/"):
          kg.json, tree.json   the structure it reasons on
          response.jsonl       response_up, tree_state, decision, approval, action
        With --policy off it keeps the campaign state and requests nothing.

    soc_analytics.py --describe --inventory FILE --out-dir DIR [--it]
        kg.json and tree.json only (each tree node says whether it is feasible).

    soc_analytics.py --replay RUN_DIR --inventory FILE --policy solver
        what a policy WOULD have done on a finished run's findings; requests
        nothing.

An action is recorded when its outcome is known: the host that ran it records
one (cps_response.py) and its agent ships it back to the manager, so the
service reads it from the same alert stream as the findings.
"""

import argparse
import base64
import datetime
import json
import os
import signal
import ssl
import threading
import time
import urllib.error
import urllib.request

import soar_kg as kgmod
import soar_mapping as mapping
import soar_policy as policy
import soar_trees as trees

POLICIES = ("off", "rules", "solver")
ALERTS = "/var/ossec/logs/alerts/alerts.json"
API_URL = "https://127.0.0.1:55000"
# Ids of cps_rules.xml: what the manager makes of a finding and of an outcome.
FINDING_RULE, OUTCOME_RULE = "100100", "100120"
RESPONSE_COMMAND = "!cps-response"  # the "!" asks for a script by name, no <command> needed
OUTCOME_TIMEOUT_S = 15.0


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


def write_structure(out_dir, g, it=False):
    """kg.json + tree.json (knowledge graph, attack-defense tree) into ``out_dir``."""
    os.makedirs(out_dir, exist_ok=True)
    kgmod.save(g, os.path.join(out_dir, "kg.json"))
    doc = trees.to_json(trees.cps_attack_tree(g), trees.cps_countermeasures(g, it=it), g)
    with open(os.path.join(out_dir, "tree.json"), "w") as f:
        json.dump(doc, f, indent=1)


class ResponseEngine:
    """Mapping + policy, independent of how events arrive or actions run.
    Policy "off" keeps the campaign state and never decides."""

    def __init__(self, kind, g, approval="auto", record=None, it=False):
        self.g = g
        self.tree = trees.cps_attack_tree(g)
        self.cms = {c.id: c for c in trees.cps_countermeasures(g, it=it)}
        mode, _delay = parse_approval(approval)
        self.policy = (
            None
            if kind == "off"
            else policy.make_policy(
                kind,
                list(self.cms.values()),
                self.tree,
                approval="deny" if mode == "deny" else "auto",
            )
        )
        self.state = mapping.CampaignState(self.tree, g)
        self.record = record or (lambda kind, **f: None)
        self._last_sig = None

    def on_event(self, ev, now=None):
        """Fold one finding; returns a Decision or None."""
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
        if self.policy is None:
            return None
        d = self.policy.decide(snap, now)
        if d is None:
            return None
        self.policy.mark_applied([a for a in d.actions if a != "notify"])
        body = d.to_dict()
        body.pop("t")
        self.record(
            "decision",
            t=stamp,
            decided_t=now,
            trigger_t=ev.get("t"),
            trigger_klass=ev.get("klass"),
            **body,
        )
        return d


# ── the manager: its alerts in, its active responses out ─────────────────────


def alert_time(alert):
    """Epoch seconds of an alert's timestamp ("2026-11-12T11:23:35.123+0000")."""
    try:
        return datetime.datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except (KeyError, ValueError):
        return None


class AlertFollower:
    """The alerts appended to alerts.json since the last poll.

    Only complete lines are consumed: the manager may be mid-write, and a
    half-read alert would be dropped as unparseable instead of read again."""

    def __init__(self, path=ALERTS):
        self.path, self.offset = path, 0

    def poll(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                chunk = f.read()
        except OSError:
            return []  # the manager has not written its first alert yet
        end = chunk.rfind(b"\n") + 1
        self.offset += end
        alerts = []
        for line in chunk[:end].splitlines():
            try:
                alerts.append(json.loads(line))
            except ValueError:
                continue
        return alerts


def shipped_event(alert):
    """The JSON line a lab host shipped, as it wrote it. ``full_log`` carries it
    verbatim; the manager's decoded ``data`` turns numbers and nulls into
    strings, which the mapping would then compare as text."""
    try:
        return json.loads(alert["full_log"])
    except (KeyError, ValueError, TypeError):
        return None


class ApiError(RuntimeError):
    pass


class ManagerApi:
    """The Wazuh manager's REST API, as much of it as a response needs."""

    def __init__(self, url=API_URL, user="wazuh", password="wazuh", timeout=5.0, http=None):
        self.url, self.timeout = url, timeout
        self._basic = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._http = http or self._urlopen
        self._token = None

    def _urlopen(self, method, path, headers, body=None):
        """-> (status, text). The manager's certificate is self-signed."""
        req = urllib.request.Request(self.url + path, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=ssl._create_unverified_context()
            ) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except (urllib.error.URLError, OSError) as e:
            raise ApiError(f"manager API unreachable: {e}") from e

    def login(self):
        status, text = self._http(
            "POST",
            "/security/user/authenticate?raw=true",
            {"Authorization": f"Basic {self._basic}"},
        )
        if status != 200 or not text.strip():
            raise ApiError(f"manager API refused the login ({status}): {text[:120]}")
        self._token = text.strip()

    def _call(self, method, path, body=None):
        if self._token is None:
            self.login()
        for attempt in (1, 2):
            headers = {"Authorization": f"Bearer {self._token}"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            status, text = self._http(method, path, headers, body)
            if status == 401 and attempt == 1:  # the token expired: log in again, once
                self.login()
                continue
            try:
                reply = json.loads(text)
            except ValueError:
                reply = {}
            if status != 200 or reply.get("error") != 0:
                raise ApiError(f"{method} {path.split('?')[0]} -> {status}: {text[:160]}")
            return reply

    def agents(self):
        """{agent name: id}. A lab host's agent is named after the host."""
        items = self._call("GET", "/agents?limit=500")["data"]["affected_items"]
        return {a["name"]: a["id"] for a in items}

    def active_response(self, agent_id, arguments):
        body = json.dumps({"command": RESPONSE_COMMAND, "arguments": list(arguments)}).encode()
        reply = self._call("PUT", f"/active-response?agents_list={agent_id}", body)
        if (reply.get("data") or {}).get("total_affected_items") != 1:
            raise ApiError(f"the manager did not dispatch to agent {agent_id}: {reply}")


class Service:
    """The loop: alerts in, decisions, requests out, outcomes back in."""

    def __init__(
        self,
        engine,
        follower,
        api,
        record,
        approval="auto",
        clock=time.time,
        outcome_timeout=OUTCOME_TIMEOUT_S,
    ):
        self.engine, self.follower, self.api, self.record = engine, follower, api, record
        self.approval, self.approval_delay = parse_approval(approval)
        self.clock, self.outcome_timeout = clock, float(outcome_timeout)
        self._agents = {}
        self._awaiting_approval = []  # (due_t, action id, context)
        self._requested = {}  # request id -> context of an action awaiting its outcome

    def step(self):
        for alert in self.follower.poll():
            rule = str((alert.get("rule") or {}).get("id"))
            if rule not in (FINDING_RULE, OUTCOME_RULE):
                continue
            ev = shipped_event(alert)
            if ev is None:
                continue
            if rule == FINDING_RULE:
                self.on_finding(ev, alert_time(alert))
            else:
                self.on_outcome(ev)
        self._grant_due()
        self._expire()

    def on_finding(self, ev, alert_t=None):
        d = self.engine.on_event(ev, now=self.clock())
        if d is None:
            return
        for action in d.actions:
            ctx = {"decided_t": d.t, "alert_t": alert_t}
            cm = self.engine.cms[action]
            if cm.requires_approval and self.approval == "delay":
                due = self.clock() + self.approval_delay
                self.record("approval", action=action, state="requested", due_t=round(due, 3))
                self._awaiting_approval.append((due, action, ctx))
            else:
                self.request(action, ctx)

    def _grant_due(self):
        now = self.clock()
        due = [p for p in self._awaiting_approval if p[0] <= now]
        self._awaiting_approval = [p for p in self._awaiting_approval if p[0] > now]
        for _t, action, ctx in due:
            self.record("approval", action=action, state="granted")
            self.request(action, ctx)

    def _agent_of(self, machine):
        if machine not in self._agents:
            self._agents = self.api.agents()  # an agent may have registered since
        return self._agents.get(machine)

    def request(self, action, ctx):
        """Ask the manager for ``action`` on its host's agent. The action is
        recorded later, by its outcome; a request that cannot be made is
        recorded now, as failed."""
        cm = self.engine.cms[action]
        now = self.clock()
        if not cm.machine:  # notify: nothing to run anywhere
            self._action(action, cm, True, [], ctx, requested_t=now, done_t=now)
            return
        request = os.urandom(8).hex()
        try:
            agent = self._agent_of(cm.machine)
            if agent is None:
                raise ApiError(f"no agent named {cm.machine!r} is registered with the manager")
            self.api.active_response(agent, ["apply", action, request])
        except ApiError as e:
            failed = [{"cmd": f"active-response {action}", "rc": -1, "out": str(e)[-300:]}]
            self._action(action, cm, False, failed, ctx, requested_t=now, done_t=self.clock())
            return
        self._requested[request] = {"action": action, "requested_t": now, **ctx}

    def on_outcome(self, rec):
        """A host's record of a response it ran (cps_response.py), shipped back."""
        pending = self._requested.pop(rec.get("request"), None)
        if pending is None:
            return  # not ours: another requester's, or already expired
        action = pending["action"]
        commands = rec.get("commands") or []
        if rec.get("refused"):
            commands = [{"cmd": f"active-response {action}", "rc": -1, "out": rec["refused"]}]
        self._action(
            action,
            self.engine.cms[action],
            bool(rec.get("ok")),
            commands,
            pending,
            requested_t=pending["requested_t"],
            done_t=rec.get("done_t") or self.clock(),
            node_started_t=rec.get("started_t"),
            node_done_t=rec.get("done_t"),
        )

    def _expire(self):
        now = self.clock()
        for request, p in list(self._requested.items()):
            if now - p["requested_t"] > self.outcome_timeout:
                del self._requested[request]
                action = p["action"]
                out = f"requested, but no outcome came back in {self.outcome_timeout:.0f}s"
                self._action(
                    action,
                    self.engine.cms[action],
                    False,
                    [{"cmd": f"active-response {action}", "rc": -1, "out": out}],
                    p,
                    requested_t=p["requested_t"],
                    done_t=now,
                )

    def _action(self, action, cm, ok, commands, ctx, requested_t, done_t, **node_times):
        self.record(
            "action",
            t=done_t,
            id=action,
            machine=cm.machine,
            ok=ok,
            issued_t=round(requested_t, 3),
            done_t=round(done_t, 3),
            decided_t=ctx.get("decided_t"),
            alert_t=ctx.get("alert_t"),
            commands=commands,
            **node_times,
        )


# ── offline: what a policy would have done ───────────────────────────────────


def _read_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _first(run_dir, *names):
    for name in names:
        p = os.path.join(run_dir, name)
        if os.path.exists(p):
            return p
    return None


def replay_run(run_dir, g, kind, approval="auto", out_path=None):
    """Mapping + policy over a finished run's sensor telemetry. Decisions are
    stamped with the triggering finding's time; nothing is requested."""
    tel = _first(run_dir, "sensor.telemetry.jsonl", "telemetry.jsonl")
    if tel is None:
        raise FileNotFoundError(f"no sensor telemetry in {run_dir}")
    # With the IT sensor, its findings join the OT ones in time order.
    it_tel = _first(run_dir, "hmi.it_telemetry.jsonl", "it_telemetry.jsonl")
    rec = JsonlRecorder(out_path)
    rec("response_up", policy=kind, approval=approval, replay=True, source=tel, it=bool(it_tel))
    eng = ResponseEngine(kind, g, approval, record=rec, it=bool(it_tel))
    events = _read_jsonl(tel) + (_read_jsonl(it_tel) if it_tel else [])
    events.sort(key=lambda e: e.get("t") or 0)
    decisions = []
    for ev in events:
        d = eng.on_event(ev, now=ev.get("t"))
        if d is None:
            continue
        decisions.append(d)
        for a in d.actions:
            if a != "notify":
                rec(
                    "action",
                    t=ev.get("t"),
                    id=a,
                    machine=eng.cms[a].machine,
                    ok=True,
                    planned=True,
                    issued_t=ev.get("t"),
                    done_t=ev.get("t"),
                )
    rec.close()
    return decisions, rec.rows


def print_replay(run_dir, decisions, out_path):
    t0 = None
    gt = os.path.join(run_dir, "ground_truth.jsonl")
    if os.path.exists(gt):
        t0 = next((r["t"] for r in _read_jsonl(gt) if r.get("kind") == "modbus_write"), None)
    for d in decisions:
        rel = f"+{d.t - t0:.3f}s from first write" if (t0 and d.t) else f"t={d.t}"
        print(f"[{d.policy}] {rel}: {', '.join(d.actions)}\n    {d.rationale}")
    if not decisions:
        print("no decisions")
    print(f"log: {out_path}")


# ── entry point ──────────────────────────────────────────────────────────────


def load_inventory(args):
    if args.inventory_b64:
        return json.loads(base64.b64decode(args.inventory_b64))
    if args.inventory:
        with open(args.inventory) as f:
            return json.load(f)
    raise SystemExit("an inventory is required: --inventory FILE or --inventory-b64 B64")


def serve(args, g):
    os.makedirs(args.out_dir, exist_ok=True)
    write_structure(args.out_dir, g, it=args.it)
    record = JsonlRecorder(os.path.join(args.out_dir, "response.jsonl"))
    record(
        "response_up",
        policy=args.policy,
        approval=args.approval,
        interval=args.interval,
        it=args.it,
    )
    engine = ResponseEngine(args.policy, g, args.approval, record=record, it=args.it)
    service = Service(engine, AlertFollower(args.alerts), ManagerApi(), record, args.approval)
    halt = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: halt.set())
    while not halt.is_set():
        try:
            service.step()
        except Exception as e:  # one bad alert must not end the SOC's watch
            print(f"analytics step failed: {e}", flush=True)
        halt.wait(args.interval)
    record.close()


def main():
    ap = argparse.ArgumentParser(description="SOC analytics: alerts -> attack tree -> response")
    ap.add_argument("--inventory", default=None, help="the SOC's inventory, a JSON file")
    ap.add_argument("--inventory-b64", default=None, help="the same, base64 on the command line")
    ap.add_argument("--policy", default="off", choices=POLICIES)
    ap.add_argument("--approval", default="auto", help="auto | deny | delay:<seconds>")
    ap.add_argument("--it", action="store_true", help="IT findings and countermeasures too")
    ap.add_argument("--interval", type=float, default=0.5, help="seconds between alert polls")
    ap.add_argument("--alerts", default=ALERTS, help="the manager's alerts.json")
    ap.add_argument("--out-dir", default="/")
    ap.add_argument("--describe", action="store_true", help="write kg.json and tree.json, exit")
    ap.add_argument("--replay", default=None, metavar="RUN_DIR", help="replay a finished run")
    ap.add_argument("--out", default=None, help="replay log")
    args = ap.parse_args()
    parse_approval(args.approval)  # a bad value fails here, not at the first decision
    g = kgmod.build_kg(load_inventory(args))
    if args.describe:
        write_structure(args.out_dir, g, it=args.it)
    elif args.replay:
        if args.policy == "off":
            raise SystemExit("--replay needs a policy that decides: rules or solver")
        out = args.out or os.path.join(args.replay, f"response.{args.policy}.replay.jsonl")
        decisions, _rows = replay_run(args.replay, g, args.policy, args.approval, out)
        print_replay(args.replay, decisions, out)
    else:
        serve(args, g)


if __name__ == "__main__":
    main()
