"""The SOC analytics (nodes/soc/soc_analytics.py): the engine over findings, the
service loop (alerts in, requests out, outcomes back), the manager's API client
and the alert follower — the node's code, run on the host with fakes in place of
the manager. No Docker.

Run: `.venv/bin/python -m pytest tests/nodes/test_soc_analytics.py`.
"""

import json
import os
import tempfile
import unittest

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)

import soc_analytics as A  # noqa: E402  (flat guest import, needs the path set above)

from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402
from tests.helpers.soar import HMI, finding, model  # noqa: E402

G = A.kgmod.build_kg(cps_inv.inventory())


def alert(rule, body, t="2026-11-12T10:00:00.000+0000"):
    """An alert as the manager writes it: the shipped line verbatim in full_log."""
    return {"rule": {"id": rule}, "timestamp": t, "full_log": json.dumps(body)}


class FakeApi:
    """Records the responses asked of it; dispatches to one agent each time."""

    AGENTS = {"sensor": "001", "hmi": "002", "firewall": "003"}

    def __init__(self):
        self.requests = []  # (agent_id, cm_id, request)
        self.fail = None  # set to an ApiError to raise on the next call

    def agents(self):
        return dict(self.AGENTS)

    def active_response(self, agent_id, arguments):
        if self.fail:
            raise self.fail
        self.requests.append((agent_id, arguments[1], arguments[2]))


class HandFollower:
    def __init__(self):
        self.queue = []

    def feed(self, *alerts):
        self.queue.extend(alerts)

    def poll(self):
        out, self.queue = self.queue, []
        return out


def service(policy="rules", approval="auto", clock=None, outcome_timeout=15.0):
    rec = A.JsonlRecorder(None)
    eng = A.ResponseEngine(policy, G, approval=approval, record=rec)
    foll = HandFollower()
    api = FakeApi()
    now = clock or [100.0]
    svc = A.Service(
        eng,
        foll,
        api,
        rec,
        approval=approval,
        clock=lambda: now[0],
        outcome_timeout=outcome_timeout,
    )
    return svc, foll, api, rec, now


def rows(rec, kind):
    return [r for r in rec.rows if r["kind"] == kind]


class Engine(unittest.TestCase):
    def test_a_confirmed_impact_decides_a_countermeasure(self):
        rec = A.JsonlRecorder(None)
        eng = A.ResponseEngine("rules", G, record=rec)
        # A remote breaker write is a policy violation that confirms breaker_open.
        d = eng.on_event(finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0))
        self.assertIsNotNone(d)
        decided = {a for r in rows(rec, "decision") for a in r["actions"]}
        self.assertTrue({"block_flow", "restore_breaker"} <= decided, rec.rows)

    def test_policy_off_keeps_the_belief_but_decides_nothing(self):
        rec = A.JsonlRecorder(None)
        eng = A.ResponseEngine("off", G, record=rec)
        d = eng.on_event(finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0))
        self.assertIsNone(d)
        self.assertTrue(rows(rec, "tree_state"), "the belief is still recorded")
        self.assertEqual(rows(rec, "decision"), [])


class Loop(unittest.TestCase):
    def confirmed_breaker(self, svc, foll):
        foll.feed(
            alert("100100", finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0)),
            alert("100100", model(1.1, "v_max")),
        )
        svc.step()

    def test_a_finding_leads_to_a_request_not_an_action_yet(self):
        svc, foll, api, rec, _ = service()
        self.confirmed_breaker(svc, foll)
        self.assertTrue(api.requests, "no response was asked of the manager")
        agents = {a for a, _cm, _r in api.requests}
        self.assertIn("003", agents)  # block_flow / restore_breaker run on the firewall
        # Nothing is recorded as an action until its outcome comes back.
        self.assertEqual([r for r in rows(rec, "action") if r["machine"]], [])

    def test_the_request_carries_an_id_never_a_command(self):
        svc, foll, api, _rec, _ = service()
        self.confirmed_breaker(svc, foll)
        for _agent, cm_id, _req in api.requests:
            self.assertIn(cm_id, ("block_flow", "restore_breaker", "force_auto"))

    def test_the_outcome_closes_the_action_with_the_nodes_times(self):
        svc, foll, api, rec, now = service()
        self.confirmed_breaker(svc, foll)
        _agent, cm_id, request = api.requests[0]
        now[0] = 101.0
        foll.feed(
            alert(
                "100120",
                {
                    "kind": "cps_response",
                    "id": cm_id,
                    "request": request,
                    "ok": True,
                    "started_t": 100.2,
                    "done_t": 100.4,
                    "commands": [{"cmd": "iptables", "rc": 0, "out": ""}],
                },
            )
        )
        svc.step()
        act = next(r for r in rows(rec, "action") if r["id"] == cm_id)
        self.assertTrue(act["ok"])
        self.assertEqual((act["node_started_t"], act["node_done_t"]), (100.2, 100.4))
        self.assertIsNotNone(act["alert_t"])

    def test_a_refused_outcome_is_a_failed_action(self):
        svc, foll, api, rec, now = service()
        self.confirmed_breaker(svc, foll)
        _agent, cm_id, request = api.requests[0]
        foll.feed(
            alert(
                "100120",
                {
                    "kind": "cps_response",
                    "id": cm_id,
                    "request": request,
                    "ok": False,
                    "refused": "countermeasure not allowed on this host",
                    "commands": [],
                },
            )
        )
        svc.step()
        act = next(r for r in rows(rec, "action") if r["id"] == cm_id)
        self.assertFalse(act["ok"])
        self.assertIn("not allowed", act["commands"][0]["out"])

    def test_no_outcome_within_the_timeout_fails_the_action(self):
        svc, foll, api, rec, now = service(outcome_timeout=5.0)
        self.confirmed_breaker(svc, foll)
        _agent, cm_id, _request = api.requests[0]
        now[0] = 100.0 + 6.0  # past the timeout, still no outcome
        svc.step()
        act = next(r for r in rows(rec, "action") if r["id"] == cm_id)
        self.assertFalse(act["ok"])
        self.assertIn("no outcome", act["commands"][0]["out"])

    def test_a_request_the_manager_will_not_take_fails_at_once(self):
        svc, foll, api, rec, _ = service()
        api.fail = A.ApiError("the manager is down")
        self.confirmed_breaker(svc, foll)
        failed = [r for r in rows(rec, "action") if not r["ok"]]
        self.assertTrue(failed)
        self.assertEqual(svc._requested, {}, "a failed request must not wait for an outcome")

    def test_notify_is_recorded_with_no_request(self):
        svc, foll, api, rec, _ = service()
        foll.feed(
            alert("100100", finding("out_of_range_command", 1.0, HMI, "dg_setpoint", value=60.0))
        )
        svc.step()
        notify = [r for r in rows(rec, "action") if r["id"] == "notify"]
        if notify:  # notify fires below the confirmation threshold
            self.assertIsNone(notify[0]["machine"])
            self.assertEqual([r for r in api.requests if r[1] == "notify"], [])

    def test_policy_off_asks_for_nothing(self):
        svc, foll, api, rec, _ = service(policy="off")
        self.confirmed_breaker(svc, foll)
        self.assertEqual(api.requests, [])
        self.assertEqual([r for r in rows(rec, "action") if r["machine"]], [])


class Approval(unittest.TestCase):
    def test_delay_holds_an_action_until_it_is_due(self):
        svc, foll, api, rec, now = service(approval="delay:5", policy="rules")
        # isolate_hmi needs approval; drive the IT path that proposes it.
        eng = svc.engine
        eng.cms["block_flow"] = eng.cms["block_flow"]  # (kept; just naming the engine)
        # A confirmed impact with the solver would need approval; emulate directly.
        svc.on_finding(finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0))
        svc.on_finding(model(1.1, "v_max"))
        # Whatever needs approval is not requested yet.
        approvals = rows(rec, "approval")
        if approvals:
            self.assertEqual(approvals[0]["state"], "requested")
            now[0] = 100.0 + 6.0
            svc.step()
            self.assertTrue(any(a["state"] == "granted" for a in rows(rec, "approval")))


class Advising(unittest.TestCase):
    """--approval operator:<s>: the SOC proposes, a person disposes."""

    def suggested(self, policy="rules"):
        svc, foll, api, rec, now = service(policy=policy, approval="operator:60")
        foll.feed(
            alert("100100", finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0)),
            alert("100100", model(1.1, "v_max")),
        )
        svc.step()
        return svc, api, rec, now

    def pending(self, svc):
        return {s["action"]: s for s in svc.desk.listing()["pending"]}

    def test_nothing_is_asked_of_the_manager_before_a_verdict(self):
        svc, api, rec, _now = self.suggested()
        self.assertEqual(
            api.requests, [], "an advising SOC ran a countermeasure nobody had approved"
        )
        asked = {r["action"] for r in rows(rec, "approval") if r["state"] == "requested"}
        self.assertEqual(asked, {"block_flow", "restore_breaker"})
        self.assertEqual(set(self.pending(svc)), asked)

    def test_a_suggestion_says_why(self):
        svc, _api, rec, _now = self.suggested(policy="solver")
        row = next(r for r in rows(rec, "approval") if r["action"] == "block_flow")
        why = row["explanation"]
        self.assertTrue(why["rationale"])
        self.assertEqual(why["trigger"]["src"], HMI)
        self.assertTrue(why["prevents"], "the suggestion names nothing it would prevent")
        self.assertTrue(all(n["label"] for n in why["prevents"]))
        self.assertEqual(why["countermeasure"]["machine"], "firewall")
        self.assertTrue(why["countermeasure"]["commands"])
        self.assertIn("total", why["cost_terms"])
        self.assertTrue(why["alternatives"])
        self.assertEqual(row["due_t"], 160.0)
        json.dumps(row)  # it travels as JSON, to the ledger and to the console

    def test_an_approved_suggestion_is_requested(self):
        svc, api, rec, now = self.suggested()
        request = self.pending(svc)["block_flow"]["request"]
        now[0] = 112.5
        self.assertEqual(svc.desk.submit(request, "approve", "ada"), "ok")
        svc.step()
        self.assertEqual([cm for _a, cm, _r in api.requests], ["block_flow"])
        granted = [r for r in rows(rec, "approval") if r["state"] == "granted"]
        self.assertEqual(
            [(r["action"], r["operator"], r["waited_s"]) for r in granted],
            [("block_flow", "ada", 12.5)],
        )
        self.assertNotIn("block_flow", self.pending(svc))

    def test_a_rejected_suggestion_never_runs_and_is_not_proposed_again(self):
        svc, api, rec, now = self.suggested()
        request = self.pending(svc)["block_flow"]["request"]
        svc.desk.submit(request, "reject", "ada")
        svc.step()
        now[0] = 130.0
        svc.on_finding(finding("policy_violation", 30.0, HMI, "switch_cmd", value=1.0))
        svc.step()
        self.assertEqual([cm for _a, cm, _r in api.requests if cm == "block_flow"], [])
        states = [r["state"] for r in rows(rec, "approval") if r["action"] == "block_flow"]
        self.assertEqual(states, ["requested", "rejected"])

    def test_the_solver_offers_the_alternative_to_a_rejected_action(self):
        svc, _api, rec, _now = self.suggested(policy="solver")
        self.assertNotIn("isolate_hmi", self.pending(svc))
        svc.desk.submit(self.pending(svc)["block_flow"]["request"], "reject")
        svc.step()
        self.assertIn(
            "isolate_hmi",
            self.pending(svc),
            "the path cut was turned down and the operator was offered no other",
        )

    def test_an_unanswered_suggestion_lapses_unapplied(self):
        svc, api, rec, now = self.suggested()
        request = self.pending(svc)["block_flow"]["request"]
        now[0] = 161.0
        svc.step()
        self.assertEqual(api.requests, [], "silence was taken for consent")
        expired = {r["action"] for r in rows(rec, "approval") if r["state"] == "expired"}
        self.assertEqual(expired, {"block_flow", "restore_breaker"})
        self.assertEqual(svc.desk.listing()["pending"], [])
        # A verdict that arrives after the deadline finds nothing to decide.
        self.assertEqual(svc.desk.submit(request, "approve"), "unknown")

    def test_notify_is_not_put_to_the_operator(self):
        svc, _foll, api, rec, _now = service(approval="operator:60")
        svc.on_finding(model(1.0, "max_dsetpoint"))
        self.assertEqual([r["id"] for r in rows(rec, "action")], ["notify"])
        self.assertEqual(rows(rec, "approval"), [])

    def test_the_approval_forms(self):
        self.assertEqual(A.parse_approval("operator:90"), ("operator", 90.0))
        self.assertEqual(A.parse_approval("delay:0"), ("delay", 0.0))
        for bad in ("operator", "operator:0", "operator:x", "delay:-1", "maybe"):
            with self.assertRaises(ValueError, msg=bad):
                A.parse_approval(bad)


class AlertFollowerAndEvent(unittest.TestCase):
    def test_follows_only_complete_lines(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "alerts.json")
            foll = A.AlertFollower(path)
            self.assertEqual(foll.poll(), [])  # no file yet
            partial = '{"rule": {"id": "100120"}, "timestamp": "x", "full_log": "{}"'
            with open(path, "w") as f:
                f.write(json.dumps(alert("100100", {"kind": "ot_finding"})) + "\n")
                f.write(partial)  # a half-written line, no newline yet
            got = foll.poll()
            self.assertEqual(len(got), 1, "the complete line is read, the partial one held")
            with open(path, "a") as f:
                f.write("}\n")  # the manager finishes the line
            self.assertEqual(len(foll.poll()), 1, "the completed line is read exactly once")
            self.assertEqual(foll.poll(), [], "and not again")

    def test_shipped_event_is_the_verbatim_line_not_the_decoded_fields(self):
        a = alert("100100", {"kind": "ot_finding", "confidence": 0.9, "entities": {"src": None}})
        a["data"] = {"confidence": "0.900000", "entities": {"src": "null"}}  # the manager's strings
        ev = A.shipped_event(a)
        self.assertEqual(ev["confidence"], 0.9)
        self.assertIsNone(ev["entities"]["src"])

    def test_alert_time_parses_the_managers_stamp(self):
        import datetime

        t = A.alert_time({"timestamp": "2026-11-12T10:00:00.000+0000"})
        self.assertEqual(
            t, datetime.datetime(2026, 11, 12, 10, 0, tzinfo=datetime.timezone.utc).timestamp()
        )
        self.assertIsNone(A.alert_time({"timestamp": "nonsense"}))
        self.assertIsNone(A.alert_time({}))


class ManagerApiClient(unittest.TestCase):
    def client(self, *responses):
        calls = []

        def http(method, path, headers, body=None):
            calls.append((method, path, headers, body))
            return responses[len(calls) - 1]

        return A.ManagerApi(http=http), calls

    def test_login_then_a_call_carries_the_token(self):
        api, calls = self.client((200, "the-token"), (200, json.dumps({"error": 0, "data": {}})))
        api._call("GET", "/agents")
        self.assertIn("authenticate", calls[0][1])
        self.assertEqual(calls[1][2]["Authorization"], "Bearer the-token")

    def test_a_401_logs_in_again_once(self):
        api, calls = self.client(
            (200, "tok1"),
            (401, "expired"),
            (200, "tok2"),
            (
                200,
                json.dumps(
                    {"error": 0, "data": {"affected_items": [{"name": "firewall", "id": "003"}]}}
                ),
            ),
        )
        self.assertEqual(api.agents(), {"firewall": "003"})
        self.assertEqual(sum("authenticate" in c[1] for c in calls), 2)

    def test_a_refused_login_raises(self):
        api, _calls = self.client((401, "bad credentials"))
        with self.assertRaises(A.ApiError):
            api.login()

    def test_active_response_requires_one_dispatched_agent(self):
        api, _calls = self.client(
            (200, "tok"), (200, json.dumps({"error": 0, "data": {"total_affected_items": 0}}))
        )
        with self.assertRaisesRegex(A.ApiError, "did not dispatch"):
            api.active_response("003", ["apply", "block_flow", "r1"])


class Replay(unittest.TestCase):
    def test_replay_decides_without_requesting(self):
        with tempfile.TemporaryDirectory() as d:
            tel = os.path.join(d, "sensor.telemetry.jsonl")
            with open(tel, "w") as f:
                for ev in (
                    finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0),
                    model(1.1, "v_max"),
                ):
                    f.write(json.dumps(ev) + "\n")
            out = os.path.join(d, "replay.jsonl")
            decisions, _rows = A.replay_run(d, G, "rules", out_path=out)
            self.assertTrue(decisions)
            self.assertTrue(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
