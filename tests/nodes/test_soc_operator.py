"""The SOC's operator API (nodes/soc/soc_operator.py): the desk that holds the
suggestions and the HTTP interface a console answers them through — a real
server on a free port, the node's code run on the host. No Docker.

Run: `.venv/bin/python -m pytest tests/nodes/test_soc_operator.py`.
"""

import json
import unittest
import urllib.error
import urllib.request

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC)

import soc_operator as O  # noqa: E402  (flat guest import, needs the path set above)

TOKEN = "s3cret"
STATE = {"mode": "advise", "countermeasures": [{"id": "block_flow"}, {"id": "isolate_hmi"}]}


class Api(unittest.TestCase):
    def setUp(self):
        self.desk = O.ApprovalDesk(clock=lambda: 100.0)
        self.api = O.OperatorApi(
            self.desk, TOKEN, host="127.0.0.1", terminal="http://127.0.0.1:1/"
        ).start()
        self.addCleanup(self.api.shutdown)
        self.desk.publish(STATE)
        self.desk.open("abc", {"action": "block_flow", "due_t": 160.0, "explanation": {}})

    def call(self, method, path, body=None, token=TOKEN, raw=False):
        """-> (status, parsed body or None, headers)."""
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.api.port}{path}", data=data, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                status, text, got = r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            status, text, got = e.code, e.read(), e.headers
        return status, (text if raw else json.loads(text) if text else None), got

    def test_the_pending_suggestions_are_listed(self):
        status, doc, _h = self.call("GET", "/approvals")
        self.assertEqual(status, 200)
        self.assertEqual(
            [(s["request"], s["state"]) for s in doc["pending"]], [("abc", "requested")]
        )
        self.assertEqual(doc["closed"], [])

    def test_no_token_no_answer(self):
        for token in (None, "wrong"):
            self.assertEqual(self.call("GET", "/approvals", token=token)[0], 401)
            status, _doc, _h = self.call(
                "POST", "/approvals/abc", {"verdict": "approve"}, token=token
            )
            self.assertEqual(status, 401)
        self.assertEqual(
            self.desk.take(), [], "a verdict was accepted from a caller without the token"
        )

    def test_an_api_without_a_token_is_refused(self):
        for token in (None, ""):
            with self.assertRaises(ValueError):
                O.OperatorApi(self.desk, token, host="127.0.0.1")

    def test_a_verdict_is_queued_once(self):
        status, doc, _h = self.call(
            "POST", "/approvals/abc", {"verdict": "approve", "operator": "ada"}
        )
        self.assertEqual((status, doc), (200, {"request": "abc", "verdict": "approve"}))
        # A second console answering the same suggestion is told so, and ignored.
        self.assertEqual(self.call("POST", "/approvals/abc", {"verdict": "reject"})[0], 409)
        self.assertEqual(
            self.desk.take(),
            [{"request": "abc", "verdict": "approve", "operator": "ada", "t": 100.0}],
        )
        self.assertEqual(self.desk.take(), [])
        self.assertEqual(self.call("GET", "/approvals")[1]["pending"][0]["state"], "decided")

    def test_what_is_not_a_verdict_is_refused(self):
        self.assertEqual(self.call("POST", "/approvals/nope", {"verdict": "approve"})[0], 404)
        self.assertEqual(self.call("POST", "/approvals/abc", {"verdict": "maybe"})[0], 400)
        self.assertEqual(self.call("POST", "/approvals/abc", b"not json")[0], 400)
        self.assertEqual(self.call("POST", "/approvals/abc", b"[1]")[0], 400)
        self.assertEqual(self.call("POST", "/approvals/abc", b"x" * (O.MAX_BODY + 1))[0], 400)
        self.assertEqual(self.call("POST", "/elsewhere/abc", {"verdict": "approve"})[0], 404)
        self.assertEqual(self.call("GET", "/nowhere")[0], 404)
        self.assertEqual(self.desk.take(), [])

    def test_the_page_is_served_but_holds_nothing(self):
        status, page, _h = self.call("GET", "/", token=None, raw=True)
        self.assertEqual(status, 200)
        self.assertIn(b"SOC console", page)
        self.assertNotIn(TOKEN.encode(), page, "the console page gives the token away")
        self.assertEqual(self.call("GET", "/state", token=None)[0], 401)

    def test_the_state_is_the_socs_view_with_its_suggestions(self):
        status, doc, _h = self.call("GET", "/state")
        self.assertEqual(status, 200)
        self.assertEqual(doc["mode"], "advise")
        self.assertEqual([s["request"] for s in doc["approvals"]["pending"]], ["abc"])
        self.assertEqual(doc["terminal"], "http://127.0.0.1:1/")

    def test_a_countermeasure_is_ordered_by_hand(self):
        body = {"op": "revert", "operator": "ada"}
        self.assertEqual(self.call("POST", "/countermeasures/block_flow", body)[0], 200)
        self.assertEqual(
            self.desk.take_orders(),
            [
                {
                    "kind": "countermeasure",
                    "operator": "ada",
                    "t": 100.0,
                    "id": "block_flow",
                    "op": "revert",
                }
            ],
        )
        self.assertEqual(self.call("POST", "/countermeasures/rm_rf", {"op": "apply"})[0], 404)
        self.assertEqual(self.call("POST", "/countermeasures/block_flow", {"op": "run"})[0], 400)
        self.assertEqual(
            self.call("POST", "/countermeasures/block_flow", {"op": "apply"}, token="x")[0], 401
        )
        self.assertEqual(
            self.desk.take_orders(), [], "an order was taken that should have been refused"
        )

    def test_the_mode_is_ordered(self):
        self.assertEqual(self.call("POST", "/mode", {"mode": "auto"})[0], 200)
        self.assertEqual(self.call("POST", "/mode", {"mode": "off"})[0], 400)
        self.assertEqual(
            [(o["kind"], o["mode"]) for o in self.desk.take_orders()], [("mode", "auto")]
        )


class Desk(unittest.TestCase):
    def test_a_closed_suggestion_keeps_its_outcome(self):
        desk = O.ApprovalDesk(clock=lambda: 7.0)
        desk.open("r1", {"action": "isolate_hmi"})
        desk.submit("r1", "reject", "ada")
        desk.close("r1", "rejected", operator="ada")
        doc = desk.listing()
        self.assertEqual(doc["pending"], [])
        self.assertEqual(
            [(c["action"], c["state"], c["operator"]) for c in doc["closed"]],
            [("isolate_hmi", "rejected", "ada")],
        )
        self.assertEqual(desk.submit("r1", "approve"), "unknown")

    def test_the_history_is_bounded(self):
        desk = O.ApprovalDesk()
        for i in range(O.CLOSED_KEPT + 5):
            desk.open(str(i), {"action": "block_flow"})
            desk.close(str(i), "expired")
        self.assertEqual(len(desk.listing()["closed"]), O.CLOSED_KEPT)


if __name__ == "__main__":
    unittest.main()
