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
CONSOLE = "http://127.0.0.1:8765"


class Api(unittest.TestCase):
    def setUp(self):
        self.desk = O.ApprovalDesk(clock=lambda: 100.0)
        self.api = O.OperatorApi(self.desk, TOKEN, host="127.0.0.1", origins=[CONSOLE]).start()
        self.addCleanup(self.api.shutdown)
        self.desk.open("abc", {"action": "block_flow", "due_t": 160.0, "explanation": {}})

    def call(self, method, path, body=None, token=TOKEN, origin=None):
        """-> (status, parsed body or None, headers)."""
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if origin:
            headers["Origin"] = origin
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
        return status, (json.loads(text) if text else None), got

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
        self.assertEqual(self.call("GET", "/")[0], 404)
        self.assertEqual(self.desk.take(), [])

    def test_only_the_configured_console_gets_cors(self):
        _s, _d, mine = self.call("GET", "/approvals", origin=CONSOLE)
        self.assertEqual(mine["Access-Control-Allow-Origin"], CONSOLE)
        _s, _d, theirs = self.call("GET", "/approvals", origin="http://evil.example")
        self.assertIsNone(
            theirs["Access-Control-Allow-Origin"],
            "a page from any origin could read the SOC's suggestions in the operator's browser",
        )

    def test_the_preflight_is_answered_without_credentials(self):
        status, _doc, h = self.call("OPTIONS", "/approvals/abc", token=None, origin=CONSOLE)
        self.assertEqual(status, 204)
        self.assertIn("Authorization", h["Access-Control-Allow-Headers"])
        self.assertIn("POST", h["Access-Control-Allow-Methods"])


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
