"""The Wazuh active response of the CPS lab (nodes/wazuh/agent/cps_response.py),
off any node: what it runs for a request, what it refuses, and that a request
delivered twice runs once.

Run: `.venv/bin/python -m pytest tests/nodes/test_cps_response.py`.
"""

import io
import json
import os
import tempfile
import unittest
from unittest import mock

from tests.helpers import guest_paths

guest_paths.add(guest_paths.WAZUH_AGENT)

import cps_response as ar  # noqa: E402  (flat guest import, needs the path set above)

ALLOWLIST = {
    "block_flow": {"apply": ["iptables -I FORWARD 1 -j DROP", "true"], "revert": ["iptables -D"]},
    "notify": {"apply": [], "revert": []},
}


def execd(*args):
    """The message wazuh-execd writes on the script's stdin."""
    return json.dumps(
        {"version": 1, "command": "add", "parameters": {"extra_args": list(args), "alert": {}}}
    )


class Requests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(
            ar.parse_request(execd("apply", "block_flow", "r1")), ("apply", "block_flow", "r1")
        )
        self.assertEqual(ar.parse_request("not json"), (None, None, None))
        self.assertEqual(ar.parse_request(execd("apply")), ("apply", None, None))

    def test_runs_the_allowlisted_commands_in_order(self):
        ran = []
        rec = ar.respond(
            "apply", "block_flow", "r1", ALLOWLIST, run=lambda c: ran.append(c) or (0, "")
        )
        self.assertEqual(ran, ALLOWLIST["block_flow"]["apply"])
        self.assertTrue(rec["ok"])
        self.assertEqual([c["cmd"] for c in rec["commands"]], ran)
        self.assertEqual((rec["kind"], rec["request"]), ("cps_response", "r1"))

    def test_a_failing_command_fails_the_response(self):
        rec = ar.respond("apply", "block_flow", "r1", ALLOWLIST, run=lambda c: (1, "no iptables"))
        self.assertFalse(rec["ok"])
        self.assertEqual(rec["commands"][0]["out"], "no iptables")

    def test_refuses_what_is_not_allowed_and_runs_nothing(self):
        ran = []

        def run(cmd):
            ran.append(cmd)
            return 0, ""

        for action, cm_id in (
            ("apply", "isolate_hmi"),
            ("apply", "rm -rf /"),
            ("exec", "block_flow"),
        ):
            rec = ar.respond(action, cm_id, "r", ALLOWLIST, run=run)
            self.assertFalse(rec["ok"], (action, cm_id))
            self.assertTrue(rec["refused"], (action, cm_id))
        self.assertEqual(ran, [], "a request outside the allowlist reached a shell")

    def test_revert_runs_the_revert_commands(self):
        ran = []
        ar.respond("revert", "block_flow", "r", ALLOWLIST, run=lambda c: ran.append(c) or (0, ""))
        self.assertEqual(ran, ["iptables -D"])


class Main(unittest.TestCase):
    """main() against real files: the allowlist it reads, the record it appends."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cps-response-")
        self.allow = os.path.join(self.dir, "allow.json")
        self.record = os.path.join(self.dir, "record.jsonl")
        with open(self.allow, "w") as f:
            json.dump({"mark": {"apply": [f"echo x >> {self.dir}/ran"], "revert": []}}, f)

    def _main(self, message):
        with (
            mock.patch.object(ar, "ALLOWLIST", self.allow),
            mock.patch.object(ar, "RECORD", self.record),
            mock.patch("sys.stdin", io.StringIO(message + "\n")),
        ):
            ar.main()

    def _records(self):
        with open(self.record) as f:
            return [json.loads(line) for line in f]

    def _ran(self):
        path = os.path.join(self.dir, "ran")
        return open(path).read().count("x") if os.path.exists(path) else 0

    def test_applies_and_records(self):
        self._main(execd("apply", "mark", "req-1"))
        self.assertEqual(self._ran(), 1)
        (rec,) = self._records()
        self.assertTrue(rec["ok"])
        self.assertLessEqual(rec["started_t"], rec["done_t"])

    def test_the_same_request_twice_runs_once(self):
        # The requester repeats a request it got no answer to: a restore or a
        # block applied twice would be a second, unrequested change to the plant.
        self._main(execd("apply", "mark", "req-1"))
        self._main(execd("apply", "mark", "req-1"))
        self.assertEqual(self._ran(), 1)
        self.assertEqual(len(self._records()), 1)
        self._main(execd("apply", "mark", "req-2"))
        self.assertEqual(self._ran(), 2)

    def test_without_an_allowlist_everything_is_refused(self):
        os.remove(self.allow)
        self._main(execd("apply", "mark", "req-1"))
        self.assertEqual(self._ran(), 0)
        self.assertTrue(self._records()[0]["refused"])


if __name__ == "__main__":
    unittest.main()
