"""The workstation's maintenance service (ews_maint.py) and the attacker's way
through it (exploit_client): the service refuses a wrong token and a client it
does not serve, and a command reaches it intact through the two shells of the
hop from the compromised host.

Run: `.venv/bin/python -m pytest tests/planes/test_ews_maint.py`.
"""

import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from tests.helpers import guest_paths

guest_paths.add(guest_paths.ATTACK_AGENTS, guest_paths.DEFENSE)

import ews_maint  # noqa: E402  (flat guest imports, need the path set above)
import exploit_client  # noqa: E402

TOKEN = "s3cret"


class Service(unittest.TestCase):
    def serve(self, allow=("127.0.0.1",)):
        server = ThreadingHTTPServer(("127.0.0.1", 0), ews_maint.make_handler(TOKEN, set(allow)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def get(self, url, token, cmd):
        q = urllib.parse.urlencode({"token": token, "cmd": cmd})
        with urllib.request.urlopen(f"{url}/run?{q}", timeout=5) as r:
            return r.read().decode()

    def test_runs_a_command_for_the_token(self):
        self.assertEqual(self.get(self.serve(), TOKEN, "echo hello").strip(), "hello")

    def test_refuses_a_wrong_token(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.get(self.serve(), "guess", "echo hello")
        self.assertEqual(e.exception.code, 403)

    def test_refuses_a_client_it_does_not_serve(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.get(self.serve(allow=("10.10.0.20",)), TOKEN, "echo hello")
        self.assertEqual(e.exception.code, 403, "any IT host could drive the workstation")


class Hop(Service):
    """exploit_client's primitives, with the HMI's shell played by this host."""

    def setUp(self):
        self.conf = Path(tempfile.mkdtemp(prefix="ews-")) / "maint.conf"
        self.real_rce = exploit_client.rce
        exploit_client.rce = lambda _url, cmd, timeout=12.0: (
            subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout
        )
        self.addCleanup(setattr, exploit_client, "rce", self.real_rce)

    def test_credential_is_read_from_the_configuration_file(self):
        self.conf.write_text(f"url=http://x:1\ntoken={TOKEN}\n")
        cred = exploit_client.maint_credential("unused", conf=str(self.conf))
        self.assertEqual(cred, {"url": "http://x:1", "token": TOKEN})
        self.assertIsNone(exploit_client.maint_credential("unused", conf="/nonexistent"))

    def test_a_quoted_command_survives_both_shells(self):
        cred = {"url": self.serve(), "token": TOKEN}
        out = exploit_client.ews_exec("unused", cred, "echo 'a b' \"$((1+2))\"; echo done")
        self.assertEqual(
            out.split(),
            ["a", "b", "3", "done"],
            "the hop mangled the command: the workstation would run something else",
        )


if __name__ == "__main__":
    unittest.main()
