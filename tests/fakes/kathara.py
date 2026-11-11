"""A fake Kathará manager for running scenarios without Docker.

FakeManager records every call (deploy/undeploy, exec) and answers
``exec_obj(..., stream=False)`` from canned data:

  * ``tail -n 1 <frames>``          -> the next of ``frames`` (CPS plant frames)
  * ``tail -n +N <path>``           -> lines N.. of ``files[path]`` (telemetry)
  * ``responses``                   -> {substring: (stdout, stderr, rc)} first match
  * anything else                   -> (b"", b"", 0)

Background execs (stream=True) return an empty iterator. ``fake_downloads``
patches the core's container download so artifacts come from ``guest_files``
({(node, guest_path): bytes}) and land in the run directory like real ones.
"""

import contextlib
import json
import os

from network_scenario.core import context as core_context


class FakeManager:
    def __init__(self, frames=None, files=None, responses=None, fail_exec=False,
                 fail_deploy=False):
        self.frames = list(frames or [])
        self.files = {k: list(v) for k, v in (files or {}).items()}
        self.responses = dict(responses or {})
        self.fail_exec = fail_exec
        self.fail_deploy = fail_deploy
        self.calls = []          # (machine name, command, wait, stream)
        self.deployed = []
        self.undeployed = []

    @staticmethod
    def _name(machine):
        return getattr(machine, "name", str(machine))

    def exec_obj(self, machine, cmd, wait=False, stream=True):
        name = self._name(machine)
        text = cmd if isinstance(cmd, str) else " ".join(cmd)
        self.calls.append((name, text, wait, stream))
        if self.fail_exec and stream is False:
            raise RuntimeError("exec blew up")
        if stream is not False:
            return iter(())
        for key, resp in self.responses.items():
            if key in text:
                return resp
        if text.startswith("tail -n 1 ") and "frames" in text:
            body = (json.dumps(self.frames.pop(0)) + "\n") if self.frames else ""
            return body.encode(), b"", 0
        if text.startswith("tail -n +"):
            start = int(text.split("+")[1].split()[0])
            path = text.split()[-1]
            lines = self.files.get(path, [])[start - 1:]
            return "".join(lines).encode(), b"", 0
        return b"", b"", 0

    def deploy_lab(self, lab):
        if self.fail_deploy:
            raise RuntimeError("deploy failed")
        self.deployed.append(lab.name)

    def undeploy_lab(self, lab=None, **_kw):
        self.undeployed.append(getattr(lab, "name", None))

    # helpers for assertions
    def commands(self, machine=None):
        return [c for m, c, _w, _s in self.calls if machine is None or m == machine]


@contextlib.contextmanager
def fake_downloads(guest_files=None):
    """Serve container downloads from ``guest_files`` {(node, guest_path): bytes}.
    Unknown files raise (as a missing file in a real container does)."""
    # Guest paths are relative to the container root "/": "x" and "/x" are one file.
    guest_files = {(n, "/" + g.lstrip("/")): data for (n, g), data in (guest_files or {}).items()}
    fetched = []
    real = core_context.fetch

    def fake(machine, src_path, dst_path):
        node = getattr(machine, "name", str(machine))
        key = (node, "/" + src_path.lstrip("/"))
        if key not in guest_files:
            raise FileNotFoundError(f"{node}:{src_path}")
        os.makedirs(os.path.dirname(dst_path) or ".", exist_ok=True)
        with open(dst_path, "wb") as f:
            f.write(guest_files[key])
        fetched.append(key)

    core_context.fetch = fake
    try:
        yield fetched
    finally:
        core_context.fetch = real
