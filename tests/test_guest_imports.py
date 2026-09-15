"""Regression test for the flat-import contract of the guest-side agents.

Every file staged into a Kathara container (see network_scenario.guest_files)
is copied FLAT to the container filesystem root "/" — Kathara does not deploy
Python packages, so an agent module can only do a bare `import <name>`, never a
package-relative one, and it can only find a shared module if that module was
ALSO copied to the same machine.

This test reproduces that exact layout on the host: for each machine in the
manifest, it copies every (host_path, guest_path) pair into a fresh scratch
directory mirroring the guest paths, then imports every guest module from
there with that directory as the only entry on sys.path[0] (matching a
container's `python3 <name>.py` run from its default working directory "/",
per network_scenario.guest_files's docstring). It catches a missing shared
module or a stray package-relative import in ~1s, without needing Docker or a
live Kathara deploy — see the "V4" gate in the project's refactor plan.

Uses only the standard library (unittest) — this project has no test-runner
dependency today, and this file doesn't need one: run it directly with
`.venv/bin/python tests/test_guest_imports.py` or via `python -m unittest`.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from network_scenario.guest_files import (  # noqa: E402
    ROUTER_FILES,
    SCMC_FILES,
    SEMP_FILES,
    SEMP_RL_FILES,
)

# One entry per Kathara machine that receives guest files. SEMP gets both the
# always-copied files and the RL-only files, since both land on the same
# machine (the RL files are conditional on a CLI flag, not on machine identity).
MACHINES = {
    "semp": SEMP_FILES + SEMP_RL_FILES,
    "scmc": SCMC_FILES,
    "router": ROUTER_FILES,
}

PROJECT_PACKAGES = ("network_scenario", "defense_plane", "attack_plane", "monitor", "traffic_generator")


def _stage(machine: str, manifest: list[tuple[str, str]]) -> Path:
    """Materialize one machine's guest files into a scratch dir mirroring its
    container filesystem root, and return that directory."""
    stage_dir = Path(tempfile.mkdtemp(prefix=f"guest-{machine}-"))
    for host_rel, guest_path in manifest:
        src = REPO_ROOT / host_rel
        # guest_path is always given with a leading "/" (see guest_files.py's
        # docstring); strip it to place the file under stage_dir instead of the
        # real filesystem root.
        dst = stage_dir / guest_path.lstrip("/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
    return stage_dir


def _python_modules(manifest: list[tuple[str, str]]) -> list[str]:
    """Guest module names (import-able names) from a manifest, .py files only —
    shell scripts (replay_background.sh) aren't Python imports."""
    names = []
    for _host_rel, guest_path in manifest:
        guest_name = guest_path.lstrip("/")
        if guest_name.endswith(".py"):
            names.append(guest_name[: -len(".py")])
    return names


class GuestFilesExistOnHost(unittest.TestCase):
    """Every manifest entry's host_path must exist before it can be staged."""

    def test_all_machines(self) -> None:
        for machine, manifest in sorted(MACHINES.items()):
            for host_rel, _guest_path in manifest:
                with self.subTest(machine=machine, host_rel=host_rel):
                    self.assertTrue(
                        (REPO_ROOT / host_rel).is_file(),
                        f"guest_files manifest for {machine!r} references missing host file: {host_rel}",
                    )


class GuestModulesImportCleanly(unittest.TestCase):
    """Every .py module staged onto a machine must import with only that
    machine's staged files on sys.path[0] — exactly the container's sys.path.

    Run in a subprocess (not importlib in-process) so each module gets a truly
    fresh sys.path and sys.modules, matching a fresh `python3 <name>.py`
    container invocation with no cross-contamination between agents.
    """

    def test_all_machines(self) -> None:
        for machine, manifest in sorted(MACHINES.items()):
            stage_dir = _stage(machine, manifest)
            modules = _python_modules(manifest)
            # A machine may only receive non-Python assets (router only gets
            # replay_background.sh) — that's a valid manifest, not a test bug.
            if not modules:
                continue

            for mod in modules:
                with self.subTest(machine=machine, module=mod):
                    result = subprocess.run(
                        [sys.executable, "-c", f"import {mod}"],
                        cwd=stage_dir,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(
                        result.returncode,
                        0,
                        f"guest module {mod!r} failed to import on machine {machine!r} "
                        f"with only its staged files on sys.path (cwd={stage_dir}):\n{result.stderr}",
                    )


class NoStrayProjectImportsInGuestAgents(unittest.TestCase):
    """Guest agents must never import a project package (defense_plane.*,
    attack_plane.*, ...) — those paths don't exist on the guest filesystem.
    A flat `from rl_policy import ...` is fine (rl_policy.py is itself staged
    as a flat guest module); `from defense_plane.rl_policy import ...` is not.
    """

    def test_all_agents(self) -> None:
        seen = set()
        for manifest in MACHINES.values():
            for host_rel, _guest_path in manifest:
                if not host_rel.endswith(".py") or host_rel in seen:
                    continue
                seen.add(host_rel)
                text = (REPO_ROOT / host_rel).read_text()
                for pkg in PROJECT_PACKAGES:
                    with self.subTest(host_rel=host_rel, package=pkg):
                        self.assertNotIn(f"from {pkg}.", text)
                        self.assertNotIn(f"import {pkg}.", text)


if __name__ == "__main__":
    unittest.main()
