"""Regression test for the flat-import contract of the guest-side agents.

Every file staged into a Kathara container (see each scenario's guest_files.py)
is copied FLAT to the container filesystem root "/" — Kathara does not deploy
Python packages, so an agent module can only do a bare `import <name>`, never a
package-relative one, and it can only find a shared module if that module was
ALSO copied to the same machine.

This test reproduces that exact layout on the host: for each machine in the
manifest, it copies every (host_path, guest_path) pair into a fresh scratch
directory mirroring the guest paths, then imports every guest module from
there with that directory as the only entry on sys.path[0] (matching a
container's `python3 <name>.py` run from its default working directory "/",
per core/topology.py's deployment-contract docstring). It catches a missing shared
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

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.scenarios.cps.guest_files import (  # noqa: E402
    ATTACKER_CPS_FILES,
    ENGINE_FILES,
    HMI_FILES,
    PLC_FILES,
    SENSOR_FILES,
)
from cyberrange.scenarios.mqtt_mtd.guest_files import (  # noqa: E402
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
    # Cyber-physical (OT/Modbus) scenario nodes.
    "engine": ENGINE_FILES,
    "plc": PLC_FILES,
    "sensor": SENSOR_FILES,
    "hmi": HMI_FILES,
    "attacker_cps": ATTACKER_CPS_FILES,
}

def _project_packages() -> tuple[str, ...]:
    """The repo's top-level importable packages, discovered rather than listed.

    This used to be a hardcoded tuple of names, which is a trap: the check below
    is ``assertNotIn(f"from {pkg}.", text)``, so the day a package is renamed the
    assertion keeps passing against a name nothing uses any more — vacuously
    true, and a guest agent could quietly acquire a host-side import. Discovering
    the names means the check can only go stale if the repo has no packages at
    all, which the test asserts outright.
    """
    names = tuple(sorted(
        p.name for p in REPO_ROOT.iterdir()
        if p.is_dir() and (p / "__init__.py").is_file() and not p.name.startswith((".", "_"))
    ))
    return names


PROJECT_PACKAGES = _project_packages()


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
    """Guest agents must never import a project package (cyberrange.planes.defense.*,
    cyberrange.planes.attack.*, ...) — those paths don't exist on the guest filesystem.
    A flat `from rl_policy import ...` is fine (rl_policy.py is itself staged
    as a flat guest module); `from cyberrange.planes.defense.rl_policy import ...` is not.
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

    def test_the_package_list_is_not_empty(self) -> None:
        """Guards the guard: every assertion above is vacuous if this is empty."""
        self.assertTrue(
            PROJECT_PACKAGES,
            "no top-level packages discovered, so the host-import check above asserts "
            "nothing. Check _project_packages() against the repo layout.")


if __name__ == "__main__":
    unittest.main()
