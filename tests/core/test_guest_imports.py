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

It also holds the other half of the guest contract: an agent may import only
what its node image installs, and the images install the versions the host
tests run against.

Run: `.venv/bin/python -m pytest tests/core/test_guest_imports.py`.
"""

import ast
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.scenarios.cps.guest_files import (  # noqa: E402
    ATTACKER_CPS_FILES,
    ENGINE_FILES,
    FW_FILES,
    HMI_FILES,
    PLC_FILES,
    SENSOR_FILES,
    SOC_FILES,
)
from cyberrange.scenarios.cps_advisor.guest_files import (  # noqa: E402
    RED_FILES,
    SOC_CONSOLE_FILES,
    TEAM_FILES,
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
    "firewall": FW_FILES,
    "plc": PLC_FILES,
    "sensor": SENSOR_FILES,
    "soc": SOC_FILES + SOC_CONSOLE_FILES + TEAM_FILES,
    "hmi": HMI_FILES + TEAM_FILES,
    "attacker_cps": ATTACKER_CPS_FILES + RED_FILES + TEAM_FILES,
}


# The image each machine runs, as the Dockerfile that builds it.
MQTT_IMAGE, CPS_IMAGE = "docker/mqtt/Dockerfile", "docker/cps/Dockerfile"
SOC_IMAGE = "docker/soc/Dockerfile"
IMAGE_OF = {
    "semp": MQTT_IMAGE,
    "scmc": MQTT_IMAGE,
    "router": MQTT_IMAGE,
    "engine": CPS_IMAGE,
    "firewall": CPS_IMAGE,
    "plc": CPS_IMAGE,
    "sensor": CPS_IMAGE,
    "soc": SOC_IMAGE,
    "hmi": CPS_IMAGE,
    "attacker_cps": CPS_IMAGE,
}
# Distributions whose import name is not their own.
IMPORT_NAME = {"paho-mqtt": "paho"}
# The guest scapy captures packets, the host scapy only reads pcaps for the
# classifier: the two are not the same code path and are pinned apart.
PINNED_APART = {"scapy"}


def pip_installs(dockerfile: str) -> dict:
    """{distribution: pinned version or None} for every `pip3 install` of a Dockerfile."""
    out, inside = {}, False
    for line in (REPO_ROOT / dockerfile).read_text().splitlines():
        inside = inside or "pip3 install" in line
        if not inside:
            continue
        for token in line.replace("\\", " ").split():
            m = re.fullmatch(r"([A-Za-z0-9_.-]+?)(?:==([\w.]+))?", token)
            if m and token not in ("RUN", "pip3", "install") and not token.startswith("-"):
                out[m.group(1)] = m.group(2)
        inside = line.rstrip().endswith("\\")
    return out


def requirements() -> dict:
    out = {}
    for line in (REPO_ROOT / "requirements.txt").read_text().splitlines():
        m = re.match(r"([A-Za-z0-9_.-]+)==([\w.]+)", line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def module_level_imports(path: Path) -> set:
    """Top-level names a module imports when it is loaded. Imports inside a
    function are left out: that is how an agent carries a dependency only one
    of its uses needs, and it fails where it is used, not at start-up."""
    names = set()

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Import):
                names.update(a.name.split(".")[0] for a in child.names)
            elif isinstance(child, ast.ImportFrom) and child.module and child.level == 0:
                names.add(child.module.split(".")[0])
            visit(child)

    visit(ast.parse(path.read_text()))
    return names


def _project_packages() -> tuple[str, ...]:
    """The repo's top-level importable packages, discovered rather than listed.

    The names are discovered because the check below is
    ``assertNotIn(f"from {pkg}.", text)``: a hardcoded list keeps passing against
    a name nothing uses the day a package is renamed — vacuously true, while a
    guest agent quietly acquires a host-side import. Discovery can only go stale
    if the repo has no packages at all, which the test asserts outright.
    """
    names = tuple(
        sorted(
            p.name
            for p in REPO_ROOT.iterdir()
            if p.is_dir() and (p / "__init__.py").is_file() and not p.name.startswith((".", "_"))
        )
    )
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
                        f"guest_files manifest for {machine!r} references "
                        f"a missing host file: {host_rel}",
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
                        f"with only its staged files on sys.path "
                        f"(cwd={stage_dir}):\n{result.stderr}",
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
            "nothing. Check _project_packages() against the repo layout.",
        )


class GuestImportsAreInTheImage(unittest.TestCase):
    """An agent runs where this repository and its virtualenv do not exist: the
    only third-party code it can load is what its node image installed."""

    def test_all_machines(self) -> None:
        for machine, manifest in sorted(MACHINES.items()):
            installed = {
                IMPORT_NAME.get(d, d.replace("-", "_")) for d in pip_installs(IMAGE_OF[machine])
            }
            staged = {g.lstrip("/")[: -len(".py")] for _h, g in manifest if g.endswith(".py")}
            for host_rel, _guest_path in manifest:
                if not host_rel.endswith(".py"):
                    continue
                third_party = (
                    module_level_imports(REPO_ROOT / host_rel)
                    - staged
                    - set(sys.stdlib_module_names)
                )
                with self.subTest(machine=machine, host_rel=host_rel):
                    self.assertFalse(
                        third_party - installed,
                        f"{host_rel} imports {sorted(third_party - installed)} when it loads, "
                        f"which {IMAGE_OF[machine]} does not install: the agent dies at start-up "
                        f"on {machine!r}. Add it to the image, or import it inside the function "
                        "that needs it.",
                    )

    def test_every_machine_has_an_image(self) -> None:
        self.assertEqual(
            set(MACHINES), set(IMAGE_OF), "a machine with no image is skipped by the check above"
        )


class ImagesPinWhatTheHostTests(unittest.TestCase):
    """The suite exercises the agents against the host's packages. An image
    that installs "whatever is latest" runs them against something else."""

    def test_every_install_is_pinned_to_the_host_version(self) -> None:
        host = requirements()
        for dockerfile in sorted(set(IMAGE_OF.values())):
            for dist, version in pip_installs(dockerfile).items():
                with self.subTest(dockerfile=dockerfile, package=dist):
                    self.assertIsNotNone(
                        version, f"{dist} is unpinned: a rebuilt image may behave differently"
                    )
                    if dist in host and dist not in PINNED_APART:
                        self.assertEqual(
                            host[dist],
                            version,
                            f"{dist} differs between requirements.txt and {dockerfile}: "
                            "the tests pass on one version and the lab runs another",
                        )


class NodeToolsArePinned(unittest.TestCase):
    """The checks above read `pip3 install` only. The Wazuh packages come from
    apt, where an unpinned name means "whatever the repository serves the day
    the image is rebuilt" — and an agent newer than its manager is refused."""

    PACKAGE = re.compile(r"\b(wazuh-(?:agent|manager))(?:=([\w.+~-]+))?(?=\s|$)")

    def installs(self):
        found = []
        for dockerfile in sorted((REPO_ROOT / "docker").glob("*/Dockerfile")):
            for line in dockerfile.read_text().splitlines():
                if line.lstrip().startswith("#") or "install" not in line:
                    continue
                for name, version in self.PACKAGE.findall(line):
                    found.append((str(dockerfile.relative_to(REPO_ROOT)), name, version))
        return found

    def test_every_wazuh_package_is_pinned_to_one_version(self):
        found = self.installs()
        self.assertEqual(
            {name for _f, name, _v in found},
            {"wazuh-agent", "wazuh-manager"},
            "the parser no longer finds the Wazuh installs: the pin check asserts nothing",
        )
        for dockerfile, name, version in found:
            with self.subTest(dockerfile=dockerfile, package=name):
                self.assertTrue(version, f"{name} is unpinned in {dockerfile}")
        self.assertEqual(
            len({v for _f, _n, v in found}),
            1,
            f"agent and manager versions differ, the manager refuses a newer agent: {found}",
        )


if __name__ == "__main__":
    unittest.main()
