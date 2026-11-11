"""The deploy contract of every scenario, frozen — the one check that covers a
real lab without Docker or Kathará.

``core.topology.export_lab_conf`` already renders a scenario exactly as it will
be deployed: interfaces, image, bridged management port, the startup commands
each node runs, and one ``# <node>: <guest_path> <- <host_path>`` line per
staged file. That output is the closest thing to a deployed lab that can be
produced offline, and nothing was asserting on it.

Two halves, deliberately treated differently:

* **the invariant half** — nodes, links, image, startup commands, and the guest
  paths each node receives. A refactor moves files on the *host*; it must never
  change what a container ends up with. Frozen in tests/snapshots/, compared
  byte for byte.
* **the host half** — where each guest file comes from. This is expected to
  change whenever a module moves, so it is not frozen; instead every host path
  must exist, and no guest module may have a twin left behind elsewhere in the
  tree (a stale copy still satisfies "the file exists" while the lab quietly
  runs old code).

Run: `.venv/bin/python -m pytest tests/test_deploy_contract.py`
Regenerate the snapshots on purpose:
`UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/core/test_deploy_contract.py`
"""

import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from cyberrange.core import cli, registry  # noqa: E402
from cyberrange.core.topology import export_lab_conf  # noqa: E402
from tests.helpers.manifests import manifest_entries  # noqa: E402

from tests.helpers import SNAPSHOT_DIR  # noqa: E402

UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"

# Where guest modules are allowed to live. Used to spot a stale twin after a
# move; update this list when the planes move, not when a single file does.
PLANE_DIRS = ("cyberrange",)


def render(scenario_name):
    """{"nodes": {...invariant...}, "host": {node: {guest: host}}} for a scenario."""
    scenario = registry.get(scenario_name)
    topo = scenario.topology(cli.default_args(scenario))
    with tempfile.TemporaryDirectory() as out:
        export_lab_conf(topo, out)
        lab_conf = Path(out, "lab.conf").read_text()
        startups = {p.stem: p.read_text() for p in Path(out).glob("*.startup")}

    nodes, host = {}, {}
    for line in lab_conf.splitlines():
        line = line.strip()
        if m := re.match(r"^# (\S+): (\S+) <- (\S+)$", line):
            node, guest, host_path = m.groups()
            nodes.setdefault(node, {}).setdefault("guest_files", []).append(guest)
            host.setdefault(node, {})[guest] = host_path
        elif m := re.match(r'^(\w+)\[(\w+)\]="(.*)"$', line):
            node, key, value = m.groups()
            nodes.setdefault(node, {}).setdefault("settings", {})[key] = value
    for node, text in startups.items():
        nodes.setdefault(node, {})["startup"] = text.splitlines()
    return {"nodes": nodes, "host": host}


class DeployContractFrozen(unittest.TestCase):
    """What the containers get must survive any host-side reshuffling."""

    def test_snapshots_match(self):
        for name in registry.names():
            with self.subTest(scenario=name):
                rendered = render(name)["nodes"]
                path = SNAPSHOT_DIR / f"lab-{name}.json"
                if UPDATE:
                    SNAPSHOT_DIR.mkdir(exist_ok=True)
                    path.write_text(json.dumps(rendered, indent=1, sort_keys=True) + "\n")
                    continue
                self.assertTrue(
                    path.exists(),
                    f"missing deploy snapshot {path}. It is the only offline check that a "
                    f"scenario still deploys the same lab — regenerate it deliberately with "
                    f"UPDATE_SNAPSHOTS=1, never by deleting it.",
                )
                expected = json.loads(path.read_text())
                self.assertEqual(
                    expected,
                    rendered,
                    f"the {name} lab deploys something other than the frozen contract: "
                    f"interfaces, image, startup commands or guest paths differ. A pure "
                    f"file move must leave this identical.",
                )


class HostPathsResolve(unittest.TestCase):
    """The other half: where the files come from, which *is* allowed to move.

    Driven by the manifests rather than by a rendered scenario, so that the
    conditional entries are covered too, and so that build-time artifacts
    (a capture, a trained policy, mosquitto.conf) stay out of it: those are
    run inputs, not repo sources, and may legitimately be absent.
    """

    def test_every_host_path_exists(self):
        for host_path, guest, manifest in manifest_entries():
            with self.subTest(manifest=manifest, guest=guest):
                self.assertTrue(
                    (REPO_ROOT / host_path).is_file(),
                    f"{manifest} stages {guest} from {host_path}, which does not exist: "
                    f"the container would come up without it.",
                )

    def test_host_paths_resolve_from_any_working_directory(self):
        """Manifest host paths are repo-relative. Resolving them against the process
        CWD works only while everything is launched from the repo root — an
        undeclared constraint that stages zero files when it is broken, without
        raising. core.paths.resolve() anchors them to the repo instead."""
        from cyberrange.core import paths

        with tempfile.TemporaryDirectory() as elsewhere:
            cwd = os.getcwd()
            os.chdir(elsewhere)
            try:
                for host_path, guest, manifest in manifest_entries():
                    with self.subTest(manifest=manifest, guest=guest):
                        self.assertTrue(
                            paths.resolve(host_path).is_file(),
                            f"{host_path} does not resolve when the process runs from "
                            f"{elsewhere}: the lab would be deployed without {guest}.",
                        )
            finally:
                os.chdir(cwd)

    def test_no_stale_twin_of_a_guest_module(self):
        """A move that leaves a copy behind passes every other check: the manifest
        points at a file that exists, and the lab quietly runs the old code."""
        for host_path in sorted({h for h, _g, _m in manifest_entries()}):
            base = os.path.basename(host_path)
            twins = []
            for plane in PLANE_DIRS:
                plane_dir = REPO_ROOT / plane
                if plane_dir.is_dir():
                    twins += [
                        str(p.relative_to(REPO_ROOT))
                        for p in plane_dir.rglob(base)
                        if "__pycache__" not in p.parts
                    ]
            with self.subTest(module=base):
                self.assertEqual(
                    [host_path],
                    sorted(twins),
                    f"{base} exists in more than one place: {sorted(twins)}. The manifest "
                    f"stages {host_path}; another copy means a move left a twin behind.",
                )


class LaunchNamesMatchTheManifest(unittest.TestCase):
    """Guest file names are written twice: in the deploy manifest, and inside the
    components that launch them (`python3 mtd_coordinator.py`). Nothing crossed
    the two lists, so a renamed guest module could leave a component starting a
    file that was never copied — a container that comes up and dies."""

    def test_every_launched_module_is_staged_somewhere(self):
        staged = {os.path.basename(guest) for _h, guest, _m in manifest_entries()}
        launched = {}
        for components in REPO_ROOT.glob("**/components.py"):
            for m in re.finditer(r"python3 (\w+\.py)", components.read_text()):
                launched.setdefault(m.group(1), set()).add(str(components.relative_to(REPO_ROOT)))

        self.assertTrue(launched, "found no `python3 <module>.py` launch strings to check")
        for module, sources in sorted(launched.items()):
            with self.subTest(module=module):
                self.assertIn(
                    module,
                    staged,
                    f"{module} is launched by {sorted(sources)} but no deploy manifest "
                    f"stages it: that container would start it and die.",
                )


if __name__ == "__main__":
    unittest.main()
