"""Every entry point the build and the campaigns invoke must actually resolve.

Module paths and `make` target names are an internal API of this repo, spread
across four kinds of file that no import graph connects:

    Makefile / make/*.mk      $(PYTHON) -m cyberrange.scenarios.mqtt_mtd.analysis.plot_results ...
    run_*.sh / scripts/*.sh   $PYTHON -m cyberrange.scenarios.mqtt_mtd.analysis.plot_sweep
    campaign steps            Step(cmd=["make", "datasets"]) and ["-m", "..."]

`make -n` prints those command lines without running them, so a module that no
longer exists is printed happily and fails hours later, in the middle of a
campaign, on the one step that needed it. These tests resolve each name
statically instead: `find_spec` for modules (no real import, so torch and
pandapower are never loaded) and the Makefile's own target list for targets.

Run: `.venv/bin/python -m pytest tests/test_entry_points.py`
"""

import importlib.util
import subprocess
import re
import sys
import unittest
from pathlib import Path

from tests.helpers import REPO_ROOT  # noqa: E402

from tests.helpers.manifests import guest_module_names                     # noqa: E402

MAKEFILES = sorted(REPO_ROOT.glob("Makefile")) + sorted(REPO_ROOT.glob("make/*.mk"))
SHELL_SCRIPTS = sorted(REPO_ROOT.glob("*.sh")) + sorted(REPO_ROOT.glob("scripts/*.sh"))
# Campaign modules build `make` and `python -m` command lines at runtime.
CAMPAIGN_SOURCES = sorted(REPO_ROOT.glob("cyberrange/**/campaign.py")) + \
    sorted(REPO_ROOT.glob("cyberrange/*campaign*.py")) + \
    sorted(REPO_ROOT.glob("cyberrange/**/campaign.py"))

MODULE_RE = re.compile(r"-m\s+([A-Za-z_][\w.]*)")
TARGET_DECL_RE = re.compile(r"^([A-Za-z0-9_.-]+):", re.M)
MAKE_CALL_RE = re.compile(r'\[\s*"make",\s*"([\w.-]+)"')
# `make` in command position only: at the start of a line or right after a
# quote/separator. A bare \bmake\b also matches English prose in comments
# ("drive every make target"), which is not an invocation of anything.
SHELL_MAKE_RE = re.compile(r'(?:^|["\'`;&|(]|\$\()\s*make\s+([a-z][\w-]*)')

# Flat guest module names (modbus_engine, plc_controller, ...) appear in `-m`
# command lines meant to run *inside a container*, or under an explicit
# PYTHONPATH of the agents dir. They are deliberately not importable from the
# repo root, so they are excluded here rather than asserted on.
def declared_targets():
    targets = set()
    for mk in MAKEFILES:
        targets.update(TARGET_DECL_RE.findall(mk.read_text()))
    targets.discard(".PHONY")
    return targets


def make_expanded_modules():
    """{module: ["make <target>"]} from what `make -n` actually prints.

    The makefiles name their entry points through variables ($(M_PLOT_RESULTS)),
    so reading the text would only ever see the variable. Asking make to expand
    each target is both simpler and stricter: it is the very command line that
    would have run.
    """
    found = {}
    for target in sorted(declared_targets()):
        out = subprocess.run(["make", "-n", target], cwd=REPO_ROOT,
                             capture_output=True, text=True)
        for name in MODULE_RE.findall(out.stdout):
            found.setdefault(name, []).append(f"make {target}")
    return found


def referenced_modules():
    """{module: [where it was found]} across makefiles, shell scripts and campaigns."""
    found = make_expanded_modules()
    for path in SHELL_SCRIPTS + CAMPAIGN_SOURCES:
        text = path.read_text()
        for name in MODULE_RE.findall(text):
            found.setdefault(name, []).append(str(path.relative_to(REPO_ROOT)))
    # campaign.py builds ["-m", "cyberrange.scenarios.mqtt_mtd.analysis.plot_results"] as separate list items
    for path in CAMPAIGN_SOURCES:
        for name in re.findall(r'"-m",\s*"([\w.]+)"', path.read_text()):
            found.setdefault(name, []).append(str(path.relative_to(REPO_ROOT)))
    return found


class ModulesResolve(unittest.TestCase):
    def test_every_dash_m_module_is_importable(self):
        guests = guest_module_names()
        modules = referenced_modules()
        self.assertTrue(modules, "found no `-m <module>` invocations to check")
        for name, sources in sorted(modules.items()):
            if name in guests:
                continue          # runs in a container, not from the repo root
            with self.subTest(module=name, sources=sorted(set(sources))):
                try:
                    spec = importlib.util.find_spec(name)
                except (ImportError, ValueError) as e:
                    spec = None
                    self.fail(f"`-m {name}` (in {sorted(set(sources))}) does not resolve: {e}")
                self.assertIsNotNone(
                    spec,
                    f"`-m {name}` is invoked by {sorted(set(sources))} but no such module "
                    f"exists. `make -n` prints this line without ever noticing.")


class MakeTargetsExist(unittest.TestCase):
    def test_targets_invoked_by_campaigns_are_declared(self):
        declared = declared_targets()
        self.assertTrue(declared, "parsed no targets out of the makefiles")
        for path in CAMPAIGN_SOURCES:
            for target in sorted(set(MAKE_CALL_RE.findall(path.read_text()))):
                with self.subTest(target=target, source=str(path.relative_to(REPO_ROOT))):
                    self.assertIn(
                        target, declared,
                        f"{path.name} runs `make {target}`, which no makefile declares: "
                        f"the campaign would fail mid-run.")

    def test_targets_invoked_by_shell_scripts_are_declared(self):
        declared = declared_targets()
        for path in SHELL_SCRIPTS:
            code = "\n".join(line for line in path.read_text().splitlines()
                             if not line.lstrip().startswith("#"))
            for target in sorted(set(SHELL_MAKE_RE.findall(code))):
                with self.subTest(target=target, source=str(path.relative_to(REPO_ROOT))):
                    self.assertIn(
                        target, declared,
                        f"{path.name} runs `make {target}`, which no makefile declares.")


if __name__ == "__main__":
    unittest.main()
