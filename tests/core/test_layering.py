"""The dependency rule of the repo, enforced instead of described.

    core  <-  planes  <-  scenarios  <-  analysis

Arrows point at what a layer is allowed to import. Nothing points back:

* **core** is the platform. It must not import a plane or a scenario, or it
  stops being the thing every scenario runs on.
* **planes** are reusable building blocks. A plane that imports a scenario can
  only ever serve that scenario — which is how `SoarResponder` and
  `DeliveryAttack` ended up CPS-only and MQTT-only respectively, and why they
  now take what they need as an argument.

Two deliberate exceptions, both string-based rather than imports, so the AST
below never sees them and neither needs an exemption:

* `core/registry.py` maps scenario names to module paths as *strings* and
  resolves them with importlib — being the one place that knows the scenarios
  exist is its whole job;
* `core/loc.py` imports each scenario package the same way, to measure it.

Run: `.venv/bin/python -m pytest tests/test_layering.py`
"""

import ast
import unittest

from tests.helpers import REPO_ROOT  # noqa: E402

CORE = REPO_ROOT / "cyberrange" / "core"
PLANES = REPO_ROOT / "cyberrange" / "planes"

# Violations still to be paid off. Empty is the goal; an entry is a promise,
# not a permission. Format: "<relative path>: <imported module>".
ALLOWED = set()


def imports_of(path):
    """Every module name imported by a file, including imports inside functions."""
    tree = ast.parse(path.read_text(), filename=str(path))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module)
    return names


def offences(root, forbidden_prefixes):
    out = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(REPO_ROOT)
        for name in imports_of(path):
            if any(name == p or name.startswith(p + ".") for p in forbidden_prefixes):
                entry = f"{rel}: {name}"
                if entry not in ALLOWED:
                    out.append(entry)
    return out


class CoreNamesNoScenario(unittest.TestCase):
    """The rule above is enforced on Python imports, which the dashboard's page
    and panels are not: they are HTML and JavaScript, and the way a scenario
    leaks into them is a hardcoded name (`scenario === "cps"`), not an import.

    The core serves the dashboard; which scenario is running is data it reads
    from a ledger, and what to draw for it comes from that scenario's panel.
    One exception is declared: LEGACY_SCENARIO, the name ledgers written before
    run_start carried a scenario field are attributed to."""

    def test_the_dashboard_does_not_name_a_scenario(self):
        from cyberrange.core import registry

        for rel in ("cyberrange/core/dashboard.py", "cyberrange/core/dashboard.html"):
            text = (REPO_ROOT / rel).read_text()
            if rel.endswith(".py"):  # the declared legacy fallback, and only it
                text = text.replace('LEGACY_SCENARIO = "cps"', "")
            for name in registry.names():
                with self.subTest(file=rel, scenario=name):
                    self.assertNotIn(
                        f'"{name}"',
                        text,
                        f"{rel} names the {name!r} scenario. The page should ask the "
                        f"registry for a panel and draw its neutral views when there "
                        f"is none; the backend should read the name from the ledger.",
                    )


class LayeringHolds(unittest.TestCase):
    def test_core_imports_no_plane_and_no_scenario(self):
        bad = offences(CORE, ["cyberrange.planes", "cyberrange.scenarios"])
        self.assertEqual(
            [],
            bad,
            "the platform core imports code that is layered above it:\n  "
            + "\n  ".join(bad)
            + "\nPass it in from the scenario (see Scenario.panel_js / Scenario.structure) "
            "rather than importing downwards.",
        )

    def test_planes_import_no_scenario(self):
        bad = offences(PLANES, ["cyberrange.scenarios"])
        self.assertEqual(
            [],
            bad,
            "a plane imports a scenario, so it can only serve that one scenario:\n  "
            + "\n  ".join(bad)
            + "\nTake the scenario-specific part as a constructor argument instead.",
        )

    def test_allowlist_is_empty(self):
        """The allowlist exists so a violation can be recorded rather than lost.
        It is empty now; keep it that way, and if something must go in, it goes
        in with a plan to take it out."""
        self.assertEqual(set(), ALLOWED, f"layering violations still outstanding: {ALLOWED}")


if __name__ == "__main__":
    unittest.main()
