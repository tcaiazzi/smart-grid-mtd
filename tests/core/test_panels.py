"""The dashboard panel contract, checked by actually running the panels.

No JavaScript in this repo is tested, and the panels are the one piece where a
mistake is both easy and invisible: a factory that throws, or returns something
the page does not expect, degrades the dashboard silently — the scenario's views
simply do not appear.

This loads every scenario's panel.js the way the page does (the file deposits a
factory in window.CyberRangePanels; the page invokes it with its own handles)
and checks what comes back. It needs node, and skips itself when node is absent
rather than pretending to pass.

Run: `.venv/bin/python -m pytest tests/core/test_panels.py`
"""

import json
import shutil
import subprocess
import unittest

from cyberrange.core import registry

NODE = shutil.which("node")

# The page's helpers, which a panel may call at any time. Stubbed here: the
# point is the shape of what a factory returns, not what it draws.
HARNESS = """
globalThis.window = globalThis;
window.CyberRangePanels = {};
const noop = () => undefined;
const api = {
  S: { scenario: null, runs: {}, order: [] },
  $: () => ({ replaceChildren: noop, style: {}, textContent: "", innerHTML: "" }),
  h: () => ({}), num: noop, dur: noop, clock: noop, now: () => 0,
  statusBadge: () => ({}), shownRunId: noop, select: noop, render: noop,
};
%s
const out = {};
for (const [name, make] of Object.entries(window.CyberRangePanels)) {
  const panel = make(api);
  out[name] = Object.keys(panel).filter(k => panel[k] !== undefined).sort();
}
console.log(JSON.stringify(out));
"""

KNOWN_KEYS = {"queue", "detail", "chart", "graph", "tabs"}
GRAPH_KEYS = {"index", "overlayAt", "marks", "drawTopology", "drawKG", "drawTree"}


@unittest.skipIf(NODE is None, "node is not installed; the panel contract is unchecked")
class PanelsLoad(unittest.TestCase):
    def _run(self, sources):
        script = HARNESS % "\n".join(sources)
        result = subprocess.run([NODE, "-e", script], capture_output=True, text=True)
        self.assertEqual(
            0,
            result.returncode,
            f"a panel failed to load or its factory threw:\n{result.stderr.strip()}",
        )
        return json.loads(result.stdout)

    def test_every_declared_panel_registers_itself(self):
        for name in registry.names():
            path = registry.get(name).panel_js()
            if path is None:
                continue
            with self.subTest(scenario=name):
                registered = self._run([open(path).read()])
                self.assertIn(
                    name,
                    registered,
                    f"{path} did not register itself under {name!r}; the page looks it "
                    f"up by the scenario name the ledger reports.",
                )

    def test_panels_expose_only_what_the_page_asks_for(self):
        sources = [
            open(registry.get(n).panel_js()).read()
            for n in registry.names()
            if registry.get(n).panel_js()
        ]
        registered = self._run(sources)
        for name, keys in registered.items():
            with self.subTest(scenario=name):
                unknown = set(keys) - KNOWN_KEYS
                self.assertEqual(
                    set(),
                    unknown,
                    f"{name} exposes {unknown}, which the page never calls. Either the "
                    f"page gained a hook and this list is stale, or the key is dead.",
                )

    def test_a_graph_panel_draws_all_three_views(self):
        """The card has three tabs; a panel that declares a graph must fill them
        all, or a tab opens onto nothing."""
        for name in registry.names():
            path = registry.get(name).panel_js()
            if path is None:
                continue
            script = (HARNESS % open(path).read()).replace(
                "Object.keys(panel).filter(k => panel[k] !== undefined).sort()",
                "panel.graph ? Object.keys(panel.graph).sort() : []",
            )
            result = subprocess.run([NODE, "-e", script], capture_output=True, text=True)
            keys = set(json.loads(result.stdout).get(name, []))
            if not keys:
                continue
            with self.subTest(scenario=name):
                self.assertEqual(
                    GRAPH_KEYS, keys, f"{name}'s graph does not match what the page calls on it"
                )


if __name__ == "__main__":
    unittest.main()
