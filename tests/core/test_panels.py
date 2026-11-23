"""The dashboard panel contract, checked by actually running the panels.

The panels are the one piece where a mistake is both easy and invisible: a
factory that throws, or returns something the page does not expect, degrades the
dashboard silently — the scenario's views simply do not appear — and a panel
that leans on another panel's private names breaks only when a run is drawn.

This loads every scenario's panel.js the way the page does (the file deposits a
factory in window.CyberRangePanels; the page invokes it with its own handles),
checks what comes back, and then draws a fake run through every hook on a
minimal DOM. It needs node, and skips itself when node is absent rather than
pretending to pass.

Run: `.venv/bin/python -m pytest tests/core/test_panels.py`
"""

import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from cyberrange.core import registry
from tests.helpers import trajectories

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
  h: () => ({}), svg: () => ({}), num: noop, dur: noop, clock: noop, now: () => 0,
  statusBadge: () => ({}), shownRunId: noop, select: noop, render: noop,
  time: () => null, setTime: noop, view: () => null,
  stepCell: () => ({}),
  // Records what a panel asks the shared table to draw, instead of drawing it.
  queueTable: (spec) => { globalThis.__queue = spec; },
};
%s
const out = {};
for (const [name, make] of Object.entries(window.CyberRangePanels)) {
  const panel = make(api);
  out[name] = Object.keys(panel).filter(k => panel[k] !== undefined).sort();
}
console.log(JSON.stringify(out));
"""

KNOWN_KEYS = {"queue", "detail", "chart", "graph", "results", "reduce", "cards", "views", "labels"}
# The page's own sections, which a view may list beside the panel's cards.
PAGE_SECTIONS = {
    "tiles-card",
    "runs-card",
    "detail",
    "score-card",
    "results-card",
    "graph-card",
    "op-card",
    "teams-card",
}
GRAPH_KEYS = {"index", "overlayAt", "marks", "drawTopology", "drawKG", "drawTree"}
GRAPH_OPTIONAL = {"options", "origin"}

# A page reduced to what panels touch (panels call h, $, num, dur, clock and S by
# name) and a run as the page's reducer leaves it, with one of every event kind
# the cps family puts on the ledger folded in through the panel's own reduce().
DRAW_HARNESS = (Path(__file__).parent / "panel_draw_harness.js").read_text()


def run_node(script):
    """Run a script under node, handed over on stdin: every panel in one script
    is longer than the operating system lets a single argument be. The drawing
    harness loads the page's libraries from the files named in the environment,
    in the order VENDOR.json lists them (a library after the one it needs). One
    that lays out in a real window (browser_only) is not loaded: the harness
    has a stand-in for it. The players' trajectories it hands the panels are
    built here, by the range's own builder."""
    from cyberrange.core.dashboard import PAGE, VENDOR_DIR, vendored

    files = [f for f, entry in vendored().items() if not entry.get("browser_only")]
    env = {
        **os.environ,
        "DASHBOARD_VENDOR_FILES": json.dumps([os.path.join(VENDOR_DIR, f) for f in files]),
        # The harness takes the page's reducer and helpers from the page itself.
        "DASHBOARD_PAGE": PAGE,
        "DASHBOARD_TRAJECTORIES": json.dumps(trajectories.of_a_run()),
    }
    return subprocess.run([NODE, "-"], input=script, capture_output=True, text=True, env=env)


@unittest.skipIf(NODE is None, "node is not installed; the panel contract is unchecked")
class PanelsLoad(unittest.TestCase):
    def _run(self, sources):
        script = HARNESS % "\n".join(sources)
        result = run_node(script)
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

    def test_a_queue_panel_draws_through_the_shared_table(self):
        """A panel must build its queue with ui.queueTable, which owns selection,
        keyboard navigation and the empty state. One that builds its own table
        loses them silently, for its scenario only."""
        for name in registry.names():
            path = registry.get(name).panel_js()
            if path is None:
                continue
            script = (HARNESS % open(path).read()).replace(
                "console.log(JSON.stringify(out));",
                """
for (const [name, make] of Object.entries(window.CyberRangePanels)) {
  const panel = make(api);
  if (!panel.queue) { out[name] = false; continue; }   // no queue hook at all
  globalThis.__queue = null;
  panel.queue();
  const spec = globalThis.__queue;
  // null means: it has a queue, but never asked the shared table to draw it.
  out[name] = spec
    ? { columns: (spec.columns || []).map(c => c.label), cells: typeof spec.cells }
    : null;
}
console.log(JSON.stringify(out));""",
            )
            result = run_node(script)
            self.assertEqual(0, result.returncode, result.stderr.strip())
            spec = json.loads(result.stdout).get(name)
            if spec is False:  # this scenario draws no queue of its own
                continue
            with self.subTest(scenario=name):
                self.assertIsNotNone(
                    spec,
                    f"{name}.queue() did not go through ui.queueTable — it draws its "
                    f"own table, so selection and keyboard navigation are now its "
                    f"own problem.",
                )
                self.assertTrue(spec["columns"], f"{name} added no columns of its own")
                self.assertEqual("function", spec["cells"], f"{name} passed no cell builder")

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
            result = run_node(script)
            keys = set(json.loads(result.stdout).get(name, []))
            if not keys:
                continue
            with self.subTest(scenario=name):
                self.assertEqual(
                    set(), GRAPH_KEYS - keys, f"{name}'s graph lacks hooks the page calls on it"
                )
                self.assertEqual(
                    set(),
                    keys - GRAPH_KEYS - GRAPH_OPTIONAL,
                    f"{name}'s graph exposes hooks the page never calls",
                )

    def test_a_card_has_an_id_a_title_and_draws(self):
        """The page lays out one card per entry and calls render() at the time the
        bar selects: a card without an id is drawn twice, one without render is an
        empty box. A card may say when it has something to show (live): the page
        calls it for every run, so anything but a function there throws at each frame."""
        for name in registry.names():
            path = registry.get(name).panel_js()
            if path is None:
                continue
            script = (HARNESS % open(path).read()).replace(
                "Object.keys(panel).filter(k => panel[k] !== undefined).sort()",
                "(panel.cards || [])"
                ".map(c => ({ id: c.id, title: c.title, render: typeof c.render,"
                " live: typeof c.live }))",
            )
            result = run_node(script)
            self.assertEqual(0, result.returncode, result.stderr.strip())
            cards = json.loads(result.stdout).get(name, [])
            with self.subTest(scenario=name):
                self.assertEqual(len(cards), len({c["id"] for c in cards}), "card ids repeat")
                for card in cards:
                    self.assertTrue(card["id"] and card["title"], f"unusable card {card}")
                    self.assertEqual("function", card["render"], f"card {card['id']} cannot draw")
                    self.assertIn(
                        card["live"],
                        ("undefined", "function"),
                        f"card {card['id']} cannot be asked whether it has anything to show",
                    )

    def test_a_view_shows_sections_that_exist(self):
        """A view lists the sections it shows, by id: one that names a section
        nobody draws shows a blank where the reader expects a card, and two
        views with one id cannot both be chosen."""
        for name in registry.names():
            path = registry.get(name).panel_js()
            if path is None:
                continue
            script = (HARNESS % open(path).read()).replace(
                "Object.keys(panel).filter(k => panel[k] !== undefined).sort()",
                "{ views: panel.views || [], cards: (panel.cards || []).map(c => c.id),"
                " docked: (panel.cards || []).filter(c => c.dock).map(c => [c.id, c.dock]) }",
            )
            result = run_node(script)
            self.assertEqual(0, result.returncode, result.stderr.strip())
            got = json.loads(result.stdout).get(name)
            if not got or not got["views"]:
                continue
            known = PAGE_SECTIONS | {f"card-{c}" for c in got["cards"]}
            with self.subTest(scenario=name):
                ids = [v["id"] for v in got["views"]]
                self.assertEqual(len(ids), len(set(ids)), "two views share an id")
                for view in got["views"]:
                    self.assertTrue(view.get("label"), f"view {view['id']} has no label")
                    self.assertEqual(
                        set(),
                        set(view["sections"]) - known,
                        f"view {view['id']} shows sections nobody draws",
                    )
                # A docked card is beside every view, so it is in none; anything
                # else that no view lists can never be brought on screen.
                shown = {s for view in got["views"] for s in view["sections"]}
                docked = {f"card-{c}" for c, _where in got["docked"]}
                self.assertEqual({"side"}, {where for _c, where in got["docked"]} | {"side"})
                self.assertEqual(set(), shown & docked, "a docked card is also listed in a view")
                self.assertEqual(
                    set(),
                    known - docked - shown,
                    "these sections are in no view: no tab of the page leads to them",
                )

    def test_the_page_has_the_sections_a_view_may_list(self):
        from cyberrange.core.dashboard import PAGE

        with open(PAGE) as f:
            page = f.read()
        for section in sorted(PAGE_SECTIONS):
            self.assertIn(
                f'id="{section}"', page, f"a view may list {section}, which is not on the page"
            )
        # The views of a scenario that declares none are the page's own.
        own = set(
            re.findall(r'"([a-z]+-card|detail)"', page[page.index("function pageViews") :][:1200])
        )
        self.assertEqual(PAGE_SECTIONS, own, "the page's own views do not cover its sections")

    def test_every_panel_draws_a_run(self):
        """Every hook of every panel, run on an empty run and on one with every
        event kind of the cps family, each card under every view and the attack
        tree from every perspective. All panels share one script on the page, so
        a panel that uses a name only another panel defines passes every shape
        test above and still throws the first time a run is selected."""
        sources = [
            open(registry.get(n).panel_js()).read()
            for n in registry.names()
            if registry.get(n).panel_js()
        ]
        # Each panel alone, then all of them together as the page serves them.
        for label, chunk in [(n, [src]) for n, src in zip(registry.names(), sources)] + [
            ("all panels", sources)
        ]:
            result = run_node(DRAW_HARNESS.replace("/* PANELS */", "\n".join(chunk)))
            with self.subTest(panels=label):
                self.assertEqual(0, result.returncode, result.stderr.strip())
                failures = {k: v for k, v in json.loads(result.stdout).items() if v}
                self.assertEqual(
                    {},
                    failures,
                    "a panel throws while drawing a run; on the page that view stays blank "
                    "and shows its error instead",
                )

    def test_a_results_panel_names_its_tabs_and_draws_them(self):
        """The page builds one button per declared tab and calls render() with
        its id: a tab without a label, or no render, is a button onto nothing."""
        for name in registry.names():
            path = registry.get(name).panel_js()
            if path is None:
                continue
            script = (HARNESS % open(path).read()).replace(
                "Object.keys(panel).filter(k => panel[k] !== undefined).sort()",
                "panel.results ? { tabs: panel.results.tabs, render: typeof panel.results.render }"
                " : null",
            )
            result = run_node(script)
            self.assertEqual(0, result.returncode, result.stderr.strip())
            results = json.loads(result.stdout).get(name)
            if results is None:
                continue
            with self.subTest(scenario=name):
                self.assertEqual("function", results["render"])
                self.assertTrue(results["tabs"], f"{name} declares results but no tab")
                for tab in results["tabs"]:
                    self.assertTrue(tab.get("id") and tab.get("label"), f"unusable tab {tab}")
                self.assertNotIn(
                    "ci", [t["id"] for t in results["tabs"]], "'ci' is the page's own tab"
                )

    def test_every_headline_metric_has_a_name_a_reader_can_use(self):
        """The Results card lists a campaign's headline metrics. One the panel
        does not name is shown as its key spelled out — `detectors · combined ·
        latency from write` — which tells a reader of the page nothing."""
        from cyberrange.scenarios.cps.metrics import CI_HEADLINE
        from cyberrange.scenarios.mqtt_mtd.campaign import HEADLINE

        for name, keys in (("cps", CI_HEADLINE), ("mqtt-mtd", HEADLINE)):
            script = (HARNESS % open(registry.get(name).panel_js()).read()).replace(
                "Object.keys(panel).filter(k => panel[k] !== undefined).sort()",
                "(panel.labels && panel.labels.metrics) || {}",
            )
            result = run_node(script)
            self.assertEqual(0, result.returncode, result.stderr.strip())
            named = json.loads(result.stdout)[name]
            for key in keys:
                with self.subTest(scenario=name, metric=key):
                    self.assertIn(
                        key, named, f"{name}'s panel gives the headline metric {key!r} no name"
                    )
                    self.assertTrue(named[key].get("label"), f"{key}: an empty label")
                    self.assertTrue(
                        named[key].get("unit"), f"{key}: no unit, so its figures cannot be read"
                    )

    def test_the_page_scripts_parse(self):
        """A syntax error in a page is a blank page and nothing else says so: the
        dashboard here, the two team consoles served in the lab, and the
        scenario guide of the documentation site."""
        import re
        import tempfile

        from cyberrange.core import paths

        for page in (
            "cyberrange/core/dashboard.html",
            "nodes/soc/soc_console.html",
            "nodes/redteam/red_console.html",
            "docs/scenario-guide.html",
        ):
            with self.subTest(page=page):
                html = (paths.REPO_ROOT / page).read_text()
                # Inline scripts only: one with a src has no body, one with a
                # type is data. The dashboard names its parts (data-part).
                scripts = re.findall(
                    r'<script(?: data-part="[^"]*")?>(.*?)</script>', html, re.DOTALL
                )
                self.assertTrue(scripts, f"no inline script found in {page}")
                with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
                    f.write("\n".join(scripts))
                result = subprocess.run([NODE, "--check", f.name], capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stderr.strip())


if __name__ == "__main__":
    unittest.main()
