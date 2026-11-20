"""test_scenario_guide.py — the interactive scenario guide, kept in step with the code.

docs/scenario-guide.html walks a newcomer through adding a scenario and writes
the scenario's skeleton from their answers. A guide that drifts from the code
teaches the wrong thing with full confidence, and nothing else would notice. So
this checks every name the guide cites against the repository (#guide-contract),
and runs the skeleton it writes the way the newcomer would: formatted, linted,
its own tests passing on the fake lab, its make rules expanding.

The skeleton half runs the page's own JavaScript and needs node; it skips itself
when node is absent rather than pretending to pass.

Run: `.venv/bin/python -m pytest tests/core/test_scenario_guide.py -q`
"""

import contextlib
import importlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import REPO_ROOT  # noqa: E402

from tests.helpers import guide_contract  # noqa: E402
from tests.helpers.guide_contract import GUIDE, contract  # noqa: E402

from cyberrange.core import paths  # noqa: E402

# Rewrite the page's derived block from the repository instead of comparing.
UPDATE = os.environ.get("UPDATE_GUIDE_CONTRACT") == "1"
NODE = shutil.which("node")
# The sample scenario's package: registered nowhere, mounted only while a test runs.
PROBE_PKG = "cyberrange.scenarios.guide_probe"
PROBE = (
    "spec.name = 'guide-probe'; spec.lab = 'guideprobe'; spec.outDir = 'output/guide-probe/run-1';"
)


def generate(mutate: str = "") -> dict:
    """The page's validateSpec and generateScenario on its example, after the JS
    statements in ``mutate`` (which see the spec as ``spec``)."""
    script = f"""
const html = require("fs").readFileSync({json.dumps(str(GUIDE))}, "utf8");
eval(html.split("// BEGIN generator")[1].split("// END generator")[0]);
const G = globalThis.ScenarioGuide;
const contract = {json.dumps(contract())};
const spec = JSON.parse(JSON.stringify(G.EXAMPLE_SPEC));
(function (spec) {{ {mutate} }})(spec);
process.stdout.write(JSON.stringify({{
  issues: G.validateSpec(spec, contract), out: G.generateScenario(spec, contract)
}}));
"""
    result = subprocess.run([NODE, "-e", script], capture_output=True, text=True)
    assert result.returncode == 0, f"the guide's generator failed:\n{result.stderr}"
    return json.loads(result.stdout)


def node(body: str):
    """Run ``body`` (JavaScript) with the page's generator and view loaded as
    ``G`` and its contract as ``contract``; returns what the body returns."""
    script = f"""
const html = require("fs").readFileSync({json.dumps(str(GUIDE))}, "utf8");
eval(html.split("// BEGIN generator")[1].split("// END generator")[0]);
eval(html.split("// BEGIN view")[1].split("// END view")[0]);
const G = globalThis.ScenarioGuide;
const contract = {json.dumps(contract())};
const example = () => JSON.parse(JSON.stringify(G.EXAMPLE_SPEC));
process.stdout.write(JSON.stringify((function () {{ {body} }})()));
"""
    result = subprocess.run([NODE, "-e", script], capture_output=True, text=True)
    assert result.returncode == 0, f"the guide's script failed:\n{result.stderr}"
    return json.loads(result.stdout)


def errors(result: dict) -> list:
    return [i["msg"] for i in result["issues"] if i["level"] == "error"]


@contextlib.contextmanager
def mounted(root: Path):
    """The skeleton under ``root`` importable as cyberrange.scenarios.guide_probe,
    its repo-relative host paths resolved under ``root`` first. Nothing is
    written to the repository and nothing is registered."""
    pkg_dir = root / "cyberrange" / "scenarios" / "guide_probe"
    spec = importlib.util.spec_from_file_location(
        PROBE_PKG, pkg_dir / "__init__.py", submodule_search_locations=[str(pkg_dir)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[PROBE_PKG] = module
    real = paths.resolve

    def resolve(rel):
        local = root / rel
        return local if not Path(rel).is_absolute() and local.exists() else real(rel)

    try:
        spec.loader.exec_module(module)
        with mock.patch.object(paths, "resolve", resolve):
            yield module
    finally:
        for key in [k for k in sys.modules if k == PROBE_PKG or k.startswith(PROBE_PKG + ".")]:
            del sys.modules[key]


class GuideCitesWhatExists(unittest.TestCase):
    """Every name in #guide-contract, against the repository it describes."""

    @classmethod
    def setUpClass(cls):
        cls.c = contract()

    def test_cited_paths_exist(self):
        for rel in self.c["paths"]:
            with self.subTest(path=rel):
                self.assertTrue(
                    (REPO_ROOT / rel).exists(),
                    f"the guide sends a newcomer to {rel}, which no longer exists",
                )

    def test_cited_symbols_resolve(self):
        for ref in self.c["symbols"]:
            module, attr = ref.split(":")
            with self.subTest(symbol=ref):
                obj = importlib.import_module(module)
                for part in attr.split("."):
                    self.assertTrue(
                        hasattr(obj, part),
                        f"the guide and its skeleton use {ref}, which is gone: the code "
                        "it writes would not import",
                    )
                    obj = getattr(obj, part)

    def test_the_lines_edits_go_next_to_are_still_there(self):
        for rel, anchors in self.c["anchors"].items():
            text = (REPO_ROOT / rel).read_text()
            for anchor in anchors:
                with self.subTest(file=rel, anchor=anchor):
                    self.assertIn(
                        anchor,
                        text,
                        f"the guide tells a newcomer to edit {rel} next to this line, or "
                        "relies on it: update the guide's edits with the file",
                    )

    def test_what_it_knows_of_the_repository_is_current(self):
        """The derived block, key by key, against the repository as it is."""
        expected = guide_contract.derived()
        if UPDATE:
            GUIDE.write_text(guide_contract.rewrite(GUIDE.read_text(), expected))
            return
        found, _hand = guide_contract.read()
        for key in sorted({*expected, *found}):
            with self.subTest(key=key):
                self.assertEqual(
                    expected.get(key),
                    found.get(key),
                    f"the guide's {key!r} no longer match the repository: "
                    f"{guide_contract.WHY.get(key, 'the guide carries a key nothing derives')}. "
                    "If the repository changed on purpose, bring the guide along with "
                    "UPDATE_GUIDE_CONTRACT=1 .venv/bin/python -m pytest "
                    "tests/core/test_scenario_guide.py -q, and read the diff of the page.",
                )

    def test_an_update_rewrites_the_derived_block_and_nothing_else(self):
        html = GUIDE.read_text()
        derived, hand = guide_contract.read(html)
        changed = {**derived, "scenarios": {**derived["scenarios"], "newcomer": "newcomer"}}
        out = guide_contract.rewrite(html, changed)
        self.assertEqual((changed, hand), guide_contract.read(out))
        strip = guide_contract._block(guide_contract.DERIVED_ID)
        self.assertEqual(
            strip.sub("", html), strip.sub("", out), "the update touched the page outside its block"
        )
        self.assertEqual(html, guide_contract.rewrite(html, derived), "an update is not stable")


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class GuideValidates(unittest.TestCase):
    """The mistakes the guide promises to catch, it catches."""

    def test_the_example_is_clean(self):
        self.assertEqual([], generate()["issues"], "the worked example shows a problem")

    def test_a_registered_name(self):
        self.assertTrue(
            any("already registered" in m for m in errors(generate("spec.name = 'cps';")))
        )

    def test_a_dash_in_a_node_name(self):
        result = generate("spec.nodes[0].name = 'field-meter'; spec.agent.enabled = false;")
        self.assertTrue(any("Kathará refuses '-'" in m for m in errors(result)))

    def test_an_address_taken_twice_on_a_link(self):
        result = generate("spec.nodes[2].ifaces[0].cidr = '10.20.0.1/24';")
        self.assertTrue(any("taken twice on CTRL" in m for m in errors(result)))

    def test_a_published_port_with_an_added_default_route(self):
        result = generate("spec.nodes[2].routes[0].replace = false;")
        self.assertTrue(any("tick 'replace'" in m for m in errors(result)))

    def test_an_agent_named_like_an_existing_guest_module(self):
        result = generate("spec.agent.module = 'planner';")
        self.assertTrue(any("already exists" in m for m in errors(result)))


@unittest.skipIf(NODE is None, "node is not installed; the guide's page is unchecked")
class GuideRenders(unittest.TestCase):
    """Every step of the page, rendered from the state alone: a step that throws
    is a blank page for whoever is on it, and nothing else would say so."""

    STATES = {
        "example": "example()",
        "blank": "G.blankSpec()",
        "broken": "Object.assign(example(), {name: 'cps', phases: [], nodes: []})",
        "new image, no agent": "Object.assign(example(), {image: 'new', agent: {enabled: false}})",
        "variant": "JSON.parse(JSON.stringify(G.EXAMPLE_VARIANT))",
        "every component": "Object.assign(example(), {components: Object.keys(contract.components)"
        ".map(type => ({type, phase: 'setup', args: {}}))})",
        "variant with a component": "Object.assign(JSON.parse(JSON.stringify(G.EXAMPLE_VARIANT)), "
        "{components: [{type: 'VulnApp', phase: '', args: {node: 'ews', port: '9090'}}]})",
        "blank variant": "Object.assign(G.blankSpec(), {kind: 'variant'})",
        "broken variant": "Object.assign(JSON.parse(JSON.stringify(G.EXAMPLE_VARIANT)), "
        "{variant: {host: 'nowhere', options: [{name: '--seed'}, {name: 'x'}]}})",
    }

    @classmethod
    def setUpClass(cls):
        cls.pages = node(
            """
const out = {};
for (const [label, spec] of Object.entries({%s})) {
  out[label] = G.stepsFor(spec).map(step => {
    const v = G.view({spec, checks: {}, step: step.id, tab: {}}, contract);
    return {step: step.id, title: step.title, html: v.main(), failed: !!v.gen.error,
            files: v.gen.files.filter(f => f.step === step.id).map(f => f.path),
            edits: v.gen.edits.filter(e => e.step === step.id).map(e => e.file),
            errors: v.issues.filter(i => i.level === "error").map(i => i.step)};
  });
}
return out;
"""
            % ", ".join(f"{json.dumps(k)}: {v}" for k, v in cls.STATES.items())
        )

    def test_every_step_renders_in_every_state(self):
        for label, pages in self.pages.items():
            self.assertEqual(11, len(pages))
            for page in pages:
                with self.subTest(state=label, step=page["step"]):
                    self.assertFalse(page["failed"], "the generator threw on this state")
                    self.assertIn(f"<h2>{page['title']}</h2>", page["html"])
                    self.assertNotIn("undefined", page["html"])
                    self.assertNotIn("[object Object]", page["html"])

    def test_each_step_shows_its_files_and_edits(self):
        for label, pages in self.pages.items():
            for page in pages:
                for path in page["files"] + page["edits"]:
                    with self.subTest(state=label, step=page["step"], path=path):
                        self.assertIn(path, page["html"])

    def test_each_step_shows_its_own_problems(self):
        for label, pages in self.pages.items():
            for page in pages:
                with self.subTest(state=label, step=page["step"]):
                    own = page["errors"].count(page["step"])
                    # The last step sums the others' up in one line.
                    summary = 1 if page["step"] == "finish" and page["errors"] else 0
                    self.assertEqual(own + summary, page["html"].count('<li class="error">'))
        self.assertTrue(self.pages["broken"][1]["errors"], "the broken state shows no problem")
        self.assertEqual(
            {"image", "episode"},
            set(self.pages["broken variant"][0]["errors"]),
            "a host the cps lab lacks and an option cps already has must both be refused",
        )

    def test_the_episode_step_offers_every_component(self):
        html = self.pages["every component"][4]["html"]
        for name, definition in contract()["components"].items():
            with self.subTest(component=name):
                self.assertIn(f"<option selected>{name}</option>", html)
                for param in definition["params"]:
                    self.assertIn(f"<code>{param['name']}</code>", html)

    def test_a_variant_has_its_own_steps(self):
        titles = [p["title"] for p in self.pages["variant"]]
        self.assertIn("The lab it builds on", titles)
        self.assertIn("What it adds", titles)
        self.assertNotIn("Declare the lab", titles)
        lab = self.pages["variant"][2]["html"]
        self.assertIn("<code>hmi</code>", lab)
        self.assertNotIn("What Kathará is given", lab, "a variant declares no lab to preview")

    def test_the_topology_step_previews_the_lab(self):
        html = self.pages["example"][2]["html"]
        self.assertIn("What Kathará is given", html)
        self.assertIn("LAB_DESCRIPTION=&quot;substation&quot;", html)
        self.assertIn('data-tab="probe.startup"', html)


@unittest.skipIf(NODE is None, "node is not installed; the guide's page is unchecked")
class AnswersFile(unittest.TestCase):
    """The answers exported to a file and read back."""

    def test_an_export_reads_back_as_the_same_answers(self):
        self.assertTrue(
            node(
                "const back = G.importSpec(G.exportSpec(example()));"
                "return JSON.stringify(back) === JSON.stringify(example());"
            )
        )

    def test_what_is_not_an_export_is_refused_with_a_reason(self):
        refused = node(
            """
const tries = {
  "not an object": 3, "another file": {name: "x"},
  "a later version": {kind: "cyberrange-scenario-spec", version: 99, spec: example()},
  "no scenario": {kind: "cyberrange-scenario-spec", version: 1, spec: {name: "x"}},
};
const out = {};
for (const [label, doc] of Object.entries(tries)) {
  try { G.importSpec(doc); out[label] = null; } catch (e) { out[label] = e.message; }
}
return out;
"""
        )
        for label, message in refused.items():
            with self.subTest(file=label):
                self.assertTrue(message, "the file was loaded as if it were answers")

    def test_a_damaged_export_still_gives_a_form_that_renders(self):
        result = node(
            """
const spec = G.importSpec({kind: "cyberrange-scenario-spec", version: 1, spec: {
  name: 7, nodes: [null, {name: "a", ifaces: "x", routes: [{}]}],
  phases: [{}, {seconds: "soon"}], agent: "yes"}});
const pages = G.STEPS.map(s => G.view({spec, checks: {}, step: s.id, tab: {}}, contract).main());
return {spec, rendered: pages.every(h => h.includes("<h2>"))};
"""
        )
        self.assertTrue(result["rendered"])
        self.assertEqual("7", result["spec"]["name"])
        self.assertEqual([], result["spec"]["nodes"][1]["ifaces"])
        self.assertEqual(0, result["spec"]["phases"][1]["seconds"])
        self.assertFalse(result["spec"]["agent"]["enabled"])


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class EveryComponent(unittest.TestCase):
    """The call the guide writes for each component of the planes, against the
    constructor it calls: an argument the class does not take is a run that dies
    at its first phase."""

    FILL = (
        "spec.components = Object.entries(contract.components).map(([type, d]) => ({type, "
        "phase: 'setup', args: Object.fromEntries(d.params.filter(p => p.default === null)"
        ".map(p => [p.name, contract.node_params.includes(p.name) ? 'probe' : '0']))}));"
    )

    @classmethod
    def setUpClass(cls):
        import ast

        cls.catalogue = contract()["components"]
        cls.calls = {}
        for kind, base in (("lab", ""), ("variant", AS_VARIANT)):
            fill = cls.FILL.replace("'probe'", "'hmi'") if base else cls.FILL
            files = generate(base + fill)["out"]["files"]
            wanted = "feature.py" if base else "scenario.py"
            [source] = [f["content"] for f in files if f["path"].endswith("/" + wanted)]
            compile(source, wanted, "exec")
            for call in ast.walk(ast.parse(source)):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr in cls.catalogue
                ):
                    cls.calls[(kind, call.func.attr)] = (
                        call.func.value.id,
                        [k.arg for k in call.keywords],
                        len(call.args),
                    )

    def test_each_call_fits_its_constructor(self):
        import inspect

        for kind in ("lab", "variant"):
            for name, definition in self.catalogue.items():
                with self.subTest(kind=kind, component=name):
                    self.assertIn((kind, name), self.calls, "the skeleton does not start it")
                    plane, keywords, positional = self.calls[(kind, name)]
                    self.assertEqual(definition["plane"], plane)
                    self.assertEqual(0, positional, "arguments are passed by name")
                    module = importlib.import_module(f"cyberrange.planes.{plane}.components")
                    inspect.signature(getattr(module, name)).bind(**dict.fromkeys(keywords, 0))

    def test_a_seed_is_the_role_s_own(self):
        seeded = [
            n for n, d in self.catalogue.items() if any(p["name"] == "seed" for p in d["params"])
        ]
        self.assertTrue(seeded)
        for name in seeded:
            with self.subTest(component=name):
                self.assertIn("seed", self.calls[("lab", name)][1])

    def test_what_a_component_needs_of_its_node_is_checked(self):
        result = generate(
            "spec.components = [{type: 'OtSensor', phase: 'setup', args: {node: 'probe'}}];"
            "spec.nodes[3].image = 'kathara/redteam';"
        )
        problems = errors(result)
        self.assertTrue(any("does not install" in m and "numpy" in m for m in problems), problems)
        self.assertTrue(any("'iface' has no default" in m for m in problems), problems)
        staged = generate(
            "spec.components = [{type: 'OtSensor', phase: 'setup', args: {node: 'probe'}}];"
        )
        [manifest] = [
            f["content"] for f in staged["out"]["files"] if f["path"].endswith("guest_files.py")
        ]
        for module in ("/ot_sensor.py", "/ot_model.py", "/ot_registers.py", "/probe_agent.py"):
            self.assertIn(module, manifest)


class _Skeleton:
    """What a newcomer gets from the guide, checked as they would use it."""

    MUTATE = ""
    VARIANT = False

    @classmethod
    def setUpClass(cls):
        result = generate(cls.MUTATE + PROBE if cls.VARIANT else PROBE + cls.MUTATE)
        assert not errors(result), f"the sample spec is invalid: {errors(result)}"
        cls.out = result["out"]
        cls.root = Path(tempfile.mkdtemp(prefix="guide-skeleton-"))
        for f in cls.out["files"]:
            path = cls.root / f["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f["content"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def ruff(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "ruff", *args, "--config", str(REPO_ROOT / "pyproject.toml")],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_it_is_formatted_and_lint_clean(self):
        fmt = self.ruff("format", "--check", "--diff", str(self.root))
        self.assertEqual(0, fmt.returncode, f"the skeleton is not ruff-formatted:\n{fmt.stdout}")
        lint = self.ruff("check", "--output-format", "concise", str(self.root))
        self.assertEqual(0, lint.returncode, f"the skeleton has lint findings:\n{lint.stdout}")

    def test_its_own_tests_pass_on_the_fake_lab(self):
        [path] = [f["path"] for f in self.out["files"] if f["path"].endswith("_scenario.py")]
        with mounted(self.root):
            spec = importlib.util.spec_from_file_location("guide_probe_test", self.root / path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            suite = unittest.TestLoader().loadTestsFromModule(module)
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        self.assertTrue(result.wasSuccessful(), f"the skeleton's tests fail:\n{stream.getvalue()}")
        self.assertEqual(
            self.out["tests"],
            result.testsRun,
            "the guide tells a newcomer to raise MIN_TESTS by this many tests",
        )

    def test_its_accounting_counts_its_files(self):
        import glob

        with mounted(self.root) as pkg:
            manifests = importlib.import_module(f"{PROBE_PKG}.guest_files")
            for category, patterns in pkg.SOURCES.items():
                for pattern in patterns:
                    with self.subTest(category=category, pattern=pattern):
                        self.assertTrue(
                            glob.glob(str(self.root / pattern)),
                            "a SOURCES pattern that matches nothing fails test_loc_coverage",
                        )
            for name in pkg.GUEST_MANIFESTS:
                with self.subTest(manifest=name):
                    for host, _guest in getattr(manifests, name):
                        # Its own files are in the skeleton; a component's are the planes'.
                        self.assertTrue(
                            (self.root / host).is_file() or (REPO_ROOT / host).is_file(),
                            f"{host} is staged but exists nowhere",
                        )

    def test_its_guest_code_imports_only_what_its_image_installs(self):
        from tests.core import test_guest_imports as guest

        for f in self.out["files"]:
            if not f["path"].startswith("nodes/"):
                continue
            with self.subTest(agent=f["path"]):
                imported = guest.module_level_imports(self.root / f["path"])
                self.assertEqual(
                    set(),
                    imported - set(sys.stdlib_module_names),
                    "the placeholder agent is documented as stdlib-only",
                )
                self.assertNotIn("cyberrange", imported)

    def test_the_page_previews_the_lab_as_the_core_renders_it(self):
        from cyberrange.core.cli import default_args
        from cyberrange.core.topology import export_lab_conf

        if self.VARIANT:
            self.skipTest("a variant declares no lab: the page has nothing to preview")
        out_dir = Path(tempfile.mkdtemp(prefix="guide-labconf-"))
        self.addCleanup(shutil.rmtree, out_dir, ignore_errors=True)
        with mounted(self.root):
            module = importlib.import_module(f"{PROBE_PKG}.scenario")
            scenario = getattr(module, self.out["names"]["cls"])()
            export_lab_conf(scenario.topology(default_args(scenario)), str(out_dir))
        rendered = {p.name: p.read_text() for p in out_dir.iterdir()}
        self.assertEqual(
            rendered,
            {f["path"]: f["content"] for f in self.out["preview"]},
            "the page shows a lab other than the one make lab-conf will render: its "
            "preview repeats core/topology.py and has fallen behind it",
        )

    def test_its_make_rules_expand(self):
        mk = self.root / "make" / "guide-probe.mk"
        for target in self.out["targets"]:
            with self.subTest(target=target):
                result = subprocess.run(
                    [
                        "make",
                        "-n",
                        "-f",
                        "Makefile",
                        "-f",
                        str(mk),
                        "M_GUIDE_PROBE_RUN=cyberrange.scenarios.guide_probe.cli",
                        target,
                    ],
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(result.stdout.strip(), f"make -n {target} printed nothing")


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class ExampleSkeleton(_Skeleton, unittest.TestCase):
    """The worked example: an agent, a best-effort and a timed phase."""

    def test_its_campaign_runs_one_scored_run_per_seed(self):
        from tests.helpers.kathara import FakeManager, fake_downloads

        out_root = tempfile.mkdtemp(prefix="guide-campaign-")
        self.addCleanup(shutil.rmtree, out_root, ignore_errors=True)
        with mounted(self.root):
            campaign = importlib.import_module(f"{PROBE_PKG}.campaign")
            cli = importlib.import_module(f"{PROBE_PKG}.cli")
            cfg = campaign.parse_args(
                ["--name", "t", "--out-root", out_root, "--seeds", "1-2", "--observe-duration", "0"]
            )
            cfg.scenario["poll_interval"] = 0

            def run(args, progress):
                with fake_downloads({("probe", "/probe_agent.log"): b"beat 1\n"}):
                    return cli.run(args, progress=progress, manager=FakeManager())

            built = campaign.build_campaign(cfg, run_fn=run, out=lambda _line: None)
            result = built.run()
        self.assertEqual("done", result["status"], result)
        for seed in (1, 2):
            metrics = Path(out_root, "t", "runs", f"seed-{seed}", "metrics.json")
            self.assertTrue(metrics.is_file(), f"run seed-{seed} was not scored")
            scored = json.loads(metrics.read_text())
            # A campaign's ledger is not in the run directory: a score read from
            # it would be empty here and nowhere else.
            self.assertEqual((1, 4), (scored["agent_lines"], scored["nodes"]))

    def test_its_panel_registers_and_draws_a_run(self):
        from tests.core import test_panels

        [panel] = [f["content"] for f in self.out["files"] if f["path"].endswith("panel.js")]
        shape = test_panels.run_node(test_panels.HARNESS % panel)
        self.assertEqual(0, shape.returncode, shape.stderr)
        self.assertEqual({"guide-probe": ["cards"]}, json.loads(shape.stdout))
        drawn = test_panels.run_node(test_panels.DRAW_HARNESS.replace("/* PANELS */", panel))
        self.assertEqual(0, drawn.returncode, drawn.stderr)
        self.assertEqual({}, {k: v for k, v in json.loads(drawn.stdout).items() if v})


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class BareSkeleton(_Skeleton, unittest.TestCase):
    """No agent, two timed phases, a node image of its own."""

    MUTATE = (
        "spec.agent.enabled = false; spec.image = 'new'; spec.newImagePackages = ['numpy'];"
        "spec.phases = [{name: 'warmup', timed: true, seconds: 5},"
        " {name: 'observe', timed: true, seconds: 30}];"
        "spec.components[0].phase = 'warmup';"
    )


AS_VARIANT = "Object.assign(spec, JSON.parse(JSON.stringify(G.EXAMPLE_VARIANT)));"


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class VariantSkeleton(_Skeleton, unittest.TestCase):
    """A variant of the cps lab: a feature with an option and an agent on the HMI."""

    MUTATE = AS_VARIANT
    VARIANT = True

    def test_it_is_the_cps_scenario_with_its_feature(self):
        from cyberrange.scenarios.cps.feature import Feature
        from cyberrange.scenarios.cps.scenario import CpsScenario

        with mounted(self.root):
            module = importlib.import_module(f"{PROBE_PKG}.scenario")
            scenario = getattr(module, self.out["names"]["cls"])()
            self.assertIsInstance(scenario, CpsScenario)
            [feature] = scenario.features
            self.assertIsInstance(feature, Feature)
            for hook in ("add_arguments", "extras", "services"):
                with self.subTest(hook=hook):
                    self.assertIsNot(
                        getattr(type(feature), hook),
                        getattr(Feature, hook),
                        f"the skeleton's feature does not implement {hook}",
                    )

    def test_its_panel_registers_and_delegates_to_the_cps_one(self):
        from tests.core import test_panels

        cps = (REPO_ROOT / "cyberrange/scenarios/cps/panel.js").read_text()
        [panel] = [f["content"] for f in self.out["files"] if f["path"].endswith("panel.js")]
        result = test_panels.run_node(test_panels.HARNESS % "\n".join([cps, panel]))
        self.assertEqual(0, result.returncode, result.stderr)
        registered = json.loads(result.stdout)
        self.assertIn("guide-probe", registered)
        self.assertEqual(registered["cps"], registered["guide-probe"])
        self.assertEqual(set(), set(registered["guide-probe"]) - test_panels.KNOWN_KEYS)


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class VariantWithComponentSkeleton(_Skeleton, unittest.TestCase):
    """A variant whose feature starts a plane component on another cps host."""

    MUTATE = AS_VARIANT + (
        "spec.components = [{type: 'VulnApp', phase: '',"
        " args: {node: 'ews', port: 'a.audit_interval'}}];"
    )
    VARIANT = True

    def test_the_component_is_staged_and_started(self):
        with mounted(self.root):
            module = importlib.import_module(f"{PROBE_PKG}.scenario")
            scenario = getattr(module, self.out["names"]["cls"])()
            from cyberrange.core.cli import default_args

            args = default_args(scenario)
            topo = scenario.topology(args)
            self.assertIn("/vuln_app.py", [guest for _host, guest in topo.node("ews").files])
            started = []
            ctx = mock.Mock(args=args, scenario=scenario)
            ctx.role_seed.return_value = 7
            ctx.start.side_effect = lambda c: started.append(c) or c
            scenario.features[0].services(ctx)
        self.assertEqual(["audit_agent", "vuln_app"], [c.name for c in started])
        self.assertIn("--port 5", started[1].command)


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class BareVariantSkeleton(_Skeleton, unittest.TestCase):
    """A variant that adds nothing yet: still a scenario that imports and runs its tests."""

    MUTATE = AS_VARIANT + "spec.agent.enabled = false; spec.variant.options = [];"
    VARIANT = True


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class EditsApply(unittest.TestCase):
    """tools/apply_scenario_edits.py places the guide's edits in the files as they
    are today — on copies, so the repository is never touched."""

    TOOL = REPO_ROOT / "tools" / "apply_scenario_edits.py"

    MUTATE = PROBE
    MACHINE, MANIFEST = "guide_probe_probe", "GUIDE_PROBE_PROBE_FILES"
    TARGETS = ("guide-probe", "guide-probe-lab", "guide-probe-dashboard", "guide-probe-campaign")

    def setUp(self):
        result = generate(self.MUTATE)
        self.doc = result["out"]["editsFile"]
        self.root = Path(tempfile.mkdtemp(prefix="guide-edits-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.files = sorted({e["file"] for e in self.doc["edits"]})
        for rel in self.files:
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(REPO_ROOT / rel, self.root / rel)
        # The rules the Makefile includes, and the new scenario's own.
        for mk in (REPO_ROOT / "make").glob("*.mk"):
            shutil.copy(mk, self.root / "make" / mk.name)
        [mk] = [f for f in result["out"]["files"] if f["path"].startswith("make/")]
        (self.root / mk["path"]).write_text(mk["content"])
        self.edits = self.root / "scenario-edits.json"
        self.edits.write_text(json.dumps(self.doc))

    def apply(self, *args):
        return subprocess.run(
            [sys.executable, str(self.TOOL), str(self.edits), "--root", str(self.root), *args],
            capture_output=True,
            text=True,
        )

    def read(self):
        return {rel: (self.root / rel).read_text() for rel in self.files}

    def test_every_file_the_guide_edits_is_covered(self):
        self.assertEqual(
            [
                "Makefile",
                "cyberrange/core/registry.py",
                "make/common.mk",
                "mkdocs.yml",
                "tests/core/test_core.py",
                "tests/core/test_guest_imports.py",
            ],
            self.files,
        )
        self.assertEqual(
            ["tests/conftest.py", "tests/snapshots/"],
            [m["file"] for m in self.doc["manual"]],
            "the snapshots and MIN_TESTS are deliberate acts: the tool must not make them",
        )

    def test_without_write_it_shows_the_diff_and_changes_nothing(self):
        before = self.read()
        result = self.apply()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("+include make/guide-probe.mk", result.stdout)
        self.assertEqual(before, self.read())

    def test_the_edits_land_where_the_files_need_them(self):
        result = self.apply("--write")
        self.assertEqual(0, result.returncode, result.stderr)
        after = self.read()

        scope = {}
        exec(compile(after["cyberrange/core/registry.py"], "registry.py", "exec"), scope)
        self.assertEqual(
            "cyberrange.scenarios.guide_probe.scenario:GuideProbeScenario",
            scope["SCENARIOS"]["guide-probe"],
        )
        core = after["tests/core/test_core.py"]
        self.assertEqual(1, core.count("registry.names()"), "the old assertion is still there")
        self.assertIn('"guide-probe", "mqtt-mtd"]', core)
        self.assertIn('registry.get("guide-probe").lab_name, "guideprobe")', core)
        guest = after["tests/core/test_guest_imports.py"]
        tables = guest.split("MACHINES = {")[1]
        self.assertIn(f'"{self.MACHINE}": {self.MANIFEST},', tables.split("}")[0])
        self.assertIn(
            f'"{self.MACHINE}": CPS_IMAGE,', tables.split("IMAGE_OF = {")[1].split("}")[0]
        )
        nav = after["mkdocs.yml"].splitlines()
        at = nav.index("      - Substation gateway: scenario-guide-probe.md")
        self.assertIn("scenario-", nav[at - 1], "the page is not with the other scenarios")

        python = [str(self.root / rel) for rel in self.files if rel.endswith(".py")]
        config = ["--config", str(REPO_ROOT / "pyproject.toml")]
        ruff = [sys.executable, "-m", "ruff"]
        fmt = subprocess.run(
            [*ruff, "format", "--check", "--diff", *config, *python], capture_output=True, text=True
        )
        self.assertEqual(0, fmt.returncode, f"the edits leave a file unformatted:\n{fmt.stdout}")

        for target in self.TARGETS:
            with self.subTest(target=target):
                make = subprocess.run(
                    ["make", "-n", target], cwd=self.root, capture_output=True, text=True
                )
                self.assertEqual(0, make.returncode, make.stderr)
                module = {"dashboard": "core.dashboard", "campaign": "guide_probe.campaign"}.get(
                    target.rsplit("-", 1)[-1], "guide_probe.cli"
                )
                self.assertIn(
                    f"-m cyberrange.{'' if 'core' in module else 'scenarios.'}{module}", make.stdout
                )
        listed = subprocess.run(["make", "help"], cwd=self.root, capture_output=True, text=True)
        self.assertIn("guide-probe-lab", listed.stdout)
        phony = re.search(r"^\.PHONY: .*$", after["Makefile"], re.MULTILINE).group(0)
        self.assertTrue(phony.endswith(" ".join(self.TARGETS)), phony[-120:])

    def test_a_second_run_changes_nothing(self):
        self.assertEqual(0, self.apply("--write").returncode)
        once = self.read()
        again = self.apply("--write")
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertIn("every edit is already in place", again.stdout)
        self.assertEqual(once, self.read())
        self.assertIn("MIN_TESTS", again.stdout, "the manual steps are not recalled")

    def test_a_place_it_cannot_find_writes_nothing_at_all(self):
        mk = self.root / "mkdocs.yml"
        mk.write_text(re.sub(r"scenario-", "page-", mk.read_text()))
        before = self.read()
        result = self.apply("--write")
        self.assertEqual(1, result.returncode)
        self.assertIn("mkdocs.yml", result.stderr)
        self.assertEqual(before, self.read(), "some edits were written and others not")

    def test_an_edit_cannot_leave_the_repository(self):
        self.doc["edits"][0]["file"] = "../outside.py"
        self.edits.write_text(json.dumps(self.doc))
        result = self.apply("--write")
        self.assertEqual(1, result.returncode)
        self.assertIn("not an edit this tool makes", result.stderr)


@unittest.skipIf(NODE is None, "node is not installed; the guide's generator is unchecked")
class VariantEditsApply(EditsApply):
    """The same edits for a variant of the cps lab, whose agent is on the HMI."""

    MUTATE = AS_VARIANT + PROBE + "spec.title = 'Substation gateway';"
    MACHINE, MANIFEST = "guide_probe_hmi", "GUIDE_PROBE_HMI_ADDED_FILES"
    TARGETS = ("guide-probe", "guide-probe-lab", "guide-probe-dashboard")


if __name__ == "__main__":
    unittest.main()
