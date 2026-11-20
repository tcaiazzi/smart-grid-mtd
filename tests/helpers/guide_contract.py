"""guide_contract.py — what the scenario guide knows about the repository, derived from it.

docs/scenario-guide.html checks a newcomer's answers against facts of this
repository: which scenario and lab names are taken, which make targets and guest
modules exist, what each node image installs. Those facts move whenever someone
adds a scenario, and a copy kept by hand inside an HTML page is a copy nobody
remembers to update.

So the page keeps them in a block of their own (#guide-contract-derived), this
module computes what the block must say, tests/core/test_scenario_guide.py
compares the two, and UPDATE_GUIDE_CONTRACT=1 rewrites the block. What cannot be
derived — the paths and symbols the guide's prose cites — stays in
#guide-contract, written by hand.
"""

import json
import re
import sys

from tests.helpers import REPO_ROOT

from cyberrange.core import registry
from cyberrange.core.scenario import DEFAULT_OVERHEAD_S, OPEN_PHASE

GUIDE = REPO_ROOT / "docs" / "scenario-guide.html"
DERIVED_ID, HAND_ID = "guide-contract-derived", "guide-contract"


def _block(block_id):
    return re.compile(
        rf'(<script type="application/json" id="{block_id}">\n)(.*?)(</script>)', re.DOTALL
    )


def read(html=None) -> tuple:
    """(derived, hand): the two blocks of the page, parsed."""
    html = GUIDE.read_text() if html is None else html
    out = []
    for block_id in (DERIVED_ID, HAND_ID):
        m = _block(block_id).search(html)
        assert m, f"the guide has no #{block_id} block: nothing ties its names to the code"
        out.append(json.loads(m.group(2)))
    return tuple(out)


def contract(html=None) -> dict:
    """The contract as the page's script sees it: both blocks, merged."""
    derived, hand = read(html)
    return {**hand, **derived}


def rewrite(html: str, derived: dict) -> str:
    """``html`` with its derived block saying ``derived``, and nothing else changed.
    One item per line and sorted keys, so that a change shows as the lines it is."""
    body = json.dumps(derived, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    out, n = _block(DERIVED_ID).subn(lambda m: m.group(1) + body + m.group(3), html, count=1)
    assert n == 1, f"the guide has no #{DERIVED_ID} block to rewrite"
    return out


def derived() -> dict:
    """What #guide-contract-derived must say, from the repository as it is."""
    # Imported here: the module stages nothing at import, but it is a test module.
    from tests.core import test_guest_imports as guest
    from tests.helpers.manifests import guest_module_names

    images, installed = {}, set()
    for dockerfile in sorted((REPO_ROOT / "docker").glob("*/Dockerfile")):
        rel = str(dockerfile.relative_to(REPO_ROOT))
        packages = sorted(guest.pip_installs(rel))
        if not packages:
            continue  # no Python of ours can run on it: not an image to offer
        constants = [k for k, v in vars(guest).items() if k.endswith("_IMAGE") and v == rel]
        assert len(constants) == 1, (
            f"{rel} installs Python packages but test_guest_imports.py names it "
            f"{len(constants)} times as an *_IMAGE constant: the guide's IMAGE_OF edit "
            "needs exactly one"
        )
        images[f"kathara/{dockerfile.parent.name}"] = {
            "dockerfile": rel,
            "constant": constants[0],
            "packages": packages,
        }
        installed |= set(packages)

    # A new image may install what some image already does, at the host's pin.
    # A package pinned apart on purpose has no single version to offer.
    pins = guest.requirements()
    offered = {p: pins[p] for p in sorted(installed - guest.PINNED_APART) if p in pins}

    targets = set()
    for mk in [REPO_ROOT / "Makefile", *sorted((REPO_ROOT / "make").glob("*.mk"))]:
        targets |= set(re.findall(r"^([a-zA-Z0-9_.-]+):", mk.read_text(), re.MULTILINE))
    targets.discard(".PHONY")

    port = re.search(r"^CPS_DASH_PORT\s*\?=\s*(\d+)", (REPO_ROOT / "make/cps.mk").read_text(), re.M)
    assert port, "make/cps.mk no longer sets CPS_DASH_PORT: the guide prints the dashboard's URL"

    # A variant builds on the cps lab: its hosts, and the options already taken.
    from cyberrange.core.cli import build_parser
    from cyberrange.scenarios.cps import topology as cps_topology
    from cyberrange.scenarios.cps.scenario import CpsScenario

    cps = CpsScenario()
    parser = build_parser(cps)
    topo = cps.topology(parser.parse_args([]))
    cps_hosts = [
        {"name": h.name, "role": h.role, "image": topo.image_of(topo.node(h.name))}
        for h in cps_topology.DEFAULT.hosts
    ]
    cps_options = sorted(
        {o for action in parser._actions for o in action.option_strings if o.startswith("--")}
    )

    return {
        "components": components(),
        "node_params": list(NODE_PARAMS),
        "cps_hosts": cps_hosts,
        "cps_options": cps_options,
        "scenarios": {name: registry.get(name).lab_name for name in registry.names()},
        "reserved_phases": sorted({*DEFAULT_OVERHEAD_S, OPEN_PHASE}),
        "planes": sorted(
            p.name
            for p in (REPO_ROOT / "cyberrange" / "planes").iterdir()
            if (p / "components.py").is_file()
        ),
        "images": images,
        "requirements": offered,
        "import_names": dict(guest.IMPORT_NAME),
        "targets": sorted(targets),
        "guest_modules": sorted(guest_module_names()),
        "dashboard_port": port.group(1),
    }


# Parameters that name a node of the lab: the guide offers the lab's nodes for them.
NODE_PARAMS = ("node", "ca_node", "client_node", "router", "scmc")


def components() -> dict:
    """{name: {...}} for every component of the planes: its plane, its
    constructor, and what starting it on a node takes — the guest files it
    launches with the modules they import, and the packages those need."""
    import ast
    import importlib
    import inspect

    from cyberrange.core.component import Component
    from tests.core import test_guest_imports as guest
    from tests.helpers.manifests import manifest_entries

    # Every staged file by the name it has in a container. One name, one host
    # file: the stale-twin guardrail holds that, and the lookup relies on it.
    staged = {}
    for host, guest_path, _label in manifest_entries():
        staged.setdefault(guest_path.rsplit("/", 1)[-1], (host, guest_path))
    modules = {name[:-3]: name for name in staged if name.endswith(".py")}
    distribution = {v: k for k, v in guest.IMPORT_NAME.items()}

    def imports(host, top_level):
        tree = ast.parse((REPO_ROOT / host).read_text())
        if top_level:
            return guest.module_level_imports(REPO_ROOT / host)
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names.add(node.module.split(".")[0])
        return names

    def closure(names):
        """The files ``names`` and every staged module they import, wherever."""
        todo, seen = list(names), []
        while todo:
            name = todo.pop(0)
            if name in seen:
                continue
            seen.append(name)
            if name.endswith(".py"):
                todo += sorted(modules[m] for m in imports(staged[name][0], False) if m in modules)
        return seen

    out = {}
    planes = sorted(
        p.name
        for p in (REPO_ROOT / "cyberrange" / "planes").iterdir()
        if (p / "components.py").is_file()
    )
    for plane in planes:
        module = importlib.import_module(f"cyberrange.planes.{plane}.components")
        for name, cls in sorted(vars(module).items()):
            if not (
                inspect.isclass(cls)
                and issubclass(cls, Component)
                and cls.__module__ == module.__name__
                and not name.startswith("_")
            ):
                continue
            # What the class names of the staged files, its in-module bases included.
            source = "".join(
                inspect.getsource(c) for c in cls.__mro__ if c.__module__ == module.__name__
            )
            launched = sorted(
                f for f in staged if re.search(rf"(?<![\w.]){re.escape(f)}\b", source)
            )
            files = closure(launched)
            needs = set()
            for f in files:
                if f.endswith(".py"):
                    needs |= imports(staged[f][0], True)
            needs -= set(sys.stdlib_module_names) | set(modules)
            params = [
                {
                    "name": p.name,
                    "default": None if p.default is inspect.Parameter.empty else repr(p.default),
                }
                for p in list(inspect.signature(cls.__init__).parameters.values())[1:]
                if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
            ]
            doc = (inspect.getdoc(cls) or "").split("\n\n")[0].replace("\n", " ")
            out[name] = {
                "plane": plane,
                "doc": doc,
                "params": params,
                # A driver is started, then run: its attack(ctx) blocks while it acts.
                "drives": callable(getattr(cls, "attack", None)),
                "files": [list(staged[f]) for f in files],
                "needs": sorted(distribution.get(n, n) for n in needs),
            }
    return out


# What goes wrong when a key is stale: the consequence the test reports.
WHY = {
    "scenarios": "a stale list lets a name or lab clash through, and the two scenarios "
    "would undeploy each other's lab",
    "reserved_phases": "the guide would let a scenario declare a phase the core emits itself",
    "planes": "the guide would offer a plane that does not exist",
    "images": "the guide says what each image installs, and so what guest code on it may "
    "import: it must say what the Dockerfiles say",
    "requirements": "a new image is pinned from these: they must be requirements.txt's",
    "import_names": "the guide's IMPORT_NAME advice would be out of date",
    "targets": "a stale list lets a new scenario shadow a target campaigns shell out to",
    "guest_modules": "two files landing as one guest module fail the stale-twin guardrail",
    "components": "the guide would write a call a component no longer accepts, or stage "
    "files it no longer launches",
    "node_params": "the guide would not offer the lab's nodes for a parameter that names one",
    "cps_hosts": "a variant would be offered a host the cps lab does not have, or told the "
    "wrong image for its guest code",
    "cps_options": "a variant could declare an option cps already has, and argparse would "
    "refuse to build its command line",
    "dashboard_port": "the guide would print a dashboard URL nothing listens on",
}
