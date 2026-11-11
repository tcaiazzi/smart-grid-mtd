"""loc.py — how much code is platform and how much is scenario.

Counts source lines (non-blank, not a comment-only line) of:

  platform core        cyberrange/core, the ledger, the dashboard
  plane components     <plane>/components.py — reusable building blocks
  each scenario        its SOURCES (cyberrange/scenarios/<x>/__init__.py)
                       by category — its own deploy manifest included — plus the
                       guest agents its nodes run (from the manifests it lists);
                       files used by more than one scenario are counted once,
                       as shared

This is the "cost of a scenario" table: what a new scenario has to write
versus what it gets from the platform.
"""

import glob
import importlib
import os

from cyberrange.core import paths, registry

REPO_ROOT = str(paths.REPO_ROOT)

# Categories must stay disjoint: each is summed on its own, so a file matched
# by two of them is counted twice (tests/test_loc_coverage.py enforces this).
# The ledger and the dashboard sit in core with everything else, so they are
# covered by its glob rather than listed a second time.
CORE = {
    "run lifecycle, topology, context, streams, campaigns, CLI, ledger, dashboard": [
        "cyberrange/core/*.py",
        "cyberrange/core/dashboard.html",
    ]
}
COMPONENTS = {
    "attack plane": ["cyberrange/planes/attack/components.py"],
    "defense plane": ["cyberrange/planes/defense/components.py"],
    "traffic plane": ["cyberrange/planes/traffic/components.py"],
    "monitor plane": ["cyberrange/planes/monitor/components.py"],
}
GUEST = "guest agents (run in the containers)"


def sloc(path):
    """Non-blank lines that are not comment-only (#, //)."""
    n = 0
    with open(path, errors="replace") as f:
        for line in f:
            t = line.strip()
            if t and not t.startswith(("#", "//")):
                n += 1
    return n


def expand(patterns):
    out = []
    for p in patterns:
        for f in sorted(glob.glob(os.path.join(REPO_ROOT, p))):
            rel = os.path.relpath(f, REPO_ROOT)
            if rel not in out:
                out.append(rel)
    return out


def scenario_files(name):
    """{category: [files]} of one scenario, guest agents included."""
    module = registry.SCENARIOS[name].split(":")[0].rsplit(".", 1)[0]
    pkg = importlib.import_module(module)
    # Each scenario declares its own deploy manifest, next to its topology.
    manifests = importlib.import_module(f"{module}.guest_files")
    cats = {cat: expand(pats) for cat, pats in getattr(pkg, "SOURCES", {}).items()}
    guest = []
    for manifest in getattr(pkg, "GUEST_MANIFESTS", ()):
        for host_path, _guest in getattr(manifests, manifest):
            if host_path not in guest and os.path.exists(os.path.join(REPO_ROOT, host_path)):
                guest.append(host_path)
    cats[GUEST] = guest
    return cats


def report():
    """{"core": {cat: n}, "components": {cat: n}, "scenarios": {name: {cat: n}},
    "shared": {"files": [...], "sloc": n}, "files": {path: sloc}}"""
    files = {}

    def count(paths):
        total = 0
        for p in paths:
            files[p] = files.get(p) or sloc(os.path.join(REPO_ROOT, p))
            total += files[p]
        return total

    core = {c: count(expand(p)) for c, p in CORE.items()}
    comps = {c: count(expand(p)) for c, p in COMPONENTS.items()}
    per = {n: scenario_files(n) for n in registry.names()}
    owners = {}
    for name, cats in per.items():
        for category_files in cats.values():
            for p in category_files:
                owners.setdefault(p, set()).add(name)
    shared = sorted(p for p, o in owners.items() if len(o) > 1)
    scen = {
        name: {c: count([p for p in paths if p not in shared]) for c, paths in cats.items()}
        for name, cats in per.items()
    }
    return {
        "core": core,
        "components": comps,
        "scenarios": scen,
        "shared": {"files": shared, "sloc": count(shared)},
        "files": files,
    }


def format_markdown(r):
    names = sorted(r["scenarios"])
    core_total = sum(r["core"].values())
    comp_total = sum(r["components"].values())
    lines = ["# Platform vs scenario code (source lines)", "", "| platform | lines |", "|---|---:|"]
    lines += [f"| core: {c} | {n} |" for c, n in r["core"].items()]
    lines += [f"| components: {c} | {n} |" for c, n in r["components"].items()]
    lines += [f"| **platform total** | **{core_total + comp_total}** |", ""]
    cats = []
    for name in names:
        cats += [c for c in r["scenarios"][name] if c not in cats]
    lines += ["| scenario-specific | " + " | ".join(names) + " |", "|---|" + "---:|" * len(names)]
    for c in cats:
        lines.append(
            f"| {c} | " + " | ".join(str(r["scenarios"][n].get(c, 0)) for n in names) + " |"
        )
    totals = {n: sum(r["scenarios"][n].values()) for n in names}
    lines.append("| **scenario total** | " + " | ".join(f"**{totals[n]}**" for n in names) + " |")
    lines += [
        "",
        f"Shared by more than one scenario (counted once): {r['shared']['sloc']} lines "
        f"({', '.join(r['shared']['files']) or '—'}).",
        "",
    ]
    plat = core_total + comp_total
    for n in names:
        lines.append(
            f"- {n}: {totals[n]} scenario lines on {plat} platform lines "
            f"({100 * plat / (plat + totals[n]):.0f}% of what it runs on is platform)."
        )
    return "\n".join(lines) + "\n"
