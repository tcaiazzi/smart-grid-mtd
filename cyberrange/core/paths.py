"""paths.py — where the repo is, computed once.

The root is *found*, not counted: walk up until a directory looks like this
repo. Every module that needs it imports it from here, so a module can move to
any depth without changing what it gets.

Counting levels instead — ``Path(__file__).resolve().parents[2]`` — encodes a
file's position in its own contents, and breaks silently when that position
changes: ``Path`` composes a wrong-but-plausible path, ``(root / rel).is_file()``
simply answers False, and a campaign concludes a step was "already built", or
writes its output outside the repo, instead of failing.
"""

import os
import time
from pathlib import Path

# Files that only ever exist at the top of this repo.
MARKERS = ("pyproject.toml", "Makefile", ".git")


def find_repo_root(start=None) -> Path:
    """The repo root at or above ``start`` (default: this file)."""
    here = Path(start or __file__).resolve()
    for candidate in (here, *here.parents):
        if candidate.is_dir() and any((candidate / m).exists() for m in MARKERS):
            return candidate
    # A checkout without any marker is not something to guess about.
    raise RuntimeError(
        f"no repo root above {here}: expected one of {MARKERS} in a parent directory"
    )


REPO_ROOT = find_repo_root()


def resolve(rel) -> Path:
    """An absolute path for a repo-relative one, independent of the CWD.

    Guest file manifests list host paths relative to the repo root; resolving
    them against the process CWD works only as long as everything is launched
    from there, which is a constraint nobody declared.
    """
    path = Path(rel)
    return path if path.is_absolute() else REPO_ROOT / path


RUNS, LATEST = "runs", "latest"


def new_run_dir(root, scenario, name=None, now=None) -> str:
    """A directory of its own for one run of ``scenario`` under ``root``:
    ``<root>/<scenario>/runs/<date-time>[-name]``, made here, with
    ``<root>/<scenario>/latest`` pointing at it.

    One directory per run, never a fixed one: a second run into the directory
    of the first appends its ledger to the other's and overwrites its
    artifacts, and what is left is neither run."""
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    base = os.path.join(root, scenario, RUNS, f"{stamp}-{name}" if name else stamp)
    path, n = base, 1
    while os.path.exists(path):  # two runs started within the same second
        n += 1
        path = f"{base}-{n}"
    os.makedirs(path)
    link = os.path.join(root, scenario, LATEST)
    # Only a link is replaced: a real directory of that name is someone's data.
    if os.path.islink(link) or not os.path.exists(link):
        tmp = f"{link}.{os.getpid()}"
        os.symlink(os.path.relpath(path, os.path.dirname(link)), tmp)
        os.replace(tmp, link)
    return path
