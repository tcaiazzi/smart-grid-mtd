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
