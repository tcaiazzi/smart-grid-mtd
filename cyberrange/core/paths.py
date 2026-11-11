"""paths.py — where the repo is, computed once.

The repo root used to be derived three separate times, each by counting
directory levels up from a module:

    core/campaign.py            Path(__file__).resolve().parents[2]
    scenarios/mqtt_mtd/campaign.py   parents[3]
    core/loc.py                 dirname(dirname(dirname(...)))

That is a silent failure waiting for a refactor. Moving a module one level
changes what ``parents[N]`` points at, and nothing raises: ``Path`` happily
composes a wrong-but-plausible path, ``(root / rel).is_file()`` just answers
False, and a campaign concludes a step was "already built" (or writes its
output outside the repo) instead of failing. Counting levels encodes a file's
position in its own contents.

Here the root is *found* instead: walk up until a directory looks like this
repo. A module can then move anywhere without touching this.
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
        f"no repo root above {here}: expected one of {MARKERS} in a parent directory")


REPO_ROOT = find_repo_root()


def resolve(rel) -> Path:
    """An absolute path for a repo-relative one, independent of the CWD.

    Guest file manifests list host paths relative to the repo root; resolving
    them against the process CWD works only as long as everything is launched
    from there, which is a constraint nobody declared.
    """
    path = Path(rel)
    return path if path.is_absolute() else REPO_ROOT / path
