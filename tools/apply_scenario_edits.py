#!/usr/bin/env python3
"""apply_scenario_edits.py — make the edits a new scenario needs in files that exist.

The scenario guide (docs/scenario-guide.html) writes a new scenario's own files,
and lists the lines it needs in files that are already there: the registry, the
make include and help, the guardrail tables, the docs nav. Seven files, each with
its own place to insert, is where following the guide by hand goes wrong; the
guide therefore also writes them as data (scenario-edits.json, in its zip) and
this applies them.

It shows the diff and writes nothing unless asked to (--write); it writes either
every edit or none, so a place it cannot find leaves the repository untouched;
and an edit already made is skipped, so it can be run again. What stays a
deliberate act — the snapshots, the floor on the number of tests — it only
recalls, with the commands.

Run, from the repository root:
    .venv/bin/python tools/apply_scenario_edits.py            # show the diff
    .venv/bin/python tools/apply_scenario_edits.py --write    # apply it
"""

import argparse
import difflib
import json
import re
import sys
from pathlib import Path

VERSION = 1
# Files that exist only at the root of this repository.
MARKERS = ("Makefile", "cyberrange/core/registry.py")


class EditError(Exception):
    """An edit that cannot be placed: nothing is written."""


def _lines(text):
    return [line for line in text.splitlines() if line.strip()]


def _present(content, text):
    """Every non-blank line of ``text`` is already a line of ``content``."""
    have = set(content.splitlines())
    return all(line in have for line in _lines(text))


def _insert(lines, index, text):
    # split, not splitlines: a text ending in a newline asks for a blank line after it.
    return lines[:index] + text.split("\n") + lines[index:]


def block_end(content, anchor, text):
    """Insert ``text`` as the last entries of the block opened by the line ``anchor``."""
    lines = content.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.rstrip() == anchor)
        end = next(i for i in range(start + 1, len(lines)) if lines[i].rstrip() in ("}", ")", "]"))
    except StopIteration:
        raise EditError(f"no block opened by the line {anchor!r}") from None
    return "\n".join(_insert(lines, end, text)) + "\n"


def after_last(content, anchor, text):
    """Insert ``text`` after the last line matching the regex ``anchor``."""
    lines = content.splitlines()
    hits = [i for i, line in enumerate(lines) if re.search(anchor, line)]
    if not hits:
        raise EditError(f"no line matches {anchor!r}")
    return "\n".join(_insert(lines, hits[-1] + 1, text)) + "\n"


def before(content, anchor, text):
    """Insert ``text`` before the first line equal to, or starting with, ``anchor``."""
    lines = content.splitlines()
    hits = [i for i, line in enumerate(lines) if line.startswith(anchor)]
    if not hits:
        raise EditError(f"no line starts with {anchor!r}")
    return "\n".join(_insert(lines, hits[0], text)) + "\n"


def append_to_line(content, anchor, text):
    """Add the words of ``text`` the line matching ``anchor`` does not have yet."""
    lines = content.splitlines()
    hits = [i for i, line in enumerate(lines) if re.search(anchor, line)]
    if len(hits) != 1:
        raise EditError(f"{len(hits)} lines match {anchor!r}, expected one")
    have = lines[hits[0]].split()
    missing = [word for word in text.split() if word not in have]
    if missing:
        lines[hits[0]] = lines[hits[0]].rstrip() + " " + " ".join(missing)
    return "\n".join(lines) + "\n"


def replace(content, anchor, text):
    """Put ``text`` in place of the one stretch matching the regex ``anchor``."""
    found = re.findall(anchor, content, re.DOTALL | re.MULTILINE)
    if len(found) != 1:
        raise EditError(f"{len(found)} stretches match {anchor!r}, expected one")
    return re.sub(anchor, lambda _m: text + "\n", content, count=1, flags=re.DOTALL | re.MULTILINE)


MODES = {
    "block_end": block_end,
    "after_last": after_last,
    "before": before,
    "append_to_line": append_to_line,
    "replace": replace,
}


def plan(root: Path, edits: list) -> dict:
    """{relative path: (old, new)} for every file the edits change. Raises
    EditError, naming the edit, when one cannot be placed."""
    contents, original = {}, {}
    for edit in edits:
        rel, mode = edit["file"], edit["mode"]
        path = (root / rel).resolve()
        # The edits come from a file: one must not reach outside the repository.
        if not path.is_relative_to(root.resolve()) or mode not in MODES:
            raise EditError(f"{rel}: not an edit this tool makes ({mode})")
        if rel not in contents:
            if not path.is_file():
                raise EditError(f"{rel}: no such file")
            contents[rel] = original[rel] = path.read_text()
        if mode != "append_to_line" and _present(contents[rel], edit["text"]):
            continue
        try:
            contents[rel] = MODES[mode](contents[rel], edit["anchor"], edit["text"])
        except EditError as e:
            raise EditError(f"{rel}: {edit.get('title', mode)}: {e}") from None
    return {rel: (original[rel], new) for rel, new in contents.items() if new != original[rel]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "edits", nargs="?", default="scenario-edits.json", help="the guide's edits file"
    )
    ap.add_argument("--root", default=".", help="the repository root (default: here)")
    ap.add_argument("--write", action="store_true", help="apply the edits (default: show them)")
    args = ap.parse_args(argv)

    root = Path(args.root)
    if not all((root / m).exists() for m in MARKERS):
        print(f"{root.resolve()} is not the repository root: run this from there", file=sys.stderr)
        return 2
    try:
        doc = json.loads(Path(args.edits).read_text())
    except (OSError, ValueError) as e:
        print(f"cannot read {args.edits}: {e}", file=sys.stderr)
        return 2
    if doc.get("version") != VERSION:
        print(
            f"{args.edits} is version {doc.get('version')}, this tool reads {VERSION}: "
            "download the skeleton again from the guide of this checkout",
            file=sys.stderr,
        )
        return 2

    try:
        changes = plan(root, doc["edits"])
    except EditError as e:
        print(f"cannot place an edit, nothing was written.\n  {e}", file=sys.stderr)
        return 1

    for rel, (old, new) in changes.items():
        sys.stdout.writelines(
            difflib.unified_diff(
                old.splitlines(keepends=True), new.splitlines(keepends=True), rel, rel, n=2
            )
        )
    if not changes:
        print("every edit is already in place")
    elif args.write:
        for rel, (_old, new) in changes.items():
            (root / rel).write_text(new)
        print(f"\nwrote {len(changes)} files")
    else:
        print(f"\n{len(changes)} files would change; run again with --write to apply")

    if doc.get("manual") and (args.write or not changes):
        print("\nLeft to you, on purpose:")
        for item in doc["manual"]:
            print(f"\n- {item['file']}: {item['title']}")
            for line in item["text"].splitlines():
                print(f"    {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
