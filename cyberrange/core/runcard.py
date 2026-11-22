"""runcard.py — what a run was made with, kept next to what it produced.

A run's results mean something only against the code, the lab and the options
that produced them. Without that on record, two runs a month apart cannot be
compared: nobody remembers which commit, which lab, which prompt. The card is
<run_dir>/run.json, written when the run starts — so that a run that dies still
says what it was — and completed when it ends.

    code      the commit, whether the tree had uncommitted changes, the Python
    lab       fingerprints of the topology and of whatever structure the
              scenario wrote, and the images of the nodes
    options   the run's options, without its secrets
    scenario  what the scenario adds (Scenario.run_card)
    outcome   status, duration, components that died

Fingerprints are short hashes: two runs with the same one ran the same thing,
which is all a comparison needs to know.
"""

import hashlib
import json
import os
import platform
import subprocess
import time

from cyberrange.core import paths

CARD = "run.json"
MASKED = "<secret>"


def fingerprint(data) -> str:
    """A short, stable name for ``data`` (text or bytes)."""
    raw = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()[:16]


def file_fingerprint(path):
    """The fingerprint of a file, or None when it is not there."""
    try:
        with open(path, "rb") as f:
            return fingerprint(f.read())
    except OSError:
        return None


def _git(*args):
    try:
        out = subprocess.run(
            ["git", *args], cwd=paths.REPO_ROOT, capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def code() -> dict:
    """The code a run is made with. ``dirty`` says the tree had changes no
    commit holds: such a run cannot be reproduced from its commit alone."""
    status = _git("status", "--porcelain")
    return {
        "commit": _git("rev-parse", "HEAD"),
        "dirty": None if status is None else bool(status),
        "python": platform.python_version(),
    }


def images(names) -> dict:
    """{image: its id} for the node images of a run, None for one the engine
    does not know. A tag says which image was asked for, the id which was run."""
    try:
        import docker  # the engine's client, already what the labs run on

        client = docker.from_env()
    except Exception:  # noqa: BLE001 — a card with no image ids is still a card
        return {name: None for name in names}
    out = {}
    for name in names:
        try:
            out[name] = client.images.get(name).short_id
        except Exception:  # noqa: BLE001
            out[name] = None
    return out


def options(args, secrets=()) -> dict:
    """The run's options as data, with every secret one masked: the card is
    kept with the run's artifacts, and a token in it would outlive the run."""
    out = {}
    for key, value in sorted(vars(args).items()):
        if key in secrets and value:
            value = MASKED
        out[key] = value if isinstance(value, (str, int, float, bool, type(None))) else str(value)
    return out


def write(out_dir, card):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, CARD), "w") as f:
        json.dump(card, f, indent=1, default=str)
    return card


def read(out_dir):
    """A run's card, or None for a run that left none."""
    try:
        with open(os.path.join(out_dir, CARD)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def start(out_dir, scenario, args, run_id) -> dict:
    return write(
        out_dir,
        {
            "run_id": run_id,
            "scenario": scenario.name,
            "started": round(time.time(), 3),
            "code": code(),
            "options": options(args, scenario.secret_options(args)),
            "scenario_card": scenario.run_card(args),
            "lab": {},
            "outcome": {"status": "running"},
        },
    )


def lab(card, out_dir, topo, structure=()):
    """Add the lab the run deployed: the topology's fingerprint, those of the
    ``structure`` files the scenario wrote, and the nodes' images."""
    card["lab"] = {
        "topology": file_fingerprint(os.path.join(out_dir, "topology.json")),
        **{name: file_fingerprint(os.path.join(out_dir, name)) for name in structure},
        "images": images(sorted({topo.image_of(n) for n in topo.nodes if topo.image_of(n)})),
    }
    return write(out_dir, card)


def finish(card, out_dir, status, duration_s, down=(), error=None):
    card["outcome"] = {
        "status": status,
        "duration_s": duration_s,
        "components_down": list(down),
        "error": (error or "").strip().splitlines()[-1:] or None,
    }
    return write(out_dir, card)


def summary(card) -> dict:
    """What of a card goes with a run's metrics: enough to tell whether two
    scored runs ran the same thing."""
    card = card or {}
    lab_ = card.get("lab") or {}
    return {
        "commit": (card.get("code") or {}).get("commit"),
        "dirty": (card.get("code") or {}).get("dirty"),
        "topology": lab_.get("topology"),
        **{k: v for k, v in (card.get("scenario_card") or {}).items() if not isinstance(v, dict)},
    }


def runs(root, scenario=None) -> list:
    """Every run under ``root`` that left a card, oldest first: its card, its
    directory, and its score when it has one. ``scenario`` keeps one's only."""
    found = []
    for dirpath, _dirs, files in os.walk(root):
        if CARD not in files:
            continue
        card = read(dirpath)
        if not card or (scenario and card.get("scenario") != scenario):
            continue
        try:
            with open(os.path.join(dirpath, "metrics.json")) as f:
                metrics = json.load(f)
        except (OSError, ValueError):
            metrics = None
        found.append({"dir": dirpath, "card": card, "metrics": metrics})
    return sorted(found, key=lambda r: r["card"].get("started") or 0)


def format_runs(found, headline=None) -> str:
    """One line per run: when, which scenario, how it ended, where it is, and
    what ``headline(scenario name, card, metrics)`` says of it."""
    lines = []
    for r in found:
        card, outcome = r["card"], r["card"].get("outcome") or {}
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(card.get("started") or 0))
        said = headline(card.get("scenario"), card, r["metrics"]) if headline else ""
        lines.append(
            f"{when}  {card.get('scenario', '?'):<12} {outcome.get('status', '?'):<11} "
            f"{r['dir']}" + (f"\n{'':18}{said}" if said else "")
        )
    return "\n".join(lines) if lines else "no run with a card (run.json) here"
