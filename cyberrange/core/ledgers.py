"""ledgers.py — reading what runs and campaigns recorded.

A progress ledger is written by cyberrange/core/progress.py, one JSONL file per
run or campaign. This reads them back: it finds every ledger under a root,
follows each one as it grows, and summarises it into the row the dashboard
lists — kind, name, scenario, progress, status.

Reading is kept apart from serving (cyberrange/core/dashboard.py) because the
two answer different questions: this one, what a run recorded; the other, who
may ask for it. A ledger is only ever read, so nothing here can disturb a lab.
"""

import bisect
import glob
import json
import os
import re
import threading
import time

from cyberrange.core import paths, registry

RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
# Ledgers written before run_start carried a `scenario` field; every one of them
# is a CPS run, and there are real experiments among them. New runs always
# record it, so this name serves history and nothing else — it is the only place
# in the dashboard that knows a scenario exists.
LEGACY_SCENARIO = "cps"
STRUCTURE_FILES = ("kg.json", "tree.json")
# A scored run keeps one document per player that sat at a seat, named by its
# team. The scenario that writes them names its files to match this pattern.
TRAJECTORY_FILES = "trajectory-*.json"
LEDGER_NAME = "progress.jsonl"
# An unfinished ledger whose file has not been touched this long is "interrupted".
# The writer touches it every progress.HEARTBEAT_S even when it has nothing to say.
STALE_S = 30.0
# The tree under the root is walked for new ledgers this often at most: it also
# holds captures and datasets, and the page asks for the list every few seconds.
DISCOVER_TTL_S = 10.0
# Events served per request, by default and at most: a long run is read in pages.
EVENTS_PAGE, EVENTS_PAGE_MAX = 2000, 10000


class _Ledger:
    """Incrementally parsed ledger file (by byte offset; a partial last line
    is kept for the next read)."""

    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.tail = b""
        self.events = []
        self.inode = None
        self.summary = None  # (what it was computed from, the summary)

    @property
    def gen(self):
        """Names this incarnation of the file: a reader holding events of
        another one must drop them, their seq numbers mean something else."""
        first = self.events[0].get("t") if self.events else None
        return f"{self.inode}-{first}"

    def refresh(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return
        size = st.st_size
        if size < self.offset or st.st_ino != self.inode:  # truncated / replaced
            self.offset, self.tail, self.events = 0, b"", []
            self.inode = st.st_ino
        if size == self.offset:
            return
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            chunk = f.read(size - self.offset)
        self.offset = size
        data = self.tail + chunk
        lines = data.split(b"\n")
        self.tail = lines.pop()  # b"" if data ended with \n
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                self.events.append(json.loads(raw))
            except json.JSONDecodeError:
                continue


def summarize(events, mtime, now=None):
    """Status/progress summary of one ledger's events."""
    now = time.time() if now is None else now
    first = events[0] if events else {}
    kind = "campaign" if first.get("kind") == "campaign_start" else "run"
    s = {
        "kind": kind,
        "events": len(events),
        "mtime": round(mtime, 3),
        "started": first.get("t"),
        "last_t": events[-1].get("t") if events else None,
    }
    if kind == "campaign":
        starts = [i for i, e in enumerate(events) if e.get("kind") == "campaign_start"]
        cur = events[starts[-1] :]
        head = cur[0]
        s["name"] = head.get("name")
        s["scenario"] = head.get("scenario") or LEGACY_SCENARIO
        s["total"] = len(head.get("grid") or [])
        finished = {e.get("run_id") for e in cur if e.get("kind") in ("run_metrics", "run_skipped")}
        failed = {e.get("run_id") for e in cur if e.get("kind") == "run_failed"}
        s["done"], s["failed"] = len(finished), len(failed - finished)
        end = next((e for e in reversed(cur) if e.get("kind") == "campaign_end"), None)
        status = end.get("status") if end else None
    else:
        start = next((e for e in reversed(events) if e.get("kind") == "run_start"), {})
        s["name"] = start.get("run_id") or first.get("run_id")
        s["mode"], s["seed"] = start.get("mode"), start.get("seed")
        s["scenario"] = start.get("scenario") or LEGACY_SCENARIO
        end = None
        if start:
            idx = events.index(start)
            end = next((e for e in events[idx:] if e.get("kind") == "run_end"), None)
        status = end.get("status") if end else None
    if status is None:
        status = "running" if now - mtime < STALE_S else "interrupted"
    s["status"] = status
    return s


class LedgerStore:
    def __init__(self, root, scenario=None):
        self.root = os.path.abspath(root)
        # Which scenario to show, or None for all of them. Filtering belongs
        # here and not in the filesystem layout: a campaign records the
        # scenario it ran, so where it was written does not have to say.
        self.scenario = scenario
        self._lock = threading.Lock()
        self._ledgers = {}  # id (relative path) -> _Ledger
        self._structures = {}  # (run dir, mtimes) -> loaded structure
        self._rebuilt = {}  # scenario name -> structure
        self._trajectories = {}  # (run dir, files and mtimes) -> {team: document}
        self._walked = None  # when the root was last walked (monotonic)

    def discover(self, force=False):
        """Walk the root for ledgers; within DISCOVER_TTL_S of the last walk
        the known ones stand, unless ``force`` (an id nobody has seen yet)."""
        now = time.monotonic()
        if not force and self._walked is not None and now - self._walked < DISCOVER_TTL_S:
            return
        self._walked = now
        found = {}
        for dirpath, _dirs, files in os.walk(self.root):
            if LEDGER_NAME in files:
                full = os.path.join(dirpath, LEDGER_NAME)
                found[os.path.relpath(full, self.root)] = full
        with self._lock:
            for lid, full in found.items():
                if lid not in self._ledgers:
                    self._ledgers[lid] = _Ledger(full)
            for lid in list(self._ledgers):
                if lid not in found:
                    del self._ledgers[lid]

    def get(self, lid):
        """The ledger of this id, read up to date; a new one is looked for once."""
        for attempt in (0, 1):
            with self._lock:
                led = self._ledgers.get(lid)
                if led is not None:
                    led.refresh()
                    return led
            if attempt == 0:
                self.discover(force=True)
        return None

    def listing(self, now=None):
        self.discover()
        out = []
        with self._lock:
            items = list(self._ledgers.items())
        clock = time.time() if now is None else now
        for lid, led in items:
            try:
                mtime = os.path.getmtime(led.path)
            except OSError:
                continue
            with self._lock:
                led.refresh()
                # A ledger that has not changed is not summarised again.
                key = (led.gen, len(led.events), mtime, clock - mtime < STALE_S)
                if led.summary is None or led.summary[0] != key:
                    led.summary = (key, summarize(led.events, mtime, clock))
                item = {"id": lid, **led.summary[1]}
            if self.scenario and item.get("scenario") != self.scenario:
                continue
            out.append(item)
        out.sort(key=lambda x: (x["status"] != "running", -(x["last_t"] or x["mtime"])))
        return out

    def events(self, lid, since=0, limit=EVENTS_PAGE):
        """One page of a ledger: {"gen", "next", "total", "events"}. ``next``
        is the seq to ask for next and never passes ``total``, the seq after
        the last event — so a reader ahead of the file learns it."""
        led = self.get(lid)
        if led is None:
            return None
        limit = max(1, min(limit or EVENTS_PAGE, EVENTS_PAGE_MAX))
        with self._lock:
            start = bisect.bisect_left(led.events, since, key=lambda e: e.get("seq", 0))
            evs = led.events[start : start + limit]
            total = led.events[-1].get("seq", len(led.events) - 1) + 1 if led.events else 0
            gen = led.gen
        nxt = evs[-1].get("seq", since) + 1 if evs else min(since, total)
        return {"gen": gen, "next": nxt, "total": total, "events": evs}

    # ── run structure (kg.json / tree.json) ─────────────────────────────────
    def run_dir(self, lid, run_id):
        """Directory of run ``run_id`` of ledger ``lid``, or None. The run must
        be named by the ledger's own events. Its directory is the ``out_dir``
        its run_start recorded; a ledger without one is read by convention — a
        campaign keeps its runs under runs/<run_id>/, a standalone run lives
        next to its ledger."""
        if not run_id:
            return None
        led = self.get(lid)
        if led is None:
            return None
        with self._lock:
            events = list(led.events)
        known = {e.get("run_id") for e in events if e.get("run_id")}
        base = os.path.dirname(led.path)
        recorded = next(
            (
                e["out_dir"]
                for e in reversed(events)
                if e.get("kind") == "run_start" and e.get("run_id") == run_id and e.get("out_dir")
            ),
            None,
        )
        # Relative to where the run was launched: the repository root. A tree
        # moved since then is no longer there, and is found by convention.
        recorded = recorded and os.path.join(paths.REPO_ROOT, recorded)
        if recorded and run_id in known and os.path.isdir(recorded):
            d = recorded
        elif not RUN_ID_RE.match(run_id) or run_id in (".", ".."):
            return None  # only a plain name may be joined into a path
        elif events and events[0].get("kind") == "campaign_start":
            if run_id not in known:
                return None
            d = os.path.join(base, "runs", run_id)
        else:
            if run_id not in known | {os.path.basename(base)}:
                return None
            d = base
        real, root = os.path.realpath(d), os.path.realpath(self.root)
        if real != root and not real.startswith(root + os.sep):
            return None
        return d

    def structure(self, lid, run_id):
        """{"source", "kg", "tree"} for a run; None if the run is unknown;
        {"error": ...} if it has no recorded structure and none can be built."""
        d = self.run_dir(lid, run_id)
        if d is None:
            return None
        scenario = self.scenario_of(lid, run_id)
        paths = [os.path.join(d, f) for f in STRUCTURE_FILES]
        try:
            key = (d,) + tuple(os.path.getmtime(p) for p in paths)
        except OSError:
            return self.rebuilt_structure(scenario)
        with self._lock:
            hit = self._structures.get(key)
        if hit is None:
            try:
                loaded = []
                for p in paths:
                    with open(p) as f:
                        loaded.append(json.load(f))
            except (OSError, json.JSONDecodeError):
                return self.rebuilt_structure(scenario)
            hit = {"source": "recorded", "kg": loaded[0], "tree": loaded[1]}
            with self._lock:
                self._structures = {k: v for k, v in self._structures.items() if k[0] != d}
                self._structures[key] = hit
        return hit

    # ── players' trajectories (trajectory-<team>.json) ───────────────────────
    def trajectories(self, lid, run_id):
        """{"trajectories": {team: document}} for a run, empty when it kept
        none (no player sat at a seat, or it is not scored yet); None if the run
        is unknown. A document that cannot be read is left out: the other
        player's game is still worth showing."""
        d = self.run_dir(lid, run_id)
        if d is None:
            return None
        head, tail = TRAJECTORY_FILES.split("*")
        found = {}
        for p in sorted(glob.glob(os.path.join(glob.escape(d), TRAJECTORY_FILES))):
            try:
                found[os.path.basename(p)[len(head) : -len(tail)]] = (p, os.path.getmtime(p))
            except OSError:
                continue  # removed between the listing and the stat
        key = (d,) + tuple((team, mtime) for team, (_p, mtime) in found.items())
        with self._lock:
            hit = self._trajectories.get(key)
        if hit is None:
            docs = {}
            for team, (p, _mtime) in found.items():
                try:
                    with open(p) as f:
                        docs[team] = json.load(f)
                except (OSError, json.JSONDecodeError):
                    continue
            hit = {"trajectories": docs}
            with self._lock:
                self._trajectories = {k: v for k, v in self._trajectories.items() if k[0] != d}
                self._trajectories[key] = hit
        return hit

    def scenario_of(self, lid, run_id):
        """The scenario a run belongs to, from its ledger (older ledgers: cps)."""
        led = self.get(lid)
        if led is None:
            return None
        with self._lock:
            events = list(led.events)
        for e in events:
            if e.get("kind") == "campaign_start" and e.get("scenario"):
                return e["scenario"]
            if e.get("kind") == "run_start" and e.get("run_id") == run_id and e.get("scenario"):
                return e["scenario"]
        return LEGACY_SCENARIO

    def rebuilt_structure(self, scenario=LEGACY_SCENARIO):
        """The current lab's structure, for runs recorded before kg.json existed.
        The scenario rebuilds it from its own topology (Scenario.structure);
        the dashboard only asks. Lazy: it pulls in networkx and the lab model."""
        if scenario not in self._rebuilt:
            try:
                built = registry.get(scenario).structure()
                if built is None:
                    return {"error": f"scenario {scenario!r} has no structure to rebuild"}
                self._rebuilt[scenario] = {"source": "rebuilt", **built}
            except Exception as e:  # no networkx / Kathará on this host
                return {"error": f"no recorded structure and it cannot be rebuilt: {e}"}
        return self._rebuilt[scenario]
