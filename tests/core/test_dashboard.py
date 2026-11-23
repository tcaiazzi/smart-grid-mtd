"""Tests for the platform progress dashboard server (cyberrange/core/dashboard.py): a
real HTTP server on a free port over a temporary root holding fake ledgers —
a finished campaign, a running one, an interrupted one, a standalone run.

Checks ledger discovery and derived status, incremental event paging with
`since` (including a ledger growing between polls and a partial last line),
that only discovered ledgers are served (no path traversal), and that the page
is served.

Run: `.venv/bin/python -m unittest tests.test_dashboard`.
"""

import hashlib
import json
import os
import re
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request


from cyberrange.core.dashboard import PAGE, VENDOR_DIR, ProgressDashboard  # noqa: E402
from cyberrange.core.ledgers import summarize  # noqa: E402
from cyberrange.core.progress import ProgressLog  # noqa: E402

GRID = [
    {"run_id": "normal-s1", "mode": "normal", "seed": 1, "attack": False},
    {"run_id": "manual-hijack-s1", "mode": "manual-hijack", "seed": 1, "attack": True},
]


def write_campaign(root, name, finish=True, done=2):
    log = ProgressLog(os.path.join(root, "campaigns", name, "progress.jsonl"))
    log.emit("campaign_start", name=name, grid=GRID, planned_run_s={})
    for g in GRID[:done]:
        b = log.bind(run_id=g["run_id"], attempt=1)
        b.emit("run_start", mode=g["mode"], seed=1, phases=[])
        b.emit("run_end", status="ok")
        b.emit("run_metrics", metrics={})
    if finish:
        log.emit("campaign_end", status="done", ok=done, failed=0, skipped=0)
    log.close()
    return os.path.join(root, "campaigns", name, "progress.jsonl")


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="cps-dash-")
        self.done = write_campaign(self.root, "finished")
        self.live = write_campaign(self.root, "live", finish=False, done=1)
        self.dead = write_campaign(self.root, "dead", finish=False, done=1)
        old = time.time() - 3600
        os.utime(self.dead, (old, old))
        run = ProgressLog(os.path.join(self.root, "manual-run", "progress.jsonl")).bind(
            run_id="manual-run"
        )
        run.emit("run_start", mode="breaker-open", seed=3, phases=[])
        run.emit("run_end", status="failed", error="x")
        run._log.close()
        os.makedirs(os.path.join(self.root, "noise"))
        with open(os.path.join(self.root, "noise", "other.jsonl"), "w") as f:
            f.write("{}\n")
        self.dash = ProgressDashboard(self.root, port=0).start()
        self.base = f"http://127.0.0.1:{self.dash.port}"

    def tearDown(self):
        self.dash.shutdown()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as r:
            return r.status, r.headers.get("Content-Type"), r.read()

    def ledgers(self):
        return {e["id"]: e for e in json.loads(self.get("/api/ledgers")[2])["ledgers"]}


class Server(_Fixture):
    def test_discovery_and_status(self):
        ls = self.ledgers()
        ids = {os.path.join("campaigns", n, "progress.jsonl") for n in ("finished", "live", "dead")}
        ids.add(os.path.join("manual-run", "progress.jsonl"))
        self.assertEqual(set(ls), ids)
        st = {k.split(os.sep)[-2]: v["status"] for k, v in ls.items()}
        self.assertEqual(
            st,
            {"finished": "done", "live": "running", "dead": "interrupted", "manual-run": "failed"},
        )
        live = ls[os.path.join("campaigns", "live", "progress.jsonl")]
        self.assertEqual(
            (live["kind"], live["name"], live["done"], live["total"]), ("campaign", "live", 1, 2)
        )
        run = ls[os.path.join("manual-run", "progress.jsonl")]
        self.assertEqual((run["kind"], run["mode"], run["seed"]), ("run", "breaker-open", 3))
        first = json.loads(self.get("/api/ledgers")[2])["ledgers"][0]
        self.assertEqual(first["status"], "running")  # running listed first

    def test_events_paging_and_growth(self):
        lid = os.path.join("campaigns", "live", "progress.jsonl")
        q = f"/api/events?id={urllib.request.quote(lid)}"
        res = json.loads(self.get(q + "&since=0")[2])
        n = len(res["events"])
        self.assertEqual(res["next"], n)
        self.assertEqual([e["seq"] for e in res["events"]], list(range(n)))
        res2 = json.loads(self.get(q + f"&since={res['next']}")[2])
        self.assertEqual((res2["next"], res2["total"], res2["events"]), (n, n, []))
        self.assertEqual(res2["gen"], res["gen"], "an unchanged file was reported as replaced")
        log = ProgressLog(self.live)  # the campaign moves on
        log.emit("aggregate", detection=[], impact=[])
        log.close()
        with open(self.live, "a") as f:
            f.write('{"seq": 99, "kind": "half')  # mid-write line
        res3 = json.loads(self.get(q + f"&since={n}")[2])
        self.assertEqual([e["kind"] for e in res3["events"]], ["aggregate"])
        self.assertEqual(res3["next"], n + 1)

    def test_a_long_ledger_is_read_in_pages(self):
        lid = os.path.join("campaigns", "finished", "progress.jsonl")
        q = f"/api/events?id={urllib.request.quote(lid)}&limit=2"
        total = json.loads(self.get(q)[2])["total"]
        self.assertGreater(total, 4, "the fixture is too short to need three pages")
        seen, since = [], 0
        for _ in range(total):
            res = json.loads(self.get(q + f"&since={since}")[2])
            self.assertLessEqual(len(res["events"]), 2)
            seen += [e["seq"] for e in res["events"]]
            since = res["next"]
            if since >= res["total"]:
                break
        self.assertEqual(seen, list(range(total)), "paging lost or repeated an event")

    def test_a_reader_ahead_of_the_file_is_told_where_it_ends(self):
        lid = os.path.join("campaigns", "live", "progress.jsonl")
        res = json.loads(self.get(f"/api/events?id={urllib.request.quote(lid)}&since=9999")[2])
        self.assertEqual(res["events"], [])
        self.assertEqual(
            res["next"], res["total"], "a reader past the end would wait there for ever"
        )

    def test_a_rewritten_ledger_is_a_new_generation(self):
        lid = os.path.join("campaigns", "live", "progress.jsonl")
        q = f"/api/events?id={urllib.request.quote(lid)}"
        before = json.loads(self.get(q)[2])
        os.rename(self.live, self.live + ".old")  # kept, so its inode is not reused
        log = ProgressLog(self.live)
        log.emit("campaign_start", name="live", grid=GRID, planned_run_s={})
        log.close()
        after = json.loads(self.get(q + f"&since={before['next']}")[2])
        self.assertNotEqual(
            after["gen"], before["gen"], "the page would merge two campaigns into one"
        )
        self.assertLess(after["next"], before["next"])

    def test_a_nan_in_a_ledger_does_not_reach_the_browser(self):
        """JSON.parse rejects a bare NaN: one in a ledger would freeze its page."""
        with open(self.live, "a") as f:
            f.write('{"seq": 50, "t": 1.0, "kind": "run_metrics", "metrics": {"x": NaN}}\n')
        lid = os.path.join("campaigns", "live", "progress.jsonl")
        body = self.get(f"/api/events?id={urllib.request.quote(lid)}")[2]

        def refuse(token):
            raise AssertionError(f"the server sent {token}, which no browser parses")

        res = json.loads(body, parse_constant=refuse)
        self.assertEqual(res["events"][-1]["metrics"], {"x": None})

    def test_the_root_is_not_walked_on_every_listing(self):
        from unittest import mock

        from cyberrange.core import ledgers

        with mock.patch.object(ledgers.os, "walk", wraps=os.walk) as walk:
            self.ledgers()
            self.ledgers()
        self.assertLessEqual(walk.call_count, 1, "every poll of the page walks the whole root")

    def test_a_ledger_written_after_the_last_walk_is_served_by_id(self):
        self.ledgers()
        path = os.path.join(self.root, "late", "progress.jsonl")
        log = ProgressLog(path)
        log.bind(run_id="late").emit("run_start", mode="m", seed=1, phases=[])
        log.close()
        lid = os.path.join("late", "progress.jsonl")
        res = json.loads(self.get(f"/api/events?id={urllib.request.quote(lid)}")[2])
        self.assertEqual([e["kind"] for e in res["events"]], ["run_start"])

    def test_only_discovered_ledgers_are_served(self):
        for bad in (
            "../../../etc/passwd",
            "noise/other.jsonl",
            "nope/progress.jsonl",
            "/etc/passwd",
        ):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                self.get("/api/events?id=" + urllib.request.quote(bad))
            self.assertEqual(cm.exception.code, 404)

    def test_page_served(self):
        status, ctype, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(b"Experiment progress", body)
        for ext in (b'src="http', b"src='http", b'href="http', b"@import"):
            self.assertNotIn(ext, body)  # self-contained, no CDN

    def test_the_time_bar_steps_plays_and_follows_live(self):
        _status, _ctype, body = self.get("/")
        for control in (
            b'id="t-prev"',
            b'id="t-next"',
            b'id="t-play"',
            b'id="g-time"',
            b'id="g-live"',
        ):
            self.assertIn(control, body, "a run could no longer be replayed fact by fact")


class Vendored(_Fixture):
    """The page's libraries are files of this repository, served by this server:
    a lab host may have no internet access, and a library fetched from elsewhere
    could send what the page only reads."""

    def manifest(self):
        with open(os.path.join(VENDOR_DIR, "VENDOR.json")) as f:
            return json.load(f)["files"]

    def test_every_vendored_file_is_the_release_it_claims_to_be(self):
        for entry in self.manifest():
            with self.subTest(file=entry["file"]):
                with open(os.path.join(VENDOR_DIR, entry["file"]), "rb") as f:
                    digest = hashlib.sha256(f.read()).hexdigest()
                self.assertEqual(
                    digest,
                    entry["sha256"],
                    f"{entry['file']} is not the {entry['version']} build VENDOR.json pins: "
                    "it was edited, or replaced without recording the new release",
                )
                self.assertTrue(
                    os.path.isfile(os.path.join(VENDOR_DIR, entry["license_file"])),
                    f"{entry['file']} is redistributed without its licence",
                )

    def test_the_page_loads_only_its_panels_and_vendored_files(self):
        _status, _ctype, body = self.get("/")
        page = body.decode()
        srcs = re.findall(r'<script[^>]*\ssrc="([^"]+)"', page)
        sheets = re.findall(r'<link[^>]*\srel="stylesheet"[^>]*\shref="([^"]+)"', page)
        allowed = {f"vendor/{e['file']}?v={e['version']}" for e in self.manifest()} | {"graph.js"}
        self.assertTrue(srcs, "the page loads no script at all")
        self.assertLessEqual(set(srcs), allowed, "the page loads a script nobody pinned")
        self.assertLessEqual(set(sheets), allowed, "the page loads a stylesheet nobody pinned")
        # A file sent under the wrong type is refused by the browser, silently.
        for src, kind in [(s, "javascript") for s in srcs] + [(s, "css") for s in sheets]:
            status, ctype, _body = self.get("/" + src)
            self.assertEqual(status, 200, src)
            self.assertIn(kind, ctype, src)

    def test_a_stylesheet_fetches_nothing_of_its_own(self):
        """A vendored stylesheet that pulled a font or an image from elsewhere
        would break the page where the lab has no internet access."""
        for entry in self.manifest():
            if entry["file"].endswith(".css"):
                with open(os.path.join(VENDOR_DIR, entry["file"])) as f:
                    css = f.read()
                self.assertNotIn("url(", css, entry["file"])
                self.assertNotIn("@import", css, entry["file"])

    def test_a_vendored_file_is_kept_by_the_browser(self):
        name = self.manifest()[0]["file"]
        with urllib.request.urlopen(f"{self.base}/vendor/{name}", timeout=5) as r:
            self.assertIn("immutable", r.headers.get("Cache-Control", ""))

    def test_only_listed_files_are_served(self):
        for bad in ("VENDOR.json", "d3.LICENSE", "../dashboard.py", "..%2Fdashboard.py", "nope.js"):
            with self.assertRaises(urllib.error.HTTPError, msg=bad) as cm:
                self.get("/vendor/" + bad)
            self.assertEqual(cm.exception.code, 404, bad)

    def test_the_page_fetches_through_one_door(self):
        """D3 can fetch on its own (d3.json and friends): the page's single
        fetch() is what test_the_page_only_ever_reads vouches for."""
        from cyberrange.core.dashboard import scenario_panels

        with open(PAGE) as f:
            sources = {"dashboard.html": f.read()}
        sources["panels"] = b"\n".join(scenario_panels()).decode()
        self.assertEqual(sources["dashboard.html"].count("fetch("), 1)
        self.assertEqual(sources["panels"].count("fetch("), 0, "a panel talks to a server itself")
        for where, text in sources.items():
            for call in ("d3.json(", "d3.text(", "d3.csv(", "d3.tsv(", "d3.dsv(", "d3.blob("):
                self.assertNotIn(call, text, f"{where} fetches around the page's getJSON")
            for call in ("d3.buffer(", "d3.image(", "d3.html(", "d3.xml(", "d3.svg("):
                self.assertNotIn(call, text, f"{where} fetches around the page's getJSON")


class Structure(_Fixture):
    """GET /api/structure: a run's kg.json / tree.json, resolved safely."""

    KG = {
        "directed": True,
        "multigraph": True,
        "graph": {},
        "nodes": [{"id": "host:hmi", "type": "host"}],
        "links": [],
    }
    TREE = {"attack_tree": {"id": "impact", "children": []}, "defense": {}, "countermeasures": []}

    def put(self, d):
        os.makedirs(d, exist_ok=True)
        for name, obj in (("kg.json", self.KG), ("tree.json", self.TREE)):
            with open(os.path.join(d, name), "w") as f:
                json.dump(obj, f)

    def structure(self, lid, run):
        q = urllib.parse.urlencode({"id": lid, "run": run})
        return json.loads(self.get("/api/structure?" + q)[2])

    def test_recorded_campaign_run(self):
        self.put(os.path.join(self.root, "campaigns", "finished", "runs", "manual-hijack-s1"))
        res = self.structure("campaigns/finished/progress.jsonl", "manual-hijack-s1")
        self.assertEqual(res["source"], "recorded")
        self.assertEqual(res["kg"]["nodes"][0]["id"], "host:hmi")
        self.assertEqual(res["tree"]["attack_tree"]["id"], "impact")

    def test_a_run_is_found_where_its_ledger_says_it_was_written(self):
        """A campaign need not keep its runs under runs/<run_id>/, and a run id
        need not be a directory name: the run's own out_dir is authoritative."""
        out_dir = os.path.join(self.root, "elsewhere", "attack")
        self.put(out_dir)
        lid = os.path.join(self.root, "campaigns", "other", "progress.jsonl")
        log = ProgressLog(lid)
        log.emit("campaign_start", name="other", grid=[], planned_run_s={})
        log.bind(run_id="fixed@output/run-0").emit("run_start", out_dir=out_dir, phases=[])
        log.close()
        res = self.structure("campaigns/other/progress.jsonl", "fixed@output/run-0")
        self.assertEqual(res["source"], "recorded")

    def test_a_recorded_directory_outside_the_root_is_refused(self):
        outside = tempfile.mkdtemp(prefix="outside-")
        self.put(outside)
        log = ProgressLog(os.path.join(self.root, "campaigns", "evil", "progress.jsonl"))
        log.emit("campaign_start", name="evil", grid=[], planned_run_s={})
        log.bind(run_id="r").emit("run_start", out_dir=outside, phases=[])
        log.close()
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.structure("campaigns/evil/progress.jsonl", "r")
        self.assertEqual(cm.exception.code, 404, "a ledger pointed the server outside --root")

    def test_recorded_standalone_run(self):
        self.put(os.path.join(self.root, "manual-run"))
        res = self.structure("manual-run/progress.jsonl", "manual-run")
        self.assertEqual(res["source"], "recorded")

    def test_missing_files_are_rebuilt(self):
        res = self.structure("campaigns/finished/progress.jsonl", "normal-s1")
        self.assertEqual(res["source"], "rebuilt")
        ids = {n["id"] for n in res["kg"]["nodes"]}
        self.assertIn("host:firewall", ids)
        self.assertEqual(res["tree"]["attack_tree"]["id"], "impact")

    def test_unknown_or_traversing_runs_refused(self):
        lid = "campaigns/finished/progress.jsonl"
        for run in ("nope-s9", "../live", "..", "manual-hijack-s1/../../live", ""):
            with self.assertRaises(urllib.error.HTTPError, msg=run) as cm:
                self.structure(lid, run)
            self.assertEqual(cm.exception.code, 404)
        with self.assertRaises(urllib.error.HTTPError):
            self.structure("../../etc/progress.jsonl", "x")

    def test_graph_js_served(self):
        status, ctype, body = self.get("/graph.js")
        self.assertEqual(status, 200)
        self.assertIn("javascript", ctype)
        self.assertIn(b"drawTopology", body)


class Trajectories(_Fixture):
    """GET /api/trajectories: what each player of a scored run did, by team. A
    run that kept none answers with none rather than failing: most runs have no
    player at a seat, and the page asks for every scored run it shows."""

    LID, RUN = "campaigns/finished/progress.jsonl", "manual-hijack-s1"

    def put(self, team, doc):
        d = os.path.join(self.root, "campaigns", "finished", "runs", self.RUN)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"trajectory-{team}.json"), "w") as f:
            f.write(doc if isinstance(doc, str) else json.dumps(doc))

    def trajectories(self, lid=LID, run=RUN):
        q = urllib.parse.urlencode({"id": lid, "run": run})
        return json.loads(self.get("/api/trajectories?" + q)[2])["trajectories"]

    def test_a_run_with_no_player_has_none(self):
        self.assertEqual(self.trajectories(), {}, "a run without players is not an error")

    def test_each_players_document_by_its_team(self):
        self.put("red", {"steps": [{"step_id": 1}]})
        self.put("blue", {"steps": []})
        got = self.trajectories()
        self.assertEqual(sorted(got), ["blue", "red"])
        self.assertEqual(got["red"]["steps"][0]["step_id"], 1)

    def test_a_document_written_again_is_read_again(self):
        """A run scored again writes its trajectories again: the page must not
        be handed the ones it was first asked for."""
        self.put("red", {"steps": []})
        self.assertEqual(self.trajectories()["red"]["steps"], [])
        self.put("red", {"steps": [{"step_id": 1}]})
        path = os.path.join(self.root, "campaigns", "finished", "runs", self.RUN)
        os.utime(os.path.join(path, "trajectory-red.json"), (1, 1))
        self.assertEqual(len(self.trajectories()["red"]["steps"]), 1)

    def test_a_document_that_cannot_be_read_does_not_hide_the_other(self):
        self.put("red", "{ cut off")
        self.put("blue", {"steps": []})
        self.assertEqual(sorted(self.trajectories()), ["blue"])

    def test_unknown_or_traversing_runs_refused(self):
        for run in ("nope-s9", "../live", "..", "manual-hijack-s1/../../live", ""):
            with self.assertRaises(urllib.error.HTTPError, msg=run) as cm:
                self.trajectories(run=run)
            self.assertEqual(cm.exception.code, 404, "a run the ledger does not name was served")
        with self.assertRaises(urllib.error.HTTPError):
            self.trajectories(lid="../../etc/progress.jsonl", run="x")


class OtherScenarios(_Fixture):
    """A ledger of another scenario (MQTT) is listed with its scenario and has
    no knowledge-graph structure; older ledgers without one count as CPS."""

    def setUp(self):
        super().setUp()
        run = ProgressLog(os.path.join(self.root, "mqtt", "datasets", "progress.jsonl")).bind(
            run_id="train"
        )
        run.emit("run_start", scenario="mqtt-mtd", mode="dataset", seed=1, phases=[])
        run.emit("mtd_action", action="hop", status="applied", cost=0.45)
        run.emit("run_end", status="ok")
        run._log.close()

    def test_scenario_in_listing_and_no_structure(self):
        led = self.ledgers()
        self.assertEqual(
            led[os.path.join("mqtt", "datasets", "progress.jsonl")]["scenario"], "mqtt-mtd"
        )
        self.assertEqual(led[os.path.join("manual-run", "progress.jsonl")]["scenario"], "cps")
        lid = urllib.parse.quote(os.path.join("mqtt", "datasets", "progress.jsonl"))
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get(f"/api/structure?id={lid}&run=train")
        self.assertEqual(cm.exception.code, 404)


class ScenarioFilter(OtherScenarios):
    """A campaign records which scenario it ran, so showing one scenario is a
    question the dashboard answers — not something the output directory layout
    has to encode by keeping each scenario in its own tree."""

    def test_filtering_keeps_only_that_scenario(self):
        every = {led["scenario"] for led in self.ledgers().values()}
        self.assertEqual({"cps", "mqtt-mtd"}, every, "the fixture should hold both scenarios")

        dash = ProgressDashboard(self.root, port=0, scenario="mqtt-mtd").start()
        try:
            url = f"http://127.0.0.1:{dash.port}/api/ledgers"
            with urllib.request.urlopen(url, timeout=5) as r:
                shown = json.load(r)["ledgers"]
        finally:
            dash.shutdown()
        self.assertTrue(shown, "filtering to a scenario that exists returned nothing")
        self.assertEqual(
            {"mqtt-mtd"},
            {led["scenario"] for led in shown},
            "the filter let another scenario's ledgers through",
        )


class Summary(unittest.TestCase):
    def test_resumed_campaign_counts_current_attempt(self):
        evs = [
            {"kind": "campaign_start", "name": "c", "grid": GRID, "t": 1},
            {"kind": "run_failed", "run_id": "normal-s1"},
            {"kind": "campaign_end", "status": "done_with_failures"},
            {"kind": "campaign_start", "name": "c", "grid": GRID, "t": 2},
            {"kind": "run_metrics", "run_id": "normal-s1"},
        ]
        s = summarize(evs, mtime=time.time())
        self.assertEqual((s["done"], s["failed"], s["status"]), (1, 0, "running"))


class ControlOnlyWatches(unittest.TestCase):
    """The platform's dashboard is the referee's view: it must have no way to
    act on a lab, or it becomes a third team with everyone's access."""

    def test_the_server_has_no_endpoint_that_writes(self):
        with tempfile.TemporaryDirectory() as root:
            dash = ProgressDashboard(root, port=0).start()
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{dash.port}/api/ledgers", data=b"{}", method="POST"
                )
                with self.assertRaises(urllib.error.HTTPError) as refused:
                    urllib.request.urlopen(req, timeout=5)
                self.assertEqual(refused.exception.code, 501)
            finally:
                dash.shutdown()

    def test_the_page_only_ever_reads(self):
        with open(PAGE) as f:
            page = f.read()
        for write in ("method:", "POST", "Authorization"):
            self.assertNotIn(
                write, page, f"the control page can send something ({write!r}): it should only read"
            )


class CoreKnowsNoScenario(unittest.TestCase):
    """The page and its server draw what every scenario has; what only one
    scenario can read lives in that scenario's panel.js."""

    # The single exception: ledgers written before run_start carried `scenario`.
    ALLOWED = {"ledgers.py": {"LEGACY_SCENARIO"}}

    def test_dashboard_sources_name_no_scenario(self):
        import re

        from cyberrange.core import paths, registry

        names = set()
        for name in registry.names():
            names |= {name, name.replace("-", "_"), name.split("-")[0]}
        core = paths.REPO_ROOT / "cyberrange" / "core"
        for fname in ("dashboard.html", "dashboard.py", "ledgers.py"):
            for lineno, line in enumerate((core / fname).read_text().splitlines(), 1):
                if any(tag in line for tag in self.ALLOWED.get(fname, ())):
                    continue
                if line.lstrip().startswith(("#", "//")) or "older ledgers" in line:
                    continue
                for name in names:
                    with self.subTest(file=fname, line=lineno, scenario=name):
                        self.assertIsNone(
                            re.search(rf"\b{re.escape(name)}\b", line, re.IGNORECASE),
                            f"core/{fname}:{lineno} names the scenario {name!r}: a view that "
                            "only one scenario can fill belongs in its panel.js",
                        )


if __name__ == "__main__":
    unittest.main()
