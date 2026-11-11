"""Tests for the platform progress dashboard server (cyberrange/core/dashboard.py): a
real HTTP server on a free port over a temporary root holding fake ledgers —
a finished campaign, a running one, an interrupted one, a standalone run.

Checks ledger discovery and derived status, incremental event paging with
`since` (including a ledger growing between polls and a partial last line),
that only discovered ledgers are served (no path traversal), and that the page
is served.

Run: `.venv/bin/python -m unittest tests.test_dashboard`.
"""

import json
import os
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request


from cyberrange.core.dashboard import ProgressDashboard, summarize  # noqa: E402
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
        self.assertEqual(res2, {"next": n, "events": []})
        log = ProgressLog(self.live)  # the campaign moves on
        log.emit("aggregate", detection=[], impact=[])
        log.close()
        with open(self.live, "a") as f:
            f.write('{"seq": 99, "kind": "half')  # mid-write line
        res3 = json.loads(self.get(q + f"&since={n}")[2])
        self.assertEqual([e["kind"] for e in res3["events"]], ["aggregate"])
        self.assertEqual(res3["next"], n + 1)

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


if __name__ == "__main__":
    unittest.main()
