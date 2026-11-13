"""The SOC's approval desk on DFIR-IRIS (nodes/soc/iris_desk.py).

The SOC's analytics puts each countermeasure to a person through a desk; this
one files it as a task of the run's IRIS case and reads the analyst's verdict
from the task's state. A fake IRIS stands in for the real one, answering the
endpoints the cps-soc spike exercised against IRIS v2.4.29 (case, task, task
list, task edit, summary, users).

Run: `.venv/bin/python -m pytest tests/nodes/test_iris_desk.py`
"""

import json
import unittest
from urllib.parse import parse_qs, urlparse

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)
# Staged on the SOC as /iris_orders.py (cps_soc.guest_files.SOC_SIEM_FILES).
guest_paths.alias(guest_paths.SOAR / "iris_soc_response" / "orders.py", "iris_orders")

import iris_desk as D  # noqa: E402  (flat guest import, needs the path set above)


class FakeIris:
    """IRIS's API as far as the desk uses it. ``down`` makes every call fail as
    an unreachable server does."""

    def __init__(self):
        self.down = False
        self.cases, self.tasks, self.users, self.calls = {}, {}, [], []
        self.modules = []
        self.summary = None

    def __call__(self, method, url, headers, body):
        if self.down:
            raise ConnectionRefusedError("IRIS is not up yet")
        u = urlparse(url)
        cid = int(parse_qs(u.query).get("cid", ["0"])[0])
        doc = json.loads(body) if body else None
        self.calls.append((method, u.path))
        ok = lambda data: (200, json.dumps({"status": "success", "data": data}).encode())  # noqa: E731
        if u.path == "/manage/cases/add":
            assert len(doc["case_description"]) >= 2, "IRIS refuses a shorter description"
            case_id = len(self.cases) + 2  # IRIS's own demo case is 1
            self.cases[case_id] = doc
            return ok({"case_id": case_id})
        if u.path == "/case/tasks/add":
            tid = len(self.tasks) + 1
            self.tasks[tid] = {"task_id": tid, "case": cid, **doc}
            return ok({"id": tid})
        if u.path == "/case/tasks/list":
            return ok({"tasks": [t for t in self.tasks.values() if t["case"] == cid]})
        if u.path.startswith("/case/tasks/update/"):
            tid = int(u.path.rsplit("/", 1)[1])
            self.tasks[tid].update(doc)
            return ok({"id": tid})
        if u.path == "/case/summary/update":
            self.summary = doc["case_description"]
            return ok(0)
        if u.path == "/manage/users/list":
            return ok([{"user_login": u} for u in self.users])
        if u.path == "/manage/users/add":
            self.users.append(doc["user_login"])
            return ok({"id": len(self.users) + 1})
        if u.path.endswith("/groups/update"):
            return ok({})
        if u.path == "/manage/modules/add":
            self.modules.append(doc["module_name"])
            return ok({"id": len(self.modules)})
        return 404, json.dumps({"status": "error", "message": "Resource not found"}).encode()

    def set_status(self, tid, status):
        """What the analyst does in IRIS's task list."""
        self.tasks[tid]["task_status_id"] = status


SUGGESTION = {
    "action": "block_flow",
    "requested_t": 10.0,
    "due_t": 70.0,
    "explanation": {
        "rationale": "cuts the HMI's path to the plant",
        "trigger": {"klass": "unexpected_modbus_client", "detector": "it", "src": "10.10.0.20"},
        "prevents": [{"node": "pivot", "label": "Pivot to the plant", "belief": 0.5}],
        "countermeasure": {"label": "Block the HMI's Modbus flow", "machine": "firewall"},
    },
}


class TheDesk(unittest.TestCase):
    def setUp(self):
        self.iris = FakeIris()
        self.now = [100.0]
        self.logged = []
        api = D.IrisApi("https://iris.lab", "key", http=self.iris)
        self.desk = D.IrisDesk(
            api, ("run-1", "SOC suggestions — run-1"), analyst=("blue", "Pw-1234567890Aa1"),
            clock=lambda: self.now[0], log=self.logged.append,
        )  # fmt: skip

    def tick(self, s=2.0):
        self.now[0] += s

    def test_a_suggestion_becomes_a_task_of_the_runs_case(self):
        self.desk.open("r1", SUGGESTION)
        (case,) = self.iris.cases.values()
        self.assertEqual(case["case_soc_id"], "run-1")
        (task,) = self.iris.tasks.values()
        self.assertEqual(task["task_title"], "Approve: Block the HMI's Modbus flow")
        self.assertEqual(task["task_status_id"], D.TODO)
        self.assertIn("Why: cuts the HMI's path to the plant", task["task_description"])
        self.assertIn("Approve: set this task to Done", task["task_description"])
        self.assertIn("r1", task["task_tags"], "the task must name the request it answers")
        self.assertEqual(self.iris.users, ["blue"], "the team's account was not created")

    def test_closing_the_task_approves_once(self):
        self.desk.open("r1", SUGGESTION)
        self.assertEqual(self.desk.take(), [], "a verdict nobody gave")
        self.iris.set_status(1, D.DONE)
        self.tick()
        (v,) = self.desk.take()
        self.assertEqual((v["request"], v["verdict"], v["operator"]), ("r1", "approve", "blue"))
        self.tick()
        self.assertEqual(self.desk.take(), [], "one task approved twice runs it twice")

    def test_cancelling_the_task_rejects(self):
        self.desk.open("r1", SUGGESTION)
        self.iris.set_status(1, D.CANCELED)
        self.tick()
        self.assertEqual([v["verdict"] for v in self.desk.take()], ["reject"])

    def test_an_expired_suggestion_is_cancelled_with_a_note(self):
        self.desk.open("r1", SUGGESTION)
        self.desk.close("r1", "expired", waited_s=60.0)
        task = self.iris.tasks[1]
        self.assertEqual(task["task_status_id"], D.CANCELED)
        self.assertIn("Expired: not answered in 60.0 s", task["task_description"])
        self.iris.set_status(1, D.DONE)  # the analyst, too late
        self.tick()
        self.assertEqual(self.desk.take(), [], "an expired suggestion must stay unapplied")

    def test_an_unreachable_iris_delays_the_task_and_never_raises(self):
        self.iris.down = True
        self.desk.open("r1", SUGGESTION)  # must not raise into the SOC's step
        self.assertEqual(self.desk.take(), [])
        self.assertTrue(self.logged, "the failure must be in the SOC's log")
        self.iris.down = False
        self.tick()
        self.desk.take()
        self.assertEqual(len(self.iris.tasks), 1, "the suggestion was lost while IRIS was down")
        self.assertEqual(len(self.iris.cases), 1)

    def test_a_task_iris_created_before_timing_out_is_not_filed_twice(self):
        """IRIS is slow on its first requests: the task exists, the answer never
        came. The next step must adopt that task, or the analyst sees the same
        suggestion several times and its verdict is read off only one of them."""
        real = self.iris.__call__
        timed_out = []

        def slow(method, url, headers, body):
            status, raw = real(method, url, headers, body)
            if "/case/tasks/add" in url and not timed_out:
                timed_out.append(url)
                raise TimeoutError("The read operation timed out")
            return status, raw

        self.desk.api.http = slow
        self.desk.open("r1", SUGGESTION)
        self.assertTrue(timed_out)
        self.tick()
        self.desk.take()
        self.assertEqual(len(self.iris.tasks), 1, "the suggestion was filed twice")
        self.iris.set_status(1, D.DONE)
        self.tick()
        self.assertEqual([v["verdict"] for v in self.desk.take()], ["approve"])

    def test_the_case_summary_is_the_attack_tree_with_the_socs_belief(self):
        self.desk.open("r1", SUGGESTION)
        leaf = {"gate": "LEAF", "children": []}
        view = {
            "structure": {
                "id": "impact", "label": "Impact", "gate": "OR", "attck": None,
                "children": [
                    {"id": "via_hmi", "label": "Through the HMI", "gate": "AND", "attck": None,
                     "children": [
                         {"id": "it_access", "label": "Web access", "attck": "T1190", **leaf},
                         {"id": "pivot", "label": "Pivot", "attck": None, **leaf},
                     ]},
                ],
            },
            "tree": [{"node": "pivot", "label": "Pivot", "state": "suspected", "belief": 0.5}],
            "countermeasures": [
                {"id": "block_flow", "prevents": ["pivot"], "restores": [], "in_effect_since": 9.0},
                {"id": "isolate_hmi", "prevents": ["it_access"], "in_effect_since": None},
            ],
            "actions": [{"id": "block_flow", "machine": "firewall", "ok": True}],
        }  # fmt: skip
        self.tick(D.SUMMARY_S)
        self.desk.publish(view)
        lines = self.iris.summary.splitlines()
        tree = [ln for ln in lines if ln.lstrip().startswith("- ") and "**" in ln]
        # The nesting is the tree's: IRIS's Markdown nests a list at four spaces.
        self.assertEqual(
            [len(ln) - len(ln.lstrip()) for ln in tree],
            [0, 4, 8, 8],
            "the tree reads as a flat list: a step no longer shows what it is a step of",
        )
        self.assertIn("**Impact** (OR)", tree[0])
        self.assertIn("**Through the HMI** (AND)", tree[1])
        self.assertTrue(
            tree[2].endswith("**Web access** [T1190]"), "an unseen step claims a belief"
        )
        # As code: IRIS's Markdown reads the underscores of a bare id as emphasis.
        self.assertIn("**Pivot**: suspected (0.50) — countered by `block_flow`", tree[3])
        self.assertNotIn("isolate_hmi", self.iris.summary, "a countermeasure not in effect")
        self.assertIn("`block_flow` on firewall", self.iris.summary)

    def test_a_summary_before_any_view_of_the_tree_says_so(self):
        self.assertIn("- nothing yet", D.summary({}))

    def file_order(self, tags):
        """What IRIS's SOC response module does when the analyst picks an entry."""
        tid = len(self.iris.tasks) + 1
        case = next(iter(self.iris.cases))
        self.iris.tasks[tid] = {"task_id": tid, "case": case, "task_title": "Order",
                                "task_description": "", "task_status_id": D.TODO,
                                "task_tags": ",".join(tags)}  # fmt: skip
        return tid

    def test_the_module_and_the_catalogue_are_filed_once(self):
        self.desk.open("r1", SUGGESTION)
        self.assertEqual(self.iris.modules, [D.MODULE], "IRIS's menus would lack the SOC's levers")
        cms = [
            {"id": "block_flow", "label": "Block the flow", "machine": "firewall",
             "commands": ["iptables -I FORWARD 1 -j DROP"], "revert": ["iptables -D FORWARD 1"]},
            {"id": "isolate_hmi", "label": "Isolate the HMI", "machine": "hmi", "commands": ["x"]},
        ]  # fmt: skip
        self.desk.publish({"countermeasures": cms})
        self.desk.publish({"countermeasures": cms})
        catalogue = [t for t in self.iris.tasks.values() if "catalog" in t["task_tags"]]
        self.assertEqual(
            sorted(t["task_tags"] for t in catalogue),
            ["cps-soc,catalog,block_flow", "cps-soc,catalog,isolate_hmi"],
        )
        self.assertTrue(all(t["task_status_id"] == D.ON_HOLD for t in catalogue))
        self.assertIn("Reverts: iptables -D FORWARD 1", catalogue[0]["task_description"])

    def test_an_order_from_irises_menu_is_handed_over_once_and_closed(self):
        self.desk.open("r1", SUGGESTION)
        self.desk.publish({"countermeasures": [{"id": "block_flow", "machine": "firewall"}]})
        tid = self.file_order(["cps-soc", "order", "revert", "block_flow", "by:ada"])
        self.tick()
        self.desk.take()
        (order,) = self.desk.take_orders()
        self.assertEqual(
            (order["kind"], order["op"], order["id"], order["operator"]),
            ("countermeasure", "revert", "block_flow", "ada"),
        )
        self.assertEqual(self.iris.tasks[tid]["task_status_id"], D.DONE)
        self.tick()
        self.desk.take()
        self.assertEqual(self.desk.take_orders(), [], "one order carried out twice")

    def test_an_order_for_another_labs_countermeasure_is_refused(self):
        self.desk.open("r1", SUGGESTION)
        self.desk.publish({"countermeasures": [{"id": "block_flow", "machine": "firewall"}]})
        tid = self.file_order(["cps-soc", "order", "apply", "wipe_everything", "by:ada"])
        self.tick()
        self.desk.take()
        self.assertEqual(self.desk.take_orders(), [])
        self.assertEqual(self.iris.tasks[tid]["task_status_id"], D.CANCELED)
        self.assertIn("not a countermeasure of this lab", self.iris.tasks[tid]["task_description"])

    def test_a_mode_order_switches_the_soc(self):
        self.desk.open("r1", SUGGESTION)
        self.file_order(["cps-soc", "order", "mode", "auto", "by:ada"])
        self.tick()
        self.desk.take()
        self.assertEqual(
            [(o["kind"], o["mode"], o["operator"]) for o in self.desk.take_orders()],
            [("mode", "auto", "ada")],
        )


class TheService(unittest.TestCase):
    """The analytics with this desk: nothing runs until the analyst closes the
    task in IRIS, and then exactly what the task proposed runs."""

    def test_the_soc_runs_what_the_analyst_approved_in_iris(self):
        import soc_analytics as A

        from cyberrange.scenarios.cps import inventory as cps_inv
        from tests.helpers.soar import HMI, finding

        iris = FakeIris()
        now = [1000.0]
        desk = D.IrisDesk(
            D.IrisApi("https://iris.lab", "key", http=iris), ("run-1", "case"),
            clock=lambda: now[0], log=lambda *_: None,
        )  # fmt: skip
        rec = A.JsonlRecorder(None)
        engine = A.ResponseEngine(
            "rules", A.kgmod.build_kg(cps_inv.inventory()), approval="operator:60", record=rec
        )
        follower, manager = _Follower(), _Manager()
        service = A.Service(
            engine, follower, manager, rec, approval="operator:60", clock=lambda: now[0],
            desk=desk,
        )  # fmt: skip
        body = finding("policy_violation", 1.0, HMI, "switch_cmd", value=1.0)
        follower.queue.append(
            {"rule": {"id": "100100"}, "timestamp": "", "full_log": json.dumps(body)}
        )
        service.step()
        self.assertTrue(iris.tasks, "the suggestion never reached IRIS")
        self.assertEqual(manager.requests, [], "an advising SOC ran what nobody approved")
        suggestions = {
            tid: t for tid, t in iris.tasks.items() if "catalog" not in t["task_tags"].split(",")
        }
        proposed = {t["task_tags"].split(",")[1] for t in suggestions.values()}
        for tid in suggestions:
            iris.set_status(tid, D.DONE)
        now[0] += 2
        service.step()
        self.assertEqual({cm for _agent, cm in manager.requests}, proposed)
        granted = [r for r in rec.rows if r["kind"] == "approval" and r["state"] == "granted"]
        self.assertEqual(len(granted), len(proposed), "the ledger would miss an answer")


class TheServiceTakesOrders(unittest.TestCase):
    def test_a_countermeasure_ordered_from_iris_runs_on_its_host(self):
        import soc_analytics as A

        from cyberrange.scenarios.cps import inventory as cps_inv

        iris = FakeIris()
        now = [1000.0]
        desk = D.IrisDesk(
            D.IrisApi("https://iris.lab", "key", http=iris), ("run-1", "case"),
            clock=lambda: now[0], log=lambda *_: None,
        )  # fmt: skip
        rec = A.JsonlRecorder(None)
        engine = A.ResponseEngine(
            "rules", A.kgmod.build_kg(cps_inv.inventory()), approval="operator:60", record=rec
        )
        manager = _Manager()
        service = A.Service(
            engine, _Follower(), manager, rec, approval="operator:60", clock=lambda: now[0],
            desk=desk,
        )  # fmt: skip
        service.step()  # IRIS answers: the case and the catalogue are filed
        self.assertTrue(any("catalog" in t["task_tags"] for t in iris.tasks.values()))
        case = next(iter(iris.cases))
        tid = len(iris.tasks) + 1
        iris.tasks[tid] = {"task_id": tid, "case": case, "task_title": "Order: apply block_flow",
                           "task_description": "", "task_status_id": D.TODO,
                           "task_tags": "cps-soc,order,apply,block_flow,by:ada"}  # fmt: skip
        now[0] += 2
        service.step()
        self.assertEqual([cm for _agent, cm in manager.requests], ["block_flow"])
        self.assertEqual(iris.tasks[tid]["task_status_id"], D.DONE)


class _Follower:
    def __init__(self):
        self.queue = []

    def poll(self):
        out, self.queue = self.queue, []
        return out


class _Manager:
    """The Wazuh manager's API: one agent per host, every response recorded."""

    def __init__(self):
        self.requests = []

    def agents(self):
        return {"sensor": "001", "hmi": "002", "firewall": "003"}

    def active_response(self, agent_id, arguments):
        self.requests.append((agent_id, arguments[1]))


if __name__ == "__main__":
    unittest.main()
