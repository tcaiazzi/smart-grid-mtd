#!/usr/bin/env python3
"""iris_desk.py — the SOC's approval desk on DFIR-IRIS, the blue team's case
management.

The analytics (soc_analytics.py) puts each countermeasure it would run to a
person, through a desk: soc_operator.ApprovalDesk serves it on the SOC's own
console; this desk files it in IRIS instead, where an analyst works. The run
has one case; a suggestion is a task of that case, with the reasons for it. The
analyst approves by closing the task (Done) and rejects by cancelling it
(Canceled); the analytics reads the verdict at its next step. A suggestion left
unanswered expires: the task is cancelled with a note saying so.

The analytics never waits on IRIS: a suggestion IRIS cannot take yet stays
queued here and is filed at a later step, and an unreachable IRIS is logged,
not raised. IRIS takes a few seconds to come up after the SOC does.

The analyst's own initiative goes through IRIS too. The desk files the lab's
countermeasures in the case as a catalogue (one task each), and IRIS's "SOC
response" module (nodes/soar/iris_soc_response/) adds to IRIS's menus "apply" and
"revert" on those tasks, "act alone" and "advise" on the case. Choosing one files
an order task; the desk hands it to the analytics as an order and closes it.

A verdict is attributed to the IRIS account the team works under: IRIS records
who edited a task, but not who changed its status from the task list. An order
names the analyst who chose it.

Copied flat onto the SOC node with iris_orders.py (the order format, shared with
the IRIS module), imported by soc_analytics.py. Stdlib only.
"""

import json
import ssl
import threading
import time
import urllib.error
import urllib.request

import iris_orders

# IRIS's task states (manage/task-status/list).
TODO, ON_HOLD, DONE, CANCELED = 1, 3, 4, 5
# The IRIS module that adds the SOC's levers to IRIS's menus.
MODULE = "iris_soc_response"
# The group whose members may work every case (manage/groups/list).
ADMINISTRATORS = 1
CUSTOMER = 1  # the customer IRIS creates at its first start
POLL_S = 1.0  # how often the tasks are read for verdicts
SUMMARY_S = 10.0  # how often the case's summary is rewritten with the SOC's view


class IrisError(RuntimeError):
    pass


class IrisApi:
    """The few calls of IRIS's REST API the desk needs. ``http`` (method, url,
    headers, body) -> (status, bytes) is injected so a test can stand in for
    IRIS; ``cafile`` is the lab's authority, None trusts any certificate."""

    # IRIS's first requests after it starts can take several seconds.
    def __init__(self, url, key, cafile=None, timeout=20.0, http=None):
        self.url, self.key, self.timeout = url.rstrip("/"), key, timeout
        if http is None:
            context = ssl.create_default_context(cafile=cafile) if cafile else None
            if context is None:
                context = ssl._create_unverified_context()
            else:
                # The lab's certificates name addresses, which is what is dialled.
                context.check_hostname = False
            http = self._urllib(context)
        self.http = http

    def _urllib(self, context):
        def call(method, url, headers, body):
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=context) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()

        return call

    def call(self, method, path, body=None):
        headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}
        data = json.dumps(body).encode() if body is not None else None
        try:
            status, raw = self.http(method, self.url + path, headers, data)
        except OSError as e:
            raise IrisError(f"{method} {path}: {e}") from e
        try:
            doc = json.loads(raw or b"{}")
        except ValueError as e:
            raise IrisError(f"{method} {path}: HTTP {status}, not JSON") from e
        if status >= 400 or doc.get("status") != "success":
            raise IrisError(f"{method} {path}: HTTP {status} {doc.get('message')!r}")
        return doc.get("data")

    def add_case(self, soc_id, name, description):
        body = {
            "case_soc_id": soc_id,
            "case_customer": CUSTOMER,
            "case_name": name,
            "case_description": description,
        }
        return self.call("POST", "/manage/cases/add", body)["case_id"]

    def add_task(self, cid, title, description, tags):
        body = {
            "task_title": title,
            "task_description": description,
            "task_status_id": TODO,
            "task_assignees_id": [],
            "task_tags": ",".join(tags),
            "custom_attributes": {},
        }
        return self.call("POST", f"/case/tasks/add?cid={cid}", body)["id"]

    def tasks(self, cid):
        return self.call("GET", f"/case/tasks/list?cid={cid}")["tasks"]

    def edit_task(self, cid, task, status, description):
        body = {
            "task_title": task["task_title"],
            "task_description": description,
            "task_status_id": status,
            "task_assignees_id": [],
            "task_tags": task.get("task_tags") or "",
            "custom_attributes": {},
        }
        return self.call("POST", f"/case/tasks/update/{task['task_id']}?cid={cid}", body)

    def register_module(self, name):
        """Add an IRIS module, if IRIS has not got it yet."""
        try:
            self.call("POST", "/manage/modules/add", {"module_name": name})
        except IrisError as e:
            if "already exists" not in str(e):
                raise

    def set_summary(self, cid, text):
        return self.call("POST", f"/case/summary/update?cid={cid}", {"case_description": text})

    def ensure_analyst(self, login, password, name):
        """The team's account, created once and able to work every case."""
        users = self.call("GET", "/manage/users/list")
        if any(u.get("user_login") == login for u in users):
            return
        body = {
            "user_name": name,
            "user_login": login,
            "user_email": f"{login}@lab.invalid",
            "user_password": password,
            "user_active": True,
        }
        uid = self.call("POST", "/manage/users/add", body)["id"]
        self.call(
            "POST", f"/manage/users/{uid}/groups/update", {"groups_membership": [ADMINISTRATORS]}
        )


def describe(suggestion):
    """A suggestion as an analyst reads it in the task: what, where, why, at
    what cost, and how to answer."""
    x = suggestion.get("explanation") or {}
    cm = x.get("countermeasure") or {}
    tr = x.get("trigger") or {}

    def nodes(items):
        return "; ".join(
            f"{n.get('label') or n.get('node')}"
            + (f" [{n['attck']}]" if n.get("attck") else "")
            + (f" (belief {n['belief']:.2f})" if isinstance(n.get("belief"), (int, float)) else "")
            for n in items or []
        )

    action = suggestion["action"]
    lines = [
        f"Proposed countermeasure: {cm.get('label') or action} ({action})",
        f"Runs on: {cm.get('machine') or '-'}",
    ]
    if tr.get("klass"):
        seen = tr["klass"] + (f" ({tr['detector']} detector)" if tr.get("detector") else "")
        lines.append(f"Seen: {seen}" + (f" from {tr['src']}" if tr.get("src") else ""))
    if x.get("prevents"):
        lines.append(f"Prevents: {nodes(x['prevents'])}")
    if x.get("restores"):
        lines.append(f"Undoes: {nodes(x['restores'])}")
    if x.get("rationale"):
        lines.append(f"Why: {x['rationale']}")
    if cm.get("commands"):
        lines.append("Commands: " + " | ".join(cm["commands"]))
    if cm.get("d3fend"):
        lines.append(f"D3FEND: {cm['d3fend']}")
    lines.append("")
    lines.append("Approve: set this task to Done. Reject: set it to Canceled.")
    return "\n".join(lines)


class IrisDesk:
    """The desk soc_analytics.Service talks to (open, close, take, take_orders,
    publish), filed in IRIS. ``case`` is (soc id, name) of the run's case;
    ``analyst`` (login, password) the account the team works under, created at
    the first step IRIS answers."""

    def __init__(self, api, case, analyst=None, clock=time.time, log=print):
        self.api, self.case, self.analyst = api, case, analyst
        self.clock, self.log = clock, log
        self._lock = threading.Lock()
        self._cid = None
        self._ready = False
        self._queued = []  # (request, suggestion) not yet filed
        self._tasks = {}  # request -> IRIS task id
        self._pending = {}  # request -> suggestion, waiting for a verdict
        self._verdicts = []
        self._last_poll = 0.0
        self._last_summary = 0.0
        self._catalogue = None  # countermeasure id -> its catalogue task, once filed
        self._orders = []  # orders read from IRIS, for the analytics' next step
        self._taken = set()  # order tasks already handed over

    # ── the desk ─────────────────────────────────────────────────────────────
    def open(self, request, suggestion):
        with self._lock:
            self._pending[request] = suggestion
            self._queued.append((request, suggestion))
        self._sync()

    def close(self, request, state, **fields):
        """The analytics' last word: granted, rejected or expired. Only an
        expiry is written back: the other two are the analyst's own doing."""
        with self._lock:
            suggestion = self._pending.pop(request, None)
            tid = self._tasks.get(request)
        if suggestion is None or state != "expired" or tid is None:
            return
        note = f"\n\nExpired: not answered in {fields.get('waited_s', '?')} s, not applied."
        try:
            task = self._task(tid)
            if task is not None and task.get("task_status_id") == TODO:
                self.api.edit_task(self._cid, task, CANCELED, describe(suggestion) + note)
        except IrisError as e:
            self.log(f"iris: could not mark {request} expired: {e}")

    def take(self):
        self._sync()
        with self._lock:
            out, self._verdicts = self._verdicts, []
            return out

    def take_orders(self):
        """What the analyst ordered from IRIS's menus since the last step."""
        with self._lock:
            out, self._orders = self._orders, []
            return out

    def publish(self, view):
        if self._cid is not None and self._catalogue is None and view.get("countermeasures"):
            try:
                self._file_catalogue(view["countermeasures"])
            except IrisError as e:
                self.log(f"iris: could not file the countermeasures: {e}")
        now = self.clock()
        if self._cid is None or now - self._last_summary < SUMMARY_S:
            return
        self._last_summary = now
        try:
            self.api.set_summary(self._cid, summary(view))
        except IrisError as e:
            self.log(f"iris: could not update the case summary: {e}")

    # ── keeping IRIS in step ─────────────────────────────────────────────────
    def _sync(self):
        """File what is queued and read the verdicts, when IRIS answers."""
        try:
            self._prepare()
            self._file()
            self._poll()
        except IrisError as e:
            self.log(f"iris: {e}")

    def _prepare(self):
        if self._ready:
            return
        if self.analyst:
            login, password = self.analyst
            self.api.ensure_analyst(login, password, f"{login} team")
        try:
            self.api.register_module(MODULE)
        except IrisError as e:
            # Without it the suggestions still work; only the menus are missing.
            self.log(f"iris: the {MODULE} module is not available: {e}")
        soc_id, name = self.case
        self._cid = self.api.add_case(
            soc_id, name, "Countermeasures the SOC's analytics proposes during this run."
        )
        self._ready = True
        # IRIS answers only seconds after it starts, so the warm-up retries above
        # log failures; without this line the log ends on one and a healthy desk
        # reads as a live fault.
        self.log(f"iris: ready — case {soc_id!r} filed as cid {self._cid}")

    def _file(self):
        while True:
            with self._lock:
                if not self._queued:
                    return
                request, suggestion = self._queued[0]
            cm = (suggestion.get("explanation") or {}).get("countermeasure") or {}
            title = f"Approve: {cm.get('label') or suggestion['action']}"
            # A request that timed out may still have created the task: the one
            # already filed under this request is adopted, not filed again.
            tid = self._filed(request)
            if tid is None:
                tid = self.api.add_task(
                    self._cid,
                    title,
                    describe(suggestion),
                    ["cps-soc", suggestion["action"], request],
                )
            with self._lock:
                self._queued.pop(0)
                self._tasks[request] = tid

    def _poll(self):
        now = self.clock()
        with self._lock:
            waiting = {r: self._tasks[r] for r in self._pending if r in self._tasks}
        if now - self._last_poll < POLL_S:
            return
        self._last_poll = now
        tasks = self.api.tasks(self._cid)
        self._take_orders(tasks, now)
        by_id = {t["task_id"]: t for t in tasks}
        who = self.analyst[0] if self.analyst else None
        with self._lock:
            for request, tid in waiting.items():
                status = (by_id.get(tid) or {}).get("task_status_id")
                if status not in (DONE, CANCELED) or request not in self._pending:
                    continue
                verdict = "approve" if status == DONE else "reject"
                self._verdicts.append(
                    {"request": request, "verdict": verdict, "operator": who, "t": round(now, 3)}
                )
                # One verdict per suggestion: the analytics closes it next.
                del self._pending[request]

    def _file_catalogue(self, countermeasures):
        """One task per countermeasure the SOC can run, kept On hold: the menus
        of these tasks are where the analyst applies or reverts one by hand."""
        filed = {}
        for t in self.api.tasks(self._cid):
            cm = iris_orders.countermeasure_of(t.get("task_tags") or "")
            if cm and "catalog" in iris_orders.tags_of(t.get("task_tags")):
                filed[cm] = t["task_id"]
        for cm in countermeasures:
            if cm["id"] in filed:
                continue
            lines = [
                f"Runs on: {cm.get('machine') or '-'}",
                "Applies: " + " | ".join(cm.get("commands") or []),
                "Reverts: " + (" | ".join(cm.get("revert") or []) or "nothing to undo"),
            ]
            if cm.get("d3fend"):
                lines.append(f"D3FEND: {cm['d3fend']}")
            lines += ["", "Apply or revert it from this task's menu: SOC: apply / revert."]
            body = {
                "task_title": f"Countermeasure: {cm.get('label') or cm['id']}",
                "task_description": "\n".join(lines),
                "task_status_id": ON_HOLD,
                "task_assignees_id": [],
                "task_tags": ",".join([iris_orders.TAG, "catalog", cm["id"]]),
                "custom_attributes": {},
            }
            filed[cm["id"]] = self.api.call("POST", f"/case/tasks/add?cid={self._cid}", body)["id"]
        self._catalogue = filed

    def _take_orders(self, tasks, now):
        """Hand the order tasks the analyst filed over to the analytics, once
        each, and close them: Done when the SOC can carry them out, Canceled
        (with the reason) when the countermeasure is not one of the lab's."""
        known = set(self._catalogue or ())
        for t in tasks:
            order = iris_orders.parse_order(t.get("task_tags") or "")
            if order is None or t["task_id"] in self._taken or t.get("task_status_id") != TODO:
                continue
            self._taken.add(t["task_id"])
            if order["kind"] == "countermeasure" and known and order["id"] not in known:
                note = f"\n\nRefused: {order['id']} is not a countermeasure of this lab."
                self.api.edit_task(self._cid, t, CANCELED, (t.get("task_description") or "") + note)
                continue
            with self._lock:
                self._orders.append({**order, "t": round(now, 3)})
            note = "\n\nTaken by the SOC; the outcome is in the case summary."
            self.api.edit_task(self._cid, t, DONE, (t.get("task_description") or "") + note)

    def _filed(self, request):
        """The id of the task already filed for ``request``, if any."""
        for t in self.api.tasks(self._cid):
            if request in (t.get("task_tags") or "").split(","):
                return t["task_id"]
        return None

    def _task(self, tid):
        return next((t for t in self.api.tasks(self._cid) if t["task_id"] == tid), None)


def summary(view):
    """The SOC's view as the case's summary (Markdown): what it believes of the
    attack, what it has done."""
    lines = ["### What the SOC believes", ""]
    tree = [n for n in view.get("tree") or [] if n.get("state") not in (None, "unknown")]
    if tree:
        for n in sorted(tree, key=lambda n: -(n.get("belief") or 0)):
            name = n.get("label") or n.get("node")
            lines.append(f"- **{name}**: {n['state']} ({n.get('belief') or 0:.2f})")
    else:
        lines.append("- nothing yet")
    done = [a for a in view.get("actions") or [] if a.get("ok")]
    lines += ["", "### Countermeasures run", ""]
    lines += [f"- {a.get('id')} on {a.get('machine') or '-'}" for a in done] or ["- none yet"]
    return "\n".join(lines)
