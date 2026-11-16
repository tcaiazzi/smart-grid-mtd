#!/usr/bin/env python3
"""dashboard_objects.py — give the Wazuh dashboard the lab's own views.

The dashboard comes with Wazuh's views of alerts and agents; the lab adds two
of its own on one dashboard: the attack tree coloured by what the SOC believes
of each step, and the knowledge graph with what the attack touches of it
(attack-tree.vega.json and knowledge-graph.vega.json, Vega visualizations over
the alerts of the SOC's belief feed). A dashboard keeps its views as saved
objects, in the indexer: this waits for the dashboard to answer and creates
them through its saved-objects API, under fixed ids, so that the team's link to
the dashboard is the same at every run.

    OSD_PASSWORD=… dashboard_objects.py --url https://10.30.0.22:5601 \
        --user kibanaserver --ca /pki/root-ca.pem [--specs /]

Copied flat onto the dashboard node and run by wazuh-dashboard-start.sh. Stdlib
only, and written for the image's Python (3.9).
"""

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

DASHBOARD = "cps-attack-tree"
TITLE = "Attack tree and knowledge graph"
# The lab's views, top to bottom on the dashboard: (visualization id, title,
# description, the staged Vega specification, height in the dashboard's rows).
VIEWS = (
    (
        "cps-attack-tree-vis",
        "Attack tree: what the SOC believes",
        "Every step of the lab's attack tree, coloured by the SOC's belief",
        "attack-tree.vega.json",
        24,
    ),
    (
        "cps-knowledge-graph-vis",
        "Knowledge graph: what the attack touches",
        "The lab as the SOC knows it, with what the attack and the response make of it",
        "knowledge-graph.vega.json",
        21,
    ),
)
# The alerts' index pattern, under the id Wazuh's app looks for at its first
# visit: without one the dashboards page only offers to create it, and a team
# following its link to the tree before opening Wazuh's home would land there.
ALERTS = "wazuh-alerts-*"
WAIT_S = 300.0  # the dashboard answers in seconds; a lab under load takes longer
NO_QUERY = json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})


def objects(specs):
    """The saved objects, as (type, id, body) the API takes. ``specs`` is
    {file name: the text of that Vega specification}, one per VIEWS entry."""
    out, panels, references, y = [], [], [], 0
    for n, (ident, title, description, spec, height) in enumerate(VIEWS):
        state = {"title": title, "type": "vega", "params": {"spec": specs[spec]}, "aggs": []}
        visualization = {
            "attributes": {
                "title": title,
                "description": description,
                "visState": json.dumps(state),
                "uiStateJSON": "{}",
                "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": NO_QUERY},
            }
        }
        out.append(("visualization", ident, visualization))
        panels.append(
            {
                # The panel format's version: the page fails on a panel without one.
                "version": "7.9.3",
                "panelIndex": str(n + 1),
                "gridData": {"x": 0, "y": y, "w": 48, "h": height, "i": str(n + 1)},
                "embeddableConfig": {},
                "panelRefName": f"panel_{n}",
            }
        )
        references.append({"name": f"panel_{n}", "type": "visualization", "id": ident})
        y += height
    dashboard = {
        "attributes": {
            "title": TITLE,
            "description": "The attack the SOC is following, on its attack tree and on the lab",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "version": 1,
            # The views are read up to the end of the range: kept at "now" and
            # refreshed, they follow the attack as the SOC does.
            "timeRestore": True,
            "timeFrom": "now-1h",
            "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 5000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": NO_QUERY},
        },
        "references": references,
    }
    return out + [("dashboard", DASHBOARD, dashboard)]


def read_specs(directory):
    """{file name: text} of the views' specifications staged in ``directory``.
    A broken one fails here, not as an empty panel."""
    specs = {}
    for _ident, _title, _description, name, _height in VIEWS:
        with open(os.path.join(directory, name)) as f:
            specs[name] = f.read()
        json.loads(specs[name])
    return specs


class Dashboard:
    """The dashboard's HTTP API, as one of the indexer's users."""

    def __init__(self, url, user, password, cafile=None):
        self.url = url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "osd-xsrf": "true",  # the API refuses a write without it
        }
        self.tls = ssl.create_default_context(cafile=cafile)

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        for k, v in self.headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=20, context=self.tls) as r:
            return json.loads(r.read() or b"{}")

    def ready(self):
        try:
            status = self.call("GET", "/api/status")
        except (OSError, ValueError):
            return False
        return ((status.get("status") or {}).get("overall") or {}).get("state") == "green"

    def install(self, specs):
        pattern = {"attributes": {"title": ALERTS, "timeFieldName": "timestamp"}}
        try:
            self.call("POST", f"/api/saved_objects/index-pattern/{ALERTS}", pattern)
        except urllib.error.HTTPError as e:
            # Already there (Wazuh's app made it, with the fields it found): kept.
            if e.code != 409:
                raise
        for kind, ident, body in objects(specs):
            self.call("POST", f"/api/saved_objects/{kind}/{ident}?overwrite=true", body)


def main():
    ap = argparse.ArgumentParser(description="create the lab's views in the Wazuh dashboard")
    ap.add_argument("--url", required=True, help="the dashboard's base URL")
    ap.add_argument("--user", required=True, help="the user the objects are created as")
    ap.add_argument("--ca", default=None, help="the authority the dashboard's certificate is from")
    ap.add_argument("--specs", default="/", help="where the views' Vega specifications are")
    args = ap.parse_args()
    password = os.environ.get("OSD_PASSWORD")
    if not password:
        sys.exit("OSD_PASSWORD is not set")
    specs = read_specs(args.specs)
    dashboard = Dashboard(args.url, args.user, password, cafile=args.ca)
    deadline = time.time() + WAIT_S
    while not dashboard.ready():
        if time.time() > deadline:
            sys.exit(f"the dashboard did not answer in {WAIT_S:.0f} s: no view installed")
        time.sleep(2)
    try:
        dashboard.install(specs)
    except urllib.error.HTTPError as e:
        sys.exit(f"the dashboard refused the views: HTTP {e.code} {e.read()[:300]!r}")
    print(f"views installed: {args.url}/app/dashboards#/view/{DASHBOARD}", flush=True)


if __name__ == "__main__":
    main()
