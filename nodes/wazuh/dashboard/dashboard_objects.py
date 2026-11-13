#!/usr/bin/env python3
"""dashboard_objects.py — give the Wazuh dashboard the lab's own views.

The dashboard comes with Wazuh's views of alerts and agents; the lab adds one
of its own, the attack tree coloured by what the SOC believes of each step
(attack-tree.vega.json, a Vega visualization over the soc_belief alerts). A
dashboard keeps its views as saved objects, in the indexer: this waits for the
dashboard to answer and creates them through its saved-objects API, under fixed
ids, so that the team's link to the view is the same at every run.

    OSD_PASSWORD=… dashboard_objects.py --url https://10.30.0.22:5601 \
        --user kibanaserver --ca /pki/root-ca.pem --spec /attack-tree.vega.json

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

VISUALIZATION, DASHBOARD = "cps-attack-tree-vis", "cps-attack-tree"
# The alerts' index pattern, under the id Wazuh's app looks for at its first
# visit: without one the dashboards page only offers to create it, and a team
# following its link to the tree before opening Wazuh's home would land there.
ALERTS = "wazuh-alerts-*"
TITLE = "Attack tree"
WAIT_S = 300.0  # the dashboard answers in seconds; a lab under load takes longer
NO_QUERY = json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})


def objects(spec):
    """The saved objects, as (type, id, body) the API takes. ``spec`` is the
    Vega specification's text."""
    visualization = {
        "attributes": {
            "title": f"{TITLE}: what the SOC believes",
            "description": "Every step of the lab's attack tree, coloured by the SOC's belief",
            "visState": json.dumps(
                {"title": TITLE, "type": "vega", "params": {"spec": spec}, "aggs": []}
            ),
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": NO_QUERY},
        }
    }
    panel = {
        # The panel format's version: the page fails on a panel without one.
        "version": "7.9.3",
        "panelIndex": "1",
        "gridData": {"x": 0, "y": 0, "w": 48, "h": 24, "i": "1"},
        "embeddableConfig": {},
        "panelRefName": "panel_0",
    }
    dashboard = {
        "attributes": {
            "title": TITLE,
            "description": "The attack the SOC is following, on the lab's attack tree",
            "panelsJSON": json.dumps([panel]),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "version": 1,
            # The tree is read up to the end of the range: kept at "now" and
            # refreshed, it follows the attack as the SOC does.
            "timeRestore": True,
            "timeFrom": "now-1h",
            "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 5000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": NO_QUERY},
        },
        "references": [{"name": "panel_0", "type": "visualization", "id": VISUALIZATION}],
    }
    return [("visualization", VISUALIZATION, visualization), ("dashboard", DASHBOARD, dashboard)]


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

    def install(self, spec):
        pattern = {"attributes": {"title": ALERTS, "timeFieldName": "timestamp"}}
        try:
            self.call("POST", f"/api/saved_objects/index-pattern/{ALERTS}", pattern)
        except urllib.error.HTTPError as e:
            # Already there (Wazuh's app made it, with the fields it found): kept.
            if e.code != 409:
                raise
        for kind, ident, body in objects(spec):
            self.call("POST", f"/api/saved_objects/{kind}/{ident}?overwrite=true", body)


def main():
    ap = argparse.ArgumentParser(description="create the lab's views in the Wazuh dashboard")
    ap.add_argument("--url", required=True, help="the dashboard's base URL")
    ap.add_argument("--user", required=True, help="the user the objects are created as")
    ap.add_argument("--ca", default=None, help="the authority the dashboard's certificate is from")
    ap.add_argument("--spec", required=True, help="the attack tree's Vega specification")
    args = ap.parse_args()
    password = os.environ.get("OSD_PASSWORD")
    if not password:
        sys.exit("OSD_PASSWORD is not set")
    with open(args.spec) as f:
        spec = f.read()
    json.loads(spec)  # a broken specification fails here, not as an empty panel
    dashboard = Dashboard(args.url, args.user, password, cafile=args.ca)
    deadline = time.time() + WAIT_S
    while not dashboard.ready():
        if time.time() > deadline:
            sys.exit(f"the dashboard did not answer in {WAIT_S:.0f} s: no view installed")
        time.sleep(2)
    try:
        dashboard.install(spec)
    except urllib.error.HTTPError as e:
        sys.exit(f"the dashboard refused the views: HTTP {e.code} {e.read()[:300]!r}")
    print(f"views installed: {args.url}/app/dashboards#/view/{DASHBOARD}", flush=True)


if __name__ == "__main__":
    main()
