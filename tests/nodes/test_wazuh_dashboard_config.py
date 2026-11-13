"""The Wazuh dashboard's app configuration (nodes/wazuh/dashboard/wazuh.yml)
against the image's entrypoint, which rewrites it at every start.

/wazuh_app_config.sh in wazuh/wazuh-dashboard appends a hosts: block unless the
file already names its host id; the app then refuses the file with two hosts:
keys (error 3019) and the blue team's SIEM shows no Wazuh data at all.

Also the lab's own view in the dashboard, the attack tree: a Vega specification
over the alerts the SOC's belief feed raises (nodes/soc/belief_feed.py through
nodes/wazuh/manager/soc_belief_rules.xml), installed as saved objects by
dashboard_objects.py. Nothing fails loudly when the three drift apart — the
panel is drawn empty — so the fields each one names are checked against the
others here.

Run: `.venv/bin/python -m pytest tests/nodes/test_wazuh_dashboard_config.py`
"""

import json
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from tests.helpers import guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.NODES / "wazuh" / "dashboard")

import belief_feed  # noqa: E402  (flat guest import, needs the path set above)
import dashboard_objects  # noqa: E402  (flat guest import)

from cyberrange.scenarios.cps_soc import scenario as soc_scenario  # noqa: E402  (after the guest path)
from cyberrange.scenarios.cps_soc.guest_files import DASHBOARD_FILES  # noqa: E402  (after the guest path)

NODES = Path(__file__).resolve().parents[2] / "nodes"
CONFIG = NODES / "wazuh/dashboard/wazuh.yml"
SPEC = NODES / "wazuh/dashboard/attack-tree.vega.json"
RULES = NODES / "wazuh/manager/soc_belief_rules.xml"
START = NODES / "wazuh/dashboard/wazuh-dashboard-start.sh"
ENTRYPOINT_HOST_ID = "1513629884013"  # what /wazuh_app_config.sh greps for


def after_entrypoint(text):
    """The file as the image's entrypoint leaves it (its append, not its sed)."""
    if ENTRYPOINT_HOST_ID in text:
        return text
    return text + f"hosts:\n  - {ENTRYPOINT_HOST_ID}:\n      url: https://wazuh\n"


class TestWazuhDashboardConfig(unittest.TestCase):
    def test_entrypoint_leaves_a_single_hosts_key(self):
        text = after_entrypoint(CONFIG.read_text())
        keys = re.findall(r"^hosts:", text, flags=re.MULTILINE)
        self.assertEqual(
            len(keys), 1, "the entrypoint appends a second hosts: and the Wazuh app refuses it"
        )

    def test_points_at_the_soc_manager_api(self):
        text = CONFIG.read_text()
        self.assertIn('url: "https://10.30.0.20"', text, "the app would not reach the manager")
        self.assertIn("port: 55000", text, "the app would not reach the manager's API")


def fed_fields():
    """Every field a belief event can carry."""
    node = {"id": "n", "label": "N", "gate": "LEAF", "attck": "T1190", "children": []}
    view = {
        "structure": {"id": "root", "label": "R", "gate": "OR", "children": [node]},
        "tree": [{"node": "n", "state": "confirmed", "belief": 0.9}],
        "countermeasures": [{"id": "cm", "prevents": ["n"], "in_effect_since": 1.0}],
    }
    return set().union(*belief_feed.rows(view))


class TestAttackTreeView(unittest.TestCase):
    def setUp(self):
        self.text = SPEC.read_text()
        self.spec = json.loads(self.text)
        # The rules file opens with a comment, which a document may not hold twice
        # at its top: wrapped, as the manager reads its rule files.
        self.rules = ET.fromstring(f"<rules>{RULES.read_text()}</rules>")

    def test_the_view_reads_only_what_the_feed_sends(self):
        read = set(re.findall(r"datum\.d\.(\w+)", self.text))
        self.assertTrue(read, "the view no longer reads the alert's fields the way this test looks")
        self.assertFalse(
            read - fed_fields(),
            "the view reads fields the feed never sends: those steps are drawn blank",
        )
        self.assertLessEqual({"node", "parent", "order", "belief"}, read, "no tree can be laid out")

    def test_the_view_asks_for_the_alerts_the_rules_raise(self):
        query = self.spec["data"][0]["url"]
        term = query["body"]["query"]["bool"]["filter"][0]["term"]
        group = self.rules.find("group").get("name").rstrip(",").split(",")
        self.assertIn(term["rule.groups"], group, "the view filters on a group no rule is in")
        self.assertEqual(query["body"]["aggs"]["nodes"]["terms"]["field"], "data.node")
        self.assertEqual(query["index"], dashboard_objects.ALERTS)

    def test_the_tree_is_as_of_the_end_of_the_time_range(self):
        time = self.spec["data"][0]["url"]["body"]["query"]["bool"]["filter"][1]["range"]
        self.assertEqual(
            time["timestamp"],
            {"lte": {"%timefilter%": "max"}},
            "with a lower bound, a step whose belief last changed before the range vanishes",
        )

    def test_every_state_the_soc_can_hold_has_a_colour_and_a_shape(self):
        states = ["confirmed", "inferred", "suspected", belief_feed.UNKNOWN]
        for scale in self.spec["scales"]:
            self.assertEqual(scale["domain"], states, scale["name"])
            self.assertEqual(len(set(scale["range"])), len(states), scale["name"])

    def test_the_rules_match_the_feeds_events(self):
        base, confirmed = self.rules.find("group").findall("rule")
        kind = base.find("field[@name='kind']").text
        self.assertRegex(belief_feed.KIND, kind, "no alert is raised for a belief event")
        self.assertEqual(confirmed.find("if_sid").text, base.get("id"))
        self.assertGreater(int(confirmed.get("level")), int(base.get("level")))
        # $(field) in a description is filled from the event: an absent one is left blank.
        for rule in (base, confirmed):
            named = set(re.findall(r"\$\((\w+)\)", rule.find("description").text))
            self.assertFalse(named - fed_fields(), rule.get("id"))

    def test_the_objects_are_a_dashboard_holding_the_view(self):
        kinds = {kind: (ident, body) for kind, ident, body in dashboard_objects.objects(self.text)}
        vis_id, vis = kinds["visualization"]
        state = json.loads(vis["attributes"]["visState"])
        self.assertEqual(state["type"], "vega")
        self.assertEqual(json.loads(state["params"]["spec"]), self.spec)
        dash_id, dash = kinds["dashboard"]
        self.assertEqual(dash["references"][0]["id"], vis_id, "a dashboard of a missing panel")
        (panel,) = json.loads(dash["attributes"]["panelsJSON"])
        self.assertIn("version", panel, "the dashboards page fails on a panel with no version")
        self.assertEqual(panel["panelRefName"], dash["references"][0]["name"])
        self.assertFalse(dash["attributes"]["refreshInterval"]["pause"], "the tree stands still")

    def test_the_teams_link_is_the_dashboard_the_objects_create(self):
        self.assertTrue(
            soc_scenario.ATTACK_TREE_VIEW.endswith(f"/view/{dashboard_objects.DASHBOARD}"),
            "the blue team's link opens a dashboard that does not exist",
        )

    def test_the_start_script_installs_the_staged_objects(self):
        staged = {guest for _host, guest in DASHBOARD_FILES}
        start = START.read_text()
        for path in ("/dashboard_objects.py", "/attack-tree.vega.json"):
            self.assertIn(path, staged)
            self.assertIn(path, start, f"{path} is staged and never used")


if __name__ == "__main__":
    unittest.main()
