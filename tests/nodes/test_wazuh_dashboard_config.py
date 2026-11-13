"""The Wazuh dashboard's app configuration (nodes/wazuh/dashboard/wazuh.yml)
against the image's entrypoint, which rewrites it at every start.

/wazuh_app_config.sh in wazuh/wazuh-dashboard appends a hosts: block unless the
file already names its host id; the app then refuses the file with two hosts:
keys (error 3019) and the blue team's SIEM shows no Wazuh data at all.

Run: `.venv/bin/python -m pytest tests/nodes/test_wazuh_dashboard_config.py`
"""

import re
import unittest
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[2] / "nodes/wazuh/dashboard/wazuh.yml"
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


if __name__ == "__main__":
    unittest.main()
