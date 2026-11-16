"""guest_files.py — what the cps-soc scenario stages on top of the cps lab.

The lab is the cps scenario's, the team access the cps-advisor one's, and so
are their manifests. Listed here is only what the SOC's own tools add: the
alert shipper, the IRIS desk and the feed of the attack tree's belief on the SOC,
and the configuration and start script of each new node's service. The services
themselves come with their images (docker/wazuh-*, docker/iris-*).
"""

# SOC node (kathara/soc-siem): the analytics' IRIS desk, and the shipper that
# puts the manager's alerts in the indexer.
SOC_SIEM_FILES = [
    ("nodes/soc/iris_desk.py", "/iris_desk.py"),
    # The order format, shared with the IRIS module below: one file, two nodes.
    ("nodes/soar/iris_soc_response/orders.py", "/iris_orders.py"),
    ("nodes/wazuh/manager/filebeat.yml", "/filebeat.yml"),
    ("nodes/wazuh/manager/wazuh-shipper-start.sh", "/wazuh-shipper-start.sh"),
    # The manager's integration that turns the alerts worth triage into IRIS alerts.
    ("nodes/wazuh/manager/iris_forward.py", "/iris_forward.py"),
    ("nodes/wazuh/manager/wazuh-iris-integration.sh", "/wazuh-iris-integration.sh"),
    # The belief on the attack tree, for the SIEM: the analytics' feed of it to
    # the manager, and the rules that make alerts of it.
    ("nodes/soc/belief_feed.py", "/belief_feed.py"),
    ("nodes/wazuh/manager/soc_belief_rules.xml", "/soc_belief_rules.xml"),
]

# Wazuh indexer (kathara/wazuh-indexer).
INDEXER_FILES = [
    ("nodes/wazuh/indexer/opensearch.yml", "/opensearch.yml"),
    ("nodes/wazuh/indexer/wazuh-indexer-start.sh", "/wazuh-indexer-start.sh"),
]

# Wazuh dashboard (kathara/wazuh-dashboard).
DASHBOARD_FILES = [
    ("nodes/wazuh/dashboard/opensearch_dashboards.yml", "/opensearch_dashboards.yml"),
    ("nodes/wazuh/dashboard/wazuh.yml", "/wazuh.yml"),
    ("nodes/wazuh/dashboard/wazuh-dashboard-start.sh", "/wazuh-dashboard-start.sh"),
    # The lab's own views, the attack tree and the knowledge graph, and what
    # creates them in the dashboard.
    ("nodes/wazuh/dashboard/attack-tree.vega.json", "/attack-tree.vega.json"),
    ("nodes/wazuh/dashboard/knowledge-graph.vega.json", "/knowledge-graph.vega.json"),
    ("nodes/wazuh/dashboard/dashboard_objects.py", "/dashboard_objects.py"),
]

# Every DFIR-IRIS node: the one script that starts its service.
IRIS_FILES = [("nodes/soar/iris-start.sh", "/iris-start.sh")]

# IRIS's app and worker: the module that adds the SOC's levers to IRIS's menus, a
# package IRIS imports by name from the PYTHONPATH the scenario gives them. Its
# __init__.py is kept under another name on the host: nodes/ holds no package
# (tests/core/test_layering.py), and only the guest path is a contract.
IRIS_MODULE_FILES = [
    (
        "nodes/soar/iris_soc_response/iris_module_init.py",
        "/iris_modules/iris_soc_response/__init__.py",
    )
] + [
    (f"nodes/soar/iris_soc_response/{name}.py", f"/iris_modules/iris_soc_response/{name}.py")
    for name in ("IrisSocResponse", "IrisSocResponseConfig", "orders")
]
