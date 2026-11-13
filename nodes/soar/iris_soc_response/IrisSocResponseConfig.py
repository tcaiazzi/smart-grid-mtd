"""IrisSocResponseConfig.py — what IRIS shows of the module, and its settings."""

module_name = "SOC response"
module_description = (
    "Orders the lab's SOC to apply or revert a countermeasure, or to act alone or "
    "advise, from the menus of the case and of its countermeasure tasks"
)
interface_version = "1.2.0"  # iris_interface as installed in IRIS v2.4.29
module_version = "0.1.0"
pipeline_support = False
pipeline_info = {}
module_configuration = [
    {
        "param_name": "orders_enabled",
        "param_human_name": "Orders enabled",
        "param_description": "File the orders chosen from the menus. Off, the entries do nothing.",
        "default": True,
        "mandatory": True,
        "type": "bool",
    }
]
