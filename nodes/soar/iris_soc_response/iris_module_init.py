"""iris_module_init.py — the package root of iris_soc_response, a DFIR-IRIS
module that puts the SOC's levers in IRIS's own menus.

An analyst working a case in IRIS can order the cps-soc lab's SOC to apply or
revert a countermeasure, or to act alone or advise, without leaving IRIS: the
module adds those entries to the menus of the case and of its countermeasure
tasks. Choosing one files an order as a task of the case; the SOC's analytics,
which follows the case (nodes/soc/iris_desk.py), carries it out and closes it.
IRIS is the only channel: IRIS's worker never reaches the SOC.

Copied onto IRIS's app and worker nodes as the package's __init__.py and found
on their PYTHONPATH; IRIS imports it by name when the SOC registers it. On the
host it is iris_module_init.py: nodes/ holds no Python package.
"""

# IRIS loads the module through this attribute (module_handler.instantiate_module_from_name).
__iris_module_interface = "IrisSocResponse"
