"""The order format of IRIS's SOC response module (nodes/soar/iris_soc_response/
orders.py), which the module writes and the SOC's desk reads.

The module itself runs only inside IRIS (it imports IRIS's data model); what its
menu entries order is decided here, where IRIS does not run, and checked against
what the desk understands: the same file is staged on both sides.

Run: `.venv/bin/python -m pytest tests/nodes/test_iris_module.py`
"""

import unittest

from tests.helpers import guest_paths

orders = guest_paths.alias(guest_paths.SOAR / "iris_soc_response" / "orders.py", "iris_orders")


class Orders(unittest.TestCase):
    def test_every_entry_is_on_a_hook_iris_has(self):
        hooks = {hook for hook, _entry in orders.ENTRIES}
        self.assertEqual(hooks, {"on_manual_trigger_task", "on_manual_trigger_case"})
        names = [entry for _hook, entry in orders.ENTRIES]
        self.assertEqual(len(names), len(set(names)), "two entries with one name in IRIS's menu")

    def test_apply_on_a_catalogue_task_round_trips(self):
        title, tags = orders.order_of(orders.APPLY, "cps-soc,catalog,isolate_hmi")
        self.assertEqual(title, "Order: apply isolate_hmi")
        self.assertEqual(
            orders.parse_order(tags + ["by:ada"]),
            {"kind": "countermeasure", "op": "apply", "id": "isolate_hmi", "operator": "ada"},
        )

    def test_revert_on_a_suggestion_task_names_its_countermeasure(self):
        _title, tags = orders.order_of(orders.REVERT, "cps-soc,block_flow,3f2a9c")
        self.assertEqual(orders.parse_order(tags)["id"], "block_flow")

    def test_the_mode_entries_order_the_mode(self):
        for entry, mode in ((orders.AUTO, "auto"), (orders.ADVISE, "advise")):
            _title, tags = orders.order_of(entry)
            self.assertEqual(
                orders.parse_order(tags), {"kind": "mode", "mode": mode, "operator": None}
            )

    def test_nothing_is_ordered_from_a_task_the_soc_did_not_file(self):
        self.assertIsNone(orders.order_of(orders.APPLY, "malware,triage"))
        self.assertIsNone(orders.order_of(orders.APPLY, "cps-soc,order,apply,block_flow"))
        self.assertIsNone(orders.parse_order("cps-soc,catalog,block_flow"))
        self.assertIsNone(orders.parse_order("cps-soc,order,mode,reboot"))


if __name__ == "__main__":
    unittest.main()
