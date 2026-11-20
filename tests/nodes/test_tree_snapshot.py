"""The SOC's attack-defence tree of the CPS lab, frozen: the attack tree and the
countermeasures (nodes/common/soar_trees.py: cps_attack_tree, cps_countermeasures)
as JSON, on the lab's inventory and on the two variants the tree must answer
differently (no engineering workstation; no boundary allow rule), with and
without the IT-side countermeasures.

The tree is derived from the knowledge graph; this snapshot is what makes a
change to the derivation visible. Ids, gates, the order of an AND's children,
ATT&CK ids, impacts, targets, feasibility on each graph, and every
countermeasure with what it prevents, restores and cuts must stay the same
unless the change means them to.

Regenerate on purpose:
`UPDATE_SNAPSHOTS=1 .venv/bin/python -m pytest tests/nodes/test_tree_snapshot.py`
"""

import json
import os
import unittest

from tests.helpers import SNAPSHOT_DIR, guest_paths

guest_paths.add(guest_paths.SOC, guest_paths.DEFENSE)

import soar_kg as kg  # noqa: E402  (flat guest imports, need the path set above)
import attack_graph  # noqa: E402
import soar_trees as trees  # noqa: E402

from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402
from cyberrange.scenarios.cps import topology as cps  # noqa: E402

UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"
SNAPSHOT = SNAPSHOT_DIR / "tree-cps.json"


def inventories():
    """{variant: inventory} of the lab and of the variants the tree answers."""
    lab = cps_inv.inventory()
    no_ews = cps_inv.inventory()
    no_ews["hosts"] = [h for h in no_ews["hosts"] if h["role"] != "engineering"]
    no_rule = cps_inv.inventory(rules=[r for r in cps.firewall_rules() if "--dport" not in r])
    return {"lab": lab, "no_ews": no_ews, "no_rule": no_rule}


def render():
    out = {}
    for name, inv in inventories().items():
        g = kg.build_kg(inv)
        for it in (False, True):
            doc = trees.to_json(
                attack_graph.attack_tree(g), attack_graph.countermeasures(g, it=it), g
            )
            out[f"{name}{'+it' if it else ''}"] = json.loads(json.dumps(doc))
    return out


class TreeFrozen(unittest.TestCase):
    def test_the_tree_and_its_countermeasures_are_the_frozen_ones(self):
        rendered = render()
        if UPDATE:
            SNAPSHOT.write_text(json.dumps(rendered, indent=1, sort_keys=True) + "\n")
            return
        self.assertTrue(
            SNAPSHOT.exists(),
            f"missing {SNAPSHOT}: regenerate it deliberately with UPDATE_SNAPSHOTS=1",
        )
        frozen = json.loads(SNAPSHOT.read_text())
        self.assertEqual(sorted(frozen), sorted(rendered))
        for variant in frozen:
            with self.subTest(variant=variant):
                self.assertEqual(
                    frozen[variant],
                    rendered[variant],
                    f"the {variant} tree changed: the SOC would reason, and the attacker plan, "
                    f"on another tree than the one frozen",
                )


if __name__ == "__main__":
    unittest.main()
