"""The tables that name the CPS impacts, and the write schedule of each mode.

An impact is named in a dozen places that cannot import one another: guest code
runs flat in containers, node software never imports the platform, the platform
never imports guest code. The copies are kept by hand; this is what notices when
one is forgotten, before a run does it with a KeyError hours into a campaign.

Run: `.venv/bin/python -m pytest tests/scenarios/cps/test_cps_impact_tables.py`.
"""

import re
import unittest
from pathlib import Path

from tests.helpers import guest_paths

guest_paths.add(
    guest_paths.REDTEAM, guest_paths.SOC, guest_paths.DEFENSE, guest_paths.ATTACK_AGENTS
)

import belief_tree  # noqa: E402  (flat guest imports, need the path set above)
import exploit_client  # noqa: E402
import ot_registers as reg  # noqa: E402
import soar_kg as kg  # noqa: E402
import soar_mapping as mapping  # noqa: E402
import soar_policy as policy  # noqa: E402
import attack_graph  # noqa: E402
import soar_trees as trees  # noqa: E402
import steps  # noqa: E402

from cyberrange.planes.attack import active_attack  # noqa: E402
from cyberrange.scenarios.cps import campaign, metrics, scenario  # noqa: E402
from cyberrange.scenarios.cps import inventory as cps_inv  # noqa: E402
from cyberrange.scenarios.cps import topology as cps  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
DG_LO, DG_HI = reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][2:4]


def setpoints(mode, repeat=None):
    return [
        v
        for writes, _hold in exploit_client.schedule(mode, repeat)
        for r, v, _raw in writes
        if r == reg.HR_DG_SETPOINT
    ]


class ModeTables(unittest.TestCase):
    def test_every_copy_names_the_same_modes(self):
        modes = set(exploit_client.DEFAULT_REPEAT)
        copies = {
            "exploit_client ATTACKS + SCHEDULES + FDI_MODE": set(exploit_client.ATTACKS)
            | set(exploit_client.SCHEDULES)
            | {exploit_client.FDI_MODE},
            "active_attack.attack_targets": set(active_attack.attack_targets()),
            "scenario.ATTACK_MODES": set(scenario.ATTACK_MODES),
            "campaign.ATTACK_MODES": set(campaign.ATTACK_MODES),
            "steps.IMPACT_MODE values": set(steps.IMPACT_MODE.values()),
        }
        for name, got in copies.items():
            self.assertEqual(got, modes, f"{name} is out of step with exploit_client's modes")
        self.assertLessEqual(active_attack.STEALTHY_MODES, modes)

    def test_the_driver_hint_names_the_registers_the_mode_writes(self):
        for mode, targets in active_attack.attack_targets().items():
            written = {r for ws, _h in exploit_client.schedule(mode) for r, _v, _raw in ws}
            self.assertEqual(
                {t["register"] for t in targets},
                written,
                f"{mode}: the ground truth would name registers the attack does not write",
            )

    def test_the_default_campaign_grid_is_made_of_known_modes(self):
        mk = (ROOT / "make" / "cps.mk").read_text()
        grid = re.search(r"^CPS_MODES\s*\?=\s*(\S+)", mk, re.M).group(1).split(",")
        self.assertEqual(tuple(grid), campaign.DEFAULT_MODES, "make and the campaign disagree")
        self.assertLessEqual(set(grid), set(campaign.KNOWN_MODES))


class LeafTables(unittest.TestCase):
    def setUp(self):
        self.g = kg.build_kg(cps_inv.inventory())
        self.tree = attack_graph.attack_tree(self.g)
        idx = trees.index(self.tree)
        # The impacts an attacker can aim for: by a write through the HMI, or
        # by falsifying readings from the engineering workstation.
        self.written = {n.id: n for n in idx["ot_action"].children}
        self.leaves = {**self.written, "meas_fdi": idx["meas_fdi"]}

    def test_every_copy_names_the_same_leaves(self):
        copies = {
            "steps.IMPACT_MODE": set(steps.IMPACT_MODE),
            "steps.DETECTABILITY": set(steps.DETECTABILITY) - set(steps.PREREQ_ORDER),
            "soar_mapping.IMPACT_LEAVES": set(mapping.IMPACT_LEAVES),
            "scenario.GOALS": set(scenario.GOALS),
        }
        for name, got in copies.items():
            self.assertEqual(got, set(self.leaves), f"{name} is out of step with the attack tree")

    def belief(self):
        found = {
            "foothold": {"ip": cps.HMI_IP, "port": cps.APP_PORT},
            "ot": {"engine_ip": cps.ENGINE_IP, "modbus_ok": True, "registers": {0: 1, 1: 0, 2: 0}},
        }
        doc = belief_tree.build(found)
        out = {}

        def walk(n):
            out[n["id"]] = n
            for c in n.get("children") or []:
                walk(c)

        walk(doc)
        return out, metrics._feasible_leaves(doc, set())

    def test_the_attacker_s_own_tree_knows_the_impacts_it_can_write(self):
        # Recon does not find the workstation's branch: what it derives feasible
        # is the written impacts only, and tree fidelity scores the rest as missed.
        _nodes, reachable = self.belief()
        self.assertEqual(reachable & set(self.leaves), set(self.written))

    def test_every_prerequisite_step_is_a_node_of_the_tree(self):
        idx = trees.index(self.tree)
        for step in steps.PREREQ_ORDER:
            self.assertIn(step, idx, f"{step}: a step the planner could never be asked for")
            self.assertIn(step, steps.DETECTABILITY, f"{step}: no noise estimate to plan with")

    def test_every_leaf_has_a_playbook_row(self):
        missing = set(self.leaves) - set(policy.RulesPolicy.PLAYBOOK)
        self.assertEqual(missing, set(), "a confirmed impact the rules policy would not answer")

    def test_attacker_and_defender_describe_a_leaf_alike(self):
        belief, _reachable = self.belief()
        for leaf in self.written:
            node = self.leaves[leaf]
            self.assertEqual(
                (belief[leaf]["attck"], belief[leaf]["impact"], belief[leaf]["targets"]),
                (node.attck, node.impact, node.targets),
                f"{leaf}: the two trees disagree, and tree fidelity would score the difference",
            )


class Schedules(unittest.TestCase):
    def test_a_fixed_mode_is_its_sequence_repeated(self):
        for mode, build in exploit_client.ATTACKS.items():
            seq = build(reg.feeder(reg.plant()))
            rounds = exploit_client.schedule(mode)
            self.assertEqual(len(rounds), exploit_client.DEFAULT_REPEAT[mode], mode)
            for writes, hold in rounds:
                self.assertEqual([(r, v) for r, v, _raw in writes], [(r, v) for r, v, _s in seq])
                self.assertEqual(hold, 1, mode)

    def test_manual_is_taken_once_and_first(self):
        for mode in ("slow-ramp", "setpoint-oscillation"):
            modes = [
                (i, v)
                for i, (ws, _h) in enumerate(exploit_client.schedule(mode))
                for r, v, _raw in ws
                if r == reg.HR_CTRL_MODE
            ]
            self.assertEqual(modes, [(0, float(reg.CTRL_MANUAL))], mode)

    def test_ramp_climbs_to_the_bound_in_steps_the_soc_reads_as_a_ramp(self):
        for repeat in (None, 20):
            values = setpoints("slow-ramp", repeat)
            self.assertEqual(values[-1], DG_HI)
            self.assertTrue(all(DG_LO <= v <= DG_HI for v in values), "a ramp step out of range")
            steps_kw = [b - a for a, b in zip([reg.DG_NOMINAL_KW] + values, values)]
            self.assertGreater(min(steps_kw), 0, "the ramp must never step back")
            self.assertLessEqual(
                max(steps_kw),
                mapping.RAMP_STEP_MAX_KW,
                "the SOC would read these steps as the hijack, not as a ramp",
            )

    def test_oscillation_swings_inside_the_envelope(self):
        values = setpoints("setpoint-oscillation")
        self.assertTrue(all(DG_LO <= v <= DG_HI for v in values), "a swing out of range")
        self.assertEqual(len(set(values)), 2)
        self.assertTrue(all(a != b for a, b in zip(values, values[1:])), "two rounds at one level")
        self.assertGreaterEqual(
            max(values) - min(values),
            mapping.SWING_MIN_KW,
            "too small a swing for the SOC to tell it from an operator's dispatch",
        )

    def test_chatter_alternates_and_ends_open(self):
        values = [v for ws, _h in exploit_client.schedule("breaker-chatter") for _r, v, _raw in ws]
        self.assertEqual(values[0], 1.0)
        self.assertTrue(all(a != b for a, b in zip(values, values[1:])))
        self.assertEqual(values[-1], 1.0, "a chatter that ends closed leaves no outage behind")


if __name__ == "__main__":
    unittest.main()
